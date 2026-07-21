package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/fx"

	"github.com/looplj/axonhub/internal/log"
	"github.com/looplj/axonhub/internal/pkg/xcache"
	"github.com/looplj/axonhub/llm/httpclient"
	"github.com/looplj/axonhub/llm/oauth"
	"github.com/looplj/axonhub/llm/transformer/xai"
)

const (
	// Cache key prefix for xAI device-flow sessions.
	xaiOAuthCacheKeyPrefix = "xai:oauth"

	// Default cache expiration for device flow (15 minutes).
	// xAI may return expires_in up to ~1800s; cap cache at that scale.
	xaiDeviceFlowCacheExpiration = 30 * time.Minute

	// Grant type for device flow.
	xaiDeviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

	// Defaults aligned with CLIProxyAPI when the device endpoint omits values.
	xaiDefaultPollInterval = 5
	xaiDefaultExpiresIn    = 1800

	// Transient network retries for Cloudflare / flaky TLS (EOF, reset).
	xaiOAuthMaxAttempts = 3
)

// getXaiOAuthClientID returns the xAI OAuth client ID.
// It checks the XAI_OAUTH_CLIENT_ID environment variable first,
// then falls back to the public Grok CLI client ID.
func getXaiOAuthClientID() string {
	if clientID := os.Getenv("XAI_OAUTH_CLIENT_ID"); clientID != "" {
		return clientID
	}
	return xai.ClientID
}

// XaiHandlersParams contains the dependencies for XaiHandlers.
type XaiHandlersParams struct {
	fx.In

	CacheConfig xcache.Config
	HttpClient  *httpclient.HttpClient
	Clock       Clock `optional:"true"`
}

// XaiHandlers provides HTTP handlers for xAI OAuth device flow.
// Flow mirrors CLIProxyAPI internal/auth/xai: OIDC discovery → device code → poll token.
type XaiHandlers struct {
	deviceCodeCache xcache.Cache[xaiDeviceFlowState]
	httpClient      *httpclient.HttpClient
	clock           Clock

	// Overridable for tests / env.
	clientID string
	scopes   string
}

// xaiDeviceFlowState stores the state of a device flow authorization.
type xaiDeviceFlowState struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	CreatedAt       int64  `json:"created_at"`
	TokenEndpoint   string `json:"token_endpoint,omitempty"`
}

// xaiDeviceCodeResponse represents the response from xAI's device code endpoint.
type xaiDeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// xaiAccessTokenResponse represents the response from xAI's token endpoint.
type xaiAccessTokenResponse struct {
	AccessToken  string `json:"access_token"` //nolint:gosec
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token,omitempty"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

func NewXaiHandlers(params XaiHandlersParams) *XaiHandlers {
	clock := params.Clock
	if clock == nil {
		clock = realClock{}
	}

	return &XaiHandlers{
		deviceCodeCache: xcache.NewFromConfig[xaiDeviceFlowState](params.CacheConfig),
		httpClient:      params.HttpClient,
		clock:           clock,
		clientID:        getXaiOAuthClientID(),
		scopes:          xai.Scopes,
	}
}

// generateXaiSessionID generates a unique session ID for the device flow.
func generateXaiSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b), nil
}

func xaiOAuthCacheKey(sessionID string) string {
	return fmt.Sprintf("%s:%s", xaiOAuthCacheKeyPrefix, sessionID)
}

// StartXaiOAuthRequest represents the request body for starting OAuth device flow.
type StartXaiOAuthRequest struct {
	Proxy *httpclient.ProxyConfig `json:"proxy,omitempty"`
}

// StartXaiOAuthResponse represents the response for starting OAuth device flow.
type StartXaiOAuthResponse struct {
	SessionID       string `json:"session_id"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// StartOAuth initiates the xAI OAuth device flow.
// POST /admin/xai/oauth/start
func (h *XaiHandlers) StartOAuth(c *gin.Context) {
	ctx := c.Request.Context()

	var req StartXaiOAuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		if err.Error() != "EOF" {
			JSONError(c, http.StatusBadRequest, errors.New("invalid request format"))
			return
		}
	}

	sessionID, err := generateXaiSessionID()
	if err != nil {
		JSONError(c, http.StatusInternalServerError, fmt.Errorf("failed to generate session ID: %w", err))
		return
	}

	httpClient := h.httpClient
	if req.Proxy != nil && req.Proxy.Type == httpclient.ProxyTypeURL && req.Proxy.URL != "" {
		httpClient = h.httpClient.WithProxy(req.Proxy)
	}

	deviceCodeResp, tokenEndpoint, err := h.requestDeviceCode(ctx, httpClient)
	if err != nil {
		JSONError(c, http.StatusBadGateway, fmt.Errorf("failed to request device code: %w", err))
		return
	}

	verificationURI := strings.TrimSpace(deviceCodeResp.VerificationURIComplete)
	if verificationURI == "" {
		verificationURI = strings.TrimSpace(deviceCodeResp.VerificationURI)
	}

	expiresIn := deviceCodeResp.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = xaiDefaultExpiresIn
	}
	interval := deviceCodeResp.Interval
	if interval <= 0 {
		interval = xaiDefaultPollInterval
	}

	state := xaiDeviceFlowState{
		DeviceCode:      deviceCodeResp.DeviceCode,
		UserCode:        deviceCodeResp.UserCode,
		VerificationURI: verificationURI,
		ExpiresIn:       expiresIn,
		Interval:        interval,
		CreatedAt:       h.clock.Now().Unix(),
		TokenEndpoint:   tokenEndpoint,
	}

	cacheKey := xaiOAuthCacheKey(sessionID)
	expiration := time.Duration(expiresIn) * time.Second
	if expiration > xaiDeviceFlowCacheExpiration {
		expiration = xaiDeviceFlowCacheExpiration
	}

	if err := h.deviceCodeCache.Set(ctx, cacheKey, state, xcache.WithExpiration(expiration)); err != nil {
		JSONError(c, http.StatusInternalServerError, fmt.Errorf("failed to save device flow state: %w", err))
		return
	}

	c.JSON(http.StatusOK, StartXaiOAuthResponse{
		SessionID:       sessionID,
		UserCode:        deviceCodeResp.UserCode,
		VerificationURI: verificationURI,
		ExpiresIn:       expiresIn,
		Interval:        interval,
	})
}

func (h *XaiHandlers) requestDeviceCode(ctx context.Context, httpClient *httpclient.HttpClient) (*xaiDeviceCodeResponse, string, error) {
	discovery, err := xai.DiscoverOAuthEndpoints(ctx, httpClient)
	if err != nil || discovery == nil {
		discovery = &xai.Discovery{
			DeviceAuthorizationEndpoint: xai.DeviceAuthURL,
			TokenEndpoint:               xai.TokenURL,
		}
	}

	formData := url.Values{}
	formData.Set("client_id", h.clientID)
	formData.Set("scope", h.scopes)

	var lastErr error
	for attempt := 1; attempt <= xaiOAuthMaxAttempts; attempt++ {
		req := &httpclient.Request{
			Method: http.MethodPost,
			URL:    discovery.DeviceAuthorizationEndpoint,
			Headers: http.Header{
				"Accept":     []string{"application/json"},
				// Match CLIProxyAPI: no custom UA (httpclient still may set axonhub/1.0).
				// Prefer a neutral UA that Cloudflare is less likely to drop.
				"User-Agent": []string{"AxonHub-xAI-OAuth/1.0"},
			},
			ContentType: "application/x-www-form-urlencoded",
			Body:        []byte(formData.Encode()),
		}

		resp, err := httpClient.Do(ctx, req)
		if err != nil {
			lastErr = fmt.Errorf("device code request failed: %w", err)
			if isTransientNetworkError(err) && attempt < xaiOAuthMaxAttempts {
				select {
				case <-ctx.Done():
					return nil, "", ctx.Err()
				case <-time.After(time.Duration(attempt) * 400 * time.Millisecond):
				}
				continue
			}
			return nil, "", lastErr
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, "", fmt.Errorf("device code request failed with status %d: %s", resp.StatusCode, string(resp.Body))
		}

		var deviceResp xaiDeviceCodeResponse
		if err := json.Unmarshal(resp.Body, &deviceResp); err != nil {
			return nil, "", fmt.Errorf("failed to parse device code response: %w", err)
		}

		if strings.TrimSpace(deviceResp.DeviceCode) == "" {
			return nil, "", errors.New("device code not received from xAI")
		}
		if strings.TrimSpace(deviceResp.UserCode) == "" {
			return nil, "", errors.New("user code not received from xAI")
		}
		if strings.TrimSpace(deviceResp.VerificationURI) == "" && strings.TrimSpace(deviceResp.VerificationURIComplete) == "" {
			return nil, "", errors.New("verification URI not received from xAI")
		}

		return &deviceResp, discovery.TokenEndpoint, nil
	}

	return nil, "", lastErr
}

// PollXaiOAuthRequest represents the request body for polling OAuth token.
type PollXaiOAuthRequest struct {
	SessionID string                  `json:"session_id" binding:"required"`
	Proxy     *httpclient.ProxyConfig `json:"proxy,omitempty"`
}

// PollXaiOAuthResponse represents the response for polling OAuth token.
// On success, credentials is a JSON string of oauth.OAuthCredentials ready to store on the channel.
type PollXaiOAuthResponse struct {
	Status       string `json:"status"`
	Message      string `json:"message,omitempty"`
	AccessToken  string `json:"access_token,omitempty"` //nolint:gosec
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
	// Credentials is the full OAuth credential JSON (access_token + refresh_token + metadata).
	Credentials string `json:"credentials,omitempty"`
}

// PollOAuth polls for the OAuth access token using the device flow.
// POST /admin/xai/oauth/poll
func (h *XaiHandlers) PollOAuth(c *gin.Context) {
	ctx := c.Request.Context()

	var req PollXaiOAuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		JSONError(c, http.StatusBadRequest, errors.New("invalid request format"))
		return
	}

	cacheKey := xaiOAuthCacheKey(req.SessionID)

	state, err := h.deviceCodeCache.Get(ctx, cacheKey)
	if err != nil {
		JSONError(c, http.StatusBadRequest, errors.New("invalid or expired session"))
		return
	}

	if h.clock.Now().Unix() > state.CreatedAt+int64(state.ExpiresIn) {
		_ = h.deviceCodeCache.Delete(ctx, cacheKey)
		JSONError(c, http.StatusBadRequest, errors.New("device code expired"))
		return
	}

	httpClient := h.httpClient
	if req.Proxy != nil && req.Proxy.Type == httpclient.ProxyTypeURL && req.Proxy.URL != "" {
		httpClient = h.httpClient.WithProxy(req.Proxy)
	}

	tokenURL := strings.TrimSpace(state.TokenEndpoint)
	if tokenURL == "" {
		tokenURL = xai.TokenURL
	}

	tokenResp, err := h.pollAccessToken(ctx, httpClient, tokenURL, state.DeviceCode)
	if err != nil {
		JSONError(c, http.StatusBadGateway, fmt.Errorf("token poll failed: %w", err))
		return
	}

	if tokenResp.Error != "" {
		switch tokenResp.Error {
		case "authorization_pending":
			c.JSON(http.StatusOK, PollXaiOAuthResponse{
				Status:  "pending",
				Message: "Authorization pending. User has not yet authorized the device.",
			})
			return
		case "slow_down":
			c.JSON(http.StatusOK, PollXaiOAuthResponse{
				Status:  "slow_down",
				Message: "Polling too fast. Please slow down.",
			})
			return
		case "expired_token":
			_ = h.deviceCodeCache.Delete(ctx, cacheKey)
			JSONError(c, http.StatusBadRequest, errors.New("device code expired"))
			return
		case "access_denied":
			_ = h.deviceCodeCache.Delete(ctx, cacheKey)
			JSONError(c, http.StatusBadRequest, errors.New("access denied by user"))
			return
		default:
			JSONError(c, http.StatusBadGateway, fmt.Errorf("OAuth error: %s - %s", tokenResp.Error, tokenResp.ErrorDesc))
			return
		}
	}

	if tokenResp.AccessToken != "" {
		if err := h.deviceCodeCache.Delete(ctx, cacheKey); err != nil {
			log.Warn(ctx, "failed to delete used oauth state from cache", log.String("session_id", req.SessionID), log.Cause(err))
		}

		creds := &oauth.OAuthCredentials{
			ClientID:     h.clientID,
			AccessToken:  tokenResp.AccessToken,
			RefreshToken: tokenResp.RefreshToken,
			IDToken:      tokenResp.IDToken,
			TokenType:    tokenResp.TokenType,
			Scopes:       strings.Fields(tokenResp.Scope),
		}
		if len(creds.Scopes) == 0 {
			creds.Scopes = xai.DefaultOAuthScopes
		}
		if tokenResp.ExpiresIn > 0 {
			creds.ExpiresAt = h.clock.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
		}
		if creds.TokenType == "" {
			creds.TokenType = "bearer"
		}

		credJSON, err := creds.ToJSON()
		if err != nil {
			JSONError(c, http.StatusInternalServerError, fmt.Errorf("failed to serialize credentials: %w", err))
			return
		}

		c.JSON(http.StatusOK, PollXaiOAuthResponse{
			Status:       "complete",
			Message:      "Authorization complete. OAuth credentials received.",
			AccessToken:  tokenResp.AccessToken,
			RefreshToken: tokenResp.RefreshToken,
			TokenType:    creds.TokenType,
			ExpiresIn:    tokenResp.ExpiresIn,
			Scope:        tokenResp.Scope,
			Credentials:  credJSON,
		})
		return
	}

	JSONError(c, http.StatusInternalServerError, errors.New("unexpected response from xAI"))
}

func (h *XaiHandlers) pollAccessToken(ctx context.Context, httpClient *httpclient.HttpClient, tokenURL, deviceCode string) (*xaiAccessTokenResponse, error) {
	formData := url.Values{}
	formData.Set("client_id", h.clientID)
	formData.Set("device_code", deviceCode)
	formData.Set("grant_type", xaiDeviceGrantType)

	var lastErr error
	for attempt := 1; attempt <= xaiOAuthMaxAttempts; attempt++ {
		req := &httpclient.Request{
			Method: http.MethodPost,
			URL:    tokenURL,
			Headers: http.Header{
				"Accept":     []string{"application/json"},
				"User-Agent": []string{"AxonHub-xAI-OAuth/1.0"},
			},
			ContentType: "application/x-www-form-urlencoded",
			Body:        []byte(formData.Encode()),
		}

		resp, err := httpClient.Do(ctx, req)
		if err != nil {
			// HttpClient maps status >= 400 to Error with Body. Device-flow providers
			// often return 400 with {"error":"authorization_pending"} which must be
			// parsed as a poll state, not a gateway failure.
			var httpErr *httpclient.Error
			if errors.As(err, &httpErr) && len(httpErr.Body) > 0 {
				tokenResp, parseErr := parseXaiTokenResponse(httpErr.Body)
				if parseErr == nil && (tokenResp.Error != "" || tokenResp.AccessToken != "") {
					return tokenResp, nil
				}
			}

			lastErr = fmt.Errorf("access token request failed: %w", err)
			if isTransientNetworkError(err) && attempt < xaiOAuthMaxAttempts {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(time.Duration(attempt) * 400 * time.Millisecond):
				}
				continue
			}
			return nil, lastErr
		}

		tokenResp, err := parseXaiTokenResponse(resp.Body)
		if err != nil {
			return nil, err
		}

		// Non-2xx without OAuth error field is a transport/API failure.
		if (resp.StatusCode < 200 || resp.StatusCode >= 300) && tokenResp.Error == "" {
			return nil, fmt.Errorf("access token request failed with status %d", resp.StatusCode)
		}

		return tokenResp, nil
	}

	return nil, lastErr
}

func parseXaiTokenResponse(body []byte) (*xaiAccessTokenResponse, error) {
	var tokenResp xaiAccessTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err == nil {
		return &tokenResp, nil
	}

	// Fall back to form-encoded parsing.
	values, parseErr := url.ParseQuery(string(body))
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse access token response: %w", parseErr)
	}

	tokenResp.AccessToken = values.Get("access_token")
	tokenResp.RefreshToken = values.Get("refresh_token")
	tokenResp.TokenType = values.Get("token_type")
	tokenResp.Scope = values.Get("scope")
	tokenResp.Error = values.Get("error")
	tokenResp.ErrorDesc = values.Get("error_description")
	if exp := values.Get("expires_in"); exp != "" {
		var n int
		if _, scanErr := fmt.Sscanf(exp, "%d", &n); scanErr == nil {
			tokenResp.ExpiresIn = n
		}
	}

	return &tokenResp, nil
}

// isTransientNetworkError reports connection-level failures that are worth retrying
// (EOF / reset / temporary dial errors — common with auth.x.ai behind bot protection).
func isTransientNetworkError(err error) bool {
	if err == nil {
		return false
	}
	// Do not retry structured HTTP status errors.
	var httpErr *httpclient.Error
	if errors.As(err, &httpErr) {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{
		"eof",
		"connection reset",
		"connection refused",
		"broken pipe",
		"tls handshake timeout",
		"i/o timeout",
		"temporary failure",
		"server closed idle connection",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}
