package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/looplj/axonhub/internal/pkg/xcache"
	"github.com/looplj/axonhub/llm/httpclient"
	"github.com/looplj/axonhub/llm/oauth"
	"github.com/looplj/axonhub/llm/transformer/xai"
)

func newXaiTestHandlers(t *testing.T, deviceURL, tokenURL string) *XaiHandlers {
	t.Helper()

	transport := &testXaiTransport{
		deviceCodeURL:  deviceURL,
		accessTokenURL: tokenURL,
		discoveryURL:   "", // discovery falls back to static endpoints rewritten by transport
	}
	hc := httpclient.NewHttpClientWithClient(&http.Client{Transport: transport})

	h := NewXaiHandlers(XaiHandlersParams{
		CacheConfig: xcache.Config{Mode: xcache.ModeMemory},
		HttpClient:  hc,
	})
	return h
}

func TestXaiHandlers_StartOAuth_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	deviceCodeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		err := r.ParseForm()
		require.NoError(t, err)
		require.Equal(t, xai.ClientID, r.FormValue("client_id"))
		require.Equal(t, xai.Scopes, r.FormValue("scope"))

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"device_code": "test-device-code-123",
			"user_code": "WXYZ-9876",
			"verification_uri": "https://auth.x.ai/device",
			"expires_in": 900,
			"interval": 5
		}`))
	}))
	defer deviceCodeServer.Close()

	h := newXaiTestHandlers(t, deviceCodeServer.URL, "")
	// Override endpoints to mock servers through transport (matches auth.x.ai paths).

	router := gin.New()
	router.POST("/admin/xai/oauth/start", h.StartOAuth)

	req := httptest.NewRequest(http.MethodPost, "/admin/xai/oauth/start", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp StartXaiOAuthResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.SessionID)
	require.Equal(t, "WXYZ-9876", resp.UserCode)
	require.Equal(t, "https://auth.x.ai/device", resp.VerificationURI)
	require.Equal(t, 900, resp.ExpiresIn)
	require.Equal(t, 5, resp.Interval)
}

func TestXaiHandlers_StartOAuth_InvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := NewXaiHandlers(XaiHandlersParams{
		CacheConfig: xcache.Config{Mode: xcache.ModeMemory},
		HttpClient:  httpclient.NewHttpClient(),
	})

	router := gin.New()
	router.POST("/admin/xai/oauth/start", h.StartOAuth)

	req := httptest.NewRequest(http.MethodPost, "/admin/xai/oauth/start", bytes.NewBufferString("{"))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "invalid request format")
}

func TestXaiHandlers_StartOAuth_UpstreamError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	deviceCodeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"service_unavailable"}`))
	}))
	defer deviceCodeServer.Close()

	h := newXaiTestHandlers(t, deviceCodeServer.URL, "")

	router := gin.New()
	router.POST("/admin/xai/oauth/start", h.StartOAuth)

	req := httptest.NewRequest(http.MethodPost, "/admin/xai/oauth/start", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadGateway, w.Code)
}

func TestXaiHandlers_StartOAuth_EmptyDeviceCode(t *testing.T) {
	gin.SetMode(gin.TestMode)

	deviceCodeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"user_code": "ABCD-EFGH",
			"verification_uri": "https://auth.x.ai/device",
			"expires_in": 900,
			"interval": 5
		}`))
	}))
	defer deviceCodeServer.Close()

	h := newXaiTestHandlers(t, deviceCodeServer.URL, "")

	router := gin.New()
	router.POST("/admin/xai/oauth/start", h.StartOAuth)

	req := httptest.NewRequest(http.MethodPost, "/admin/xai/oauth/start", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadGateway, w.Code)
	require.Contains(t, w.Body.String(), "device code not received")
}

func TestXaiHandlers_PollOAuth_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	deviceCodeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"device_code": "poll-device-code",
			"user_code": "POLL-CODE",
			"verification_uri": "https://auth.x.ai/device",
			"expires_in": 900,
			"interval": 5
		}`))
	}))
	defer deviceCodeServer.Close()

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.NoError(t, r.ParseForm())
		require.Equal(t, xai.ClientID, r.FormValue("client_id"))
		require.Equal(t, "poll-device-code", r.FormValue("device_code"))
		require.Equal(t, "urn:ietf:params:oauth:grant-type:device_code", r.FormValue("grant_type"))

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"access_token": "xai-access-token",
			"refresh_token": "xai-refresh-token",
			"expires_in": 3600,
			"token_type": "bearer",
			"scope": "openid offline_access api:access"
		}`))
	}))
	defer tokenServer.Close()

	h := newXaiTestHandlers(t, deviceCodeServer.URL, tokenServer.URL)

	router := gin.New()
	router.POST("/admin/xai/oauth/start", h.StartOAuth)
	router.POST("/admin/xai/oauth/poll", h.PollOAuth)

	startReq := httptest.NewRequest(http.MethodPost, "/admin/xai/oauth/start", bytes.NewBufferString("{}"))
	startReq.Header.Set("Content-Type", "application/json")
	startW := httptest.NewRecorder()
	router.ServeHTTP(startW, startReq)
	require.Equal(t, http.StatusOK, startW.Code)

	var startResp StartXaiOAuthResponse
	require.NoError(t, json.Unmarshal(startW.Body.Bytes(), &startResp))

	pollBody, _ := json.Marshal(PollXaiOAuthRequest{SessionID: startResp.SessionID})
	pollReq := httptest.NewRequest(http.MethodPost, "/admin/xai/oauth/poll", bytes.NewBuffer(pollBody))
	pollReq.Header.Set("Content-Type", "application/json")
	pollW := httptest.NewRecorder()
	router.ServeHTTP(pollW, pollReq)

	require.Equal(t, http.StatusOK, pollW.Code)

	var pollResp PollXaiOAuthResponse
	require.NoError(t, json.Unmarshal(pollW.Body.Bytes(), &pollResp))
	require.Equal(t, "complete", pollResp.Status)
	require.Equal(t, "xai-access-token", pollResp.AccessToken)
	require.Equal(t, "xai-refresh-token", pollResp.RefreshToken)
	require.NotEmpty(t, pollResp.Credentials)

	creds, err := oauth.ParseCredentialsJSON(pollResp.Credentials)
	require.NoError(t, err)
	require.Equal(t, "xai-access-token", creds.AccessToken)
	require.Equal(t, "xai-refresh-token", creds.RefreshToken)
	require.Equal(t, xai.ClientID, creds.ClientID)
	require.NotZero(t, creds.ExpiresAt)
}

func TestXaiHandlers_PollOAuth_AuthorizationPending(t *testing.T) {
	gin.SetMode(gin.TestMode)

	deviceCodeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"device_code": "pending-device",
			"user_code": "PEND-CODE",
			"verification_uri": "https://auth.x.ai/device",
			"expires_in": 900,
			"interval": 5
		}`))
	}))
	defer deviceCodeServer.Close()

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"authorization_pending","error_description":"waiting"}`))
	}))
	defer tokenServer.Close()

	h := newXaiTestHandlers(t, deviceCodeServer.URL, tokenServer.URL)

	router := gin.New()
	router.POST("/admin/xai/oauth/start", h.StartOAuth)
	router.POST("/admin/xai/oauth/poll", h.PollOAuth)

	startReq := httptest.NewRequest(http.MethodPost, "/admin/xai/oauth/start", bytes.NewBufferString("{}"))
	startReq.Header.Set("Content-Type", "application/json")
	startW := httptest.NewRecorder()
	router.ServeHTTP(startW, startReq)
	require.Equal(t, http.StatusOK, startW.Code)

	var startResp StartXaiOAuthResponse
	require.NoError(t, json.Unmarshal(startW.Body.Bytes(), &startResp))

	pollBody, _ := json.Marshal(PollXaiOAuthRequest{SessionID: startResp.SessionID})
	pollReq := httptest.NewRequest(http.MethodPost, "/admin/xai/oauth/poll", bytes.NewBuffer(pollBody))
	pollReq.Header.Set("Content-Type", "application/json")
	pollW := httptest.NewRecorder()
	router.ServeHTTP(pollW, pollReq)

	require.Equal(t, http.StatusOK, pollW.Code)

	var pollResp PollXaiOAuthResponse
	require.NoError(t, json.Unmarshal(pollW.Body.Bytes(), &pollResp))
	require.Equal(t, "pending", pollResp.Status)
}

func TestXaiHandlers_PollOAuth_SlowDown(t *testing.T) {
	gin.SetMode(gin.TestMode)

	deviceCodeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"device_code": "slow-device",
			"user_code": "SLOW-CODE",
			"verification_uri": "https://auth.x.ai/device",
			"expires_in": 900,
			"interval": 5
		}`))
	}))
	defer deviceCodeServer.Close()

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":"slow_down"}`))
	}))
	defer tokenServer.Close()

	h := newXaiTestHandlers(t, deviceCodeServer.URL, tokenServer.URL)

	router := gin.New()
	router.POST("/admin/xai/oauth/start", h.StartOAuth)
	router.POST("/admin/xai/oauth/poll", h.PollOAuth)

	startReq := httptest.NewRequest(http.MethodPost, "/admin/xai/oauth/start", bytes.NewBufferString("{}"))
	startReq.Header.Set("Content-Type", "application/json")
	startW := httptest.NewRecorder()
	router.ServeHTTP(startW, startReq)
	require.Equal(t, http.StatusOK, startW.Code)

	var startResp StartXaiOAuthResponse
	require.NoError(t, json.Unmarshal(startW.Body.Bytes(), &startResp))

	pollBody, _ := json.Marshal(PollXaiOAuthRequest{SessionID: startResp.SessionID})
	pollReq := httptest.NewRequest(http.MethodPost, "/admin/xai/oauth/poll", bytes.NewBuffer(pollBody))
	pollReq.Header.Set("Content-Type", "application/json")
	pollW := httptest.NewRecorder()
	router.ServeHTTP(pollW, pollReq)

	require.Equal(t, http.StatusOK, pollW.Code)

	var pollResp PollXaiOAuthResponse
	require.NoError(t, json.Unmarshal(pollW.Body.Bytes(), &pollResp))
	require.Equal(t, "slow_down", pollResp.Status)
}

func TestXaiHandlers_PollOAuth_InvalidSession(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := NewXaiHandlers(XaiHandlersParams{
		CacheConfig: xcache.Config{Mode: xcache.ModeMemory},
		HttpClient:  httpclient.NewHttpClient(),
	})

	router := gin.New()
	router.POST("/admin/xai/oauth/poll", h.PollOAuth)

	pollBody, _ := json.Marshal(PollXaiOAuthRequest{SessionID: "missing-session"})
	pollReq := httptest.NewRequest(http.MethodPost, "/admin/xai/oauth/poll", bytes.NewBuffer(pollBody))
	pollReq.Header.Set("Content-Type", "application/json")
	pollW := httptest.NewRecorder()
	router.ServeHTTP(pollW, pollReq)

	require.Equal(t, http.StatusBadRequest, pollW.Code)
	require.Contains(t, pollW.Body.String(), "invalid or expired session")
}

func TestXaiHandlers_PollOAuth_DeviceCodeExpired(t *testing.T) {
	gin.SetMode(gin.TestMode)

	deviceCodeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"device_code": "expired-device",
			"user_code": "EXP-CODE",
			"verification_uri": "https://auth.x.ai/device",
			"expires_in": 1,
			"interval": 5
		}`))
	}))
	defer deviceCodeServer.Close()

	clock := &fakeClock{currentTime: time.Now()}
	transport := &testXaiTransport{deviceCodeURL: deviceCodeServer.URL}
	hc := httpclient.NewHttpClientWithClient(&http.Client{Transport: transport})

	h := NewXaiHandlers(XaiHandlersParams{
		CacheConfig: xcache.Config{Mode: xcache.ModeMemory},
		HttpClient:  hc,
		Clock:       clock,
	})

	router := gin.New()
	router.POST("/admin/xai/oauth/start", h.StartOAuth)
	router.POST("/admin/xai/oauth/poll", h.PollOAuth)

	startReq := httptest.NewRequest(http.MethodPost, "/admin/xai/oauth/start", bytes.NewBufferString("{}"))
	startReq.Header.Set("Content-Type", "application/json")
	startW := httptest.NewRecorder()
	router.ServeHTTP(startW, startReq)
	require.Equal(t, http.StatusOK, startW.Code)

	var startResp StartXaiOAuthResponse
	require.NoError(t, json.Unmarshal(startW.Body.Bytes(), &startResp))

	clock.Advance(2 * time.Second)

	pollBody, _ := json.Marshal(PollXaiOAuthRequest{SessionID: startResp.SessionID})
	pollReq := httptest.NewRequest(http.MethodPost, "/admin/xai/oauth/poll", bytes.NewBuffer(pollBody))
	pollReq.Header.Set("Content-Type", "application/json")
	pollW := httptest.NewRecorder()
	router.ServeHTTP(pollW, pollReq)

	require.Equal(t, http.StatusBadRequest, pollW.Code)
	require.Contains(t, pollW.Body.String(), "device code expired")
}

type testXaiTransport struct {
	deviceCodeURL  string
	accessTokenURL string
	discoveryURL   string
}

func (t *testXaiTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u := req.URL.String()

	// OIDC discovery — return endpoints that still match auth.x.ai hosts so validation passes,
	// then device/token calls are rewritten to local test servers below.
	if strings.Contains(u, ".well-known/openid-configuration") {
		body := []byte(`{
			"device_authorization_endpoint":"https://auth.x.ai/oauth2/device/code",
			"token_endpoint":"https://auth.x.ai/oauth2/token",
			"issuer":"https://auth.x.ai"
		}`)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(body)),
			Request:    req,
		}, nil
	}

	if strings.Contains(u, "auth.x.ai/oauth2/device/code") || strings.Contains(req.URL.Path, "/oauth2/device/code") {
		if t.deviceCodeURL != "" {
			body, _ := io.ReadAll(req.Body)
			_ = req.Body.Close()

			proxyReq, err := http.NewRequestWithContext(req.Context(), req.Method, t.deviceCodeURL, bytes.NewBuffer(body))
			if err != nil {
				return nil, err
			}
			proxyReq.Header = req.Header.Clone()
			return http.DefaultTransport.RoundTrip(proxyReq)
		}
	}

	if strings.Contains(u, "auth.x.ai/oauth2/token") || strings.Contains(req.URL.Path, "/oauth2/token") {
		if t.accessTokenURL != "" {
			body, _ := io.ReadAll(req.Body)
			_ = req.Body.Close()

			proxyReq, err := http.NewRequestWithContext(req.Context(), req.Method, t.accessTokenURL, bytes.NewBuffer(body))
			if err != nil {
				return nil, err
			}
			proxyReq.Header = req.Header.Clone()
			return http.DefaultTransport.RoundTrip(proxyReq)
		}
	}

	return nil, fmt.Errorf("unexpected request to %s", req.URL)
}
