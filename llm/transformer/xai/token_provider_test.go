package xai

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/looplj/axonhub/llm/httpclient"
	"github.com/looplj/axonhub/llm/oauth"
)

func TestNewTokenProvider_SetsClientID(t *testing.T) {
	creds := &oauth.OAuthCredentials{
		AccessToken:  "access",
		RefreshToken: "refresh",
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	p := NewTokenProvider(TokenProviderParams{
		Credentials: creds,
		HTTPClient:  httpclient.NewHttpClient(),
	})

	got, err := p.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "access", got.AccessToken)
	// ClientID is applied on the provider's stored credentials for refresh.
	// Get returns a copy of stored creds which includes ClientID after NewTokenProvider.
	require.Equal(t, ClientID, got.ClientID)
}

func TestTokenProvider_RefreshAgainstMockEndpoint(t *testing.T) {
	var sawForm url.Values

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		sawForm, err = url.ParseQuery(string(body))
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"access_token":"new-access",
			"refresh_token":"new-refresh",
			"expires_in":3600,
			"token_type":"bearer",
			"scope":"openid offline_access api:access"
		}`))
	}))
	t.Cleanup(tokenServer.Close)

	var refreshed *oauth.OAuthCredentials
	p := oauth.NewTokenProvider(oauth.TokenProviderParams{
		Credentials: &oauth.OAuthCredentials{
			AccessToken:  "old-access",
			RefreshToken: "old-refresh",
			ClientID:     ClientID,
			ExpiresAt:    time.Now().Add(-time.Hour),
		},
		HTTPClient: httpclient.NewHttpClient(),
		OAuthUrls: oauth.OAuthUrls{
			AuthorizeUrl: AuthorizeURL,
			TokenUrl:     tokenServer.URL,
		},
		OnRefreshed: func(ctx context.Context, c *oauth.OAuthCredentials) error {
			refreshed = c
			return nil
		},
	})

	got, err := p.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "new-access", got.AccessToken)
	require.Equal(t, "new-refresh", got.RefreshToken)
	require.NotNil(t, refreshed)
	require.Equal(t, "new-access", refreshed.AccessToken)
	require.Equal(t, "new-refresh", refreshed.RefreshToken)
	require.Equal(t, "refresh_token", sawForm.Get("grant_type"))
	require.Equal(t, ClientID, sawForm.Get("client_id"))
	require.Equal(t, "old-refresh", sawForm.Get("refresh_token"))
}

func TestTokenProvider_RefreshPreservesRefreshTokenWhenNotRotated(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// No refresh_token in response — provider must keep the old one.
		_, _ = w.Write([]byte(`{
			"access_token":"rotated-access",
			"expires_in":7200,
			"token_type":"bearer"
		}`))
	}))
	t.Cleanup(tokenServer.Close)

	p := oauth.NewTokenProvider(oauth.TokenProviderParams{
		Credentials: &oauth.OAuthCredentials{
			AccessToken:  "old-access",
			RefreshToken: "keep-me",
			ClientID:     ClientID,
			ExpiresAt:    time.Now().Add(-time.Hour),
		},
		HTTPClient: httpclient.NewHttpClient(),
		OAuthUrls: oauth.OAuthUrls{
			TokenUrl: tokenServer.URL,
		},
	})

	got, err := p.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "rotated-access", got.AccessToken)
	require.Equal(t, "keep-me", got.RefreshToken)
}

func TestDeviceFlowProvider_StartAndPoll(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/device/code", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.NoError(t, r.ParseForm())
		require.Equal(t, ClientID, r.FormValue("client_id"))
		require.Contains(t, r.FormValue("scope"), "offline_access")
		require.Contains(t, r.FormValue("scope"), "api:access")

		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code":      "dev-code-1",
			"user_code":        "ABCD-1234",
			"verification_uri": "https://auth.x.ai/device",
			"expires_in":       900,
			"interval":         5,
		})
	})
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.NoError(t, r.ParseForm())
		require.Equal(t, "urn:ietf:params:oauth:grant-type:device_code", r.FormValue("grant_type"))
		require.Equal(t, "dev-code-1", r.FormValue("device_code"))
		require.Equal(t, ClientID, r.FormValue("client_id"))

		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "xai-access",
			"refresh_token": "xai-refresh",
			"expires_in":    3600,
			"token_type":    "bearer",
			"scope":         "openid offline_access api:access",
		})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	provider := oauth.NewDeviceFlowProvider(oauth.DeviceFlowProviderParams{
		HTTPClient: httpclient.NewHttpClient(),
		Config: oauth.DeviceFlowConfig{
			DeviceAuthURL: server.URL + "/oauth2/device/code",
			TokenURL:      server.URL + "/oauth2/token",
			ClientID:      ClientID,
			Scopes:        DefaultOAuthScopes,
		},
	})

	start, err := provider.Start(context.Background())
	require.NoError(t, err)
	require.Equal(t, "dev-code-1", start.DeviceCode)
	require.Equal(t, "ABCD-1234", start.UserCode)
	require.True(t, strings.Contains(start.VerificationURI, "auth.x.ai") || start.VerificationURI != "")

	creds, err := provider.Poll(context.Background(), start.DeviceCode)
	require.NoError(t, err)
	require.Equal(t, "xai-access", creds.AccessToken)
	require.Equal(t, "xai-refresh", creds.RefreshToken)
	require.Equal(t, ClientID, creds.ClientID)
	require.NotZero(t, creds.ExpiresAt)
}

func TestDefaultDeviceFlowConfig(t *testing.T) {
	cfg := DefaultDeviceFlowConfig()
	require.Equal(t, DeviceAuthURL, cfg.DeviceAuthURL)
	require.Equal(t, TokenURL, cfg.TokenURL)
	require.Equal(t, ClientID, cfg.ClientID)
	require.Equal(t, DefaultOAuthScopes, cfg.Scopes)
	require.Equal(t, Scopes, strings.Join(cfg.Scopes, " "))
}

func TestDiscoverOAuthEndpoints_FallbackOnFailure(t *testing.T) {
	// Discovery against a closed port should fall back to static endpoints.
	hc := httpclient.NewHttpClient()
	// Temporarily unreachable URL is handled inside Discover via failed GET —
	// DiscoverOAuthEndpoints always returns static fallbacks on network error.
	// Call with a client that works; real discovery may succeed in CI with network.
	// Exercise fallback path by using a client that forces transport errors:
	transport := &failingRoundTripper{}
	hc = httpclient.NewHttpClientWithClient(&http.Client{Transport: transport})

	d, err := DiscoverOAuthEndpoints(context.Background(), hc)
	require.NoError(t, err)
	require.Equal(t, DeviceAuthURL, d.DeviceAuthorizationEndpoint)
	require.Equal(t, TokenURL, d.TokenEndpoint)
}

type failingRoundTripper struct{}

func (f *failingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, errors.New("simulated network failure")
}
