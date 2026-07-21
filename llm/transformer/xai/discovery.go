package xai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/looplj/axonhub/llm/httpclient"
)

// Discovery holds OAuth endpoints resolved from xAI OIDC discovery.
type Discovery struct {
	DeviceAuthorizationEndpoint string
	TokenEndpoint               string
}

// DiscoverOAuthEndpoints resolves xAI device + token endpoints via OIDC discovery.
// Falls back to DeviceAuthURL / TokenURL when discovery fails or fields are empty.
func DiscoverOAuthEndpoints(ctx context.Context, client *httpclient.HttpClient) (*Discovery, error) {
	if client == nil {
		return &Discovery{
			DeviceAuthorizationEndpoint: DeviceAuthURL,
			TokenEndpoint:               TokenURL,
		}, nil
	}

	resp, err := client.Do(ctx, &httpclient.Request{
		Method: http.MethodGet,
		URL:    DiscoveryURL,
		Headers: http.Header{
			"Accept": []string{"application/json"},
		},
	})
	if err != nil {
		// Network flake — use well-known static endpoints (same as CLIProxyAPI fallbacks).
		return &Discovery{
			DeviceAuthorizationEndpoint: DeviceAuthURL,
			TokenEndpoint:               TokenURL,
		}, nil
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &Discovery{
			DeviceAuthorizationEndpoint: DeviceAuthURL,
			TokenEndpoint:               TokenURL,
		}, nil
	}

	var payload struct {
		DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
		TokenEndpoint               string `json:"token_endpoint"`
	}
	if err := json.Unmarshal(resp.Body, &payload); err != nil {
		return &Discovery{
			DeviceAuthorizationEndpoint: DeviceAuthURL,
			TokenEndpoint:               TokenURL,
		}, nil
	}

	deviceEP, err := validateOAuthEndpoint(payload.DeviceAuthorizationEndpoint, "device_authorization_endpoint")
	if err != nil {
		deviceEP = DeviceAuthURL
	}
	tokenEP, err := validateOAuthEndpoint(payload.TokenEndpoint, "token_endpoint")
	if err != nil {
		tokenEP = TokenURL
	}

	return &Discovery{
		DeviceAuthorizationEndpoint: deviceEP,
		TokenEndpoint:               tokenEP,
	}, nil
}

func validateOAuthEndpoint(rawURL, field string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", fmt.Errorf("xai discovery %s is empty", field)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("xai discovery %s is invalid: %w", field, err)
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("xai discovery %s must use https: %q", field, rawURL)
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host != "x.ai" && !strings.HasSuffix(host, ".x.ai") {
		return "", fmt.Errorf("xai discovery %s host %q is not on x.ai", field, host)
	}
	return rawURL, nil
}
