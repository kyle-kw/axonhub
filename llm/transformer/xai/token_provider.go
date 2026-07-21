package xai

import (
	"context"

	"github.com/looplj/axonhub/llm/httpclient"
	"github.com/looplj/axonhub/llm/oauth"
)

// DefaultTokenURLs are the production xAI OAuth endpoints.
var DefaultTokenURLs = oauth.OAuthUrls{
	AuthorizeUrl: AuthorizeURL,
	TokenUrl:     TokenURL,
}

// DefaultDeviceFlowConfig is the device-flow configuration for xAI OAuth.
// Scopes match CLIProxyAPI / Grok CLI (openid profile email offline_access grok-cli:access api:access).
func DefaultDeviceFlowConfig() oauth.DeviceFlowConfig {
	return oauth.DeviceFlowConfig{
		DeviceAuthURL: DeviceAuthURL,
		TokenURL:      TokenURL,
		ClientID:      ClientID,
		Scopes:        DefaultOAuthScopes,
	}
}

// TokenProviderParams contains parameters for creating an xAI OAuth token provider.
type TokenProviderParams struct {
	Credentials *oauth.OAuthCredentials
	HTTPClient  *httpclient.HttpClient
	OnRefreshed func(ctx context.Context, refreshed *oauth.OAuthCredentials) error
}

// NewTokenProvider creates a form-encoded OAuth token provider for xAI.
// Tokens are refreshed via the standard refresh_token grant against auth.x.ai.
func NewTokenProvider(params TokenProviderParams) *oauth.TokenProvider {
	creds := params.Credentials
	if creds != nil && creds.ClientID == "" {
		// Ensure refresh requests include the public client id.
		copied := *creds
		copied.ClientID = ClientID
		creds = &copied
	}

	return oauth.NewTokenProvider(oauth.TokenProviderParams{
		Credentials: creds,
		HTTPClient:  params.HTTPClient,
		OAuthUrls:   DefaultTokenURLs,
		OnRefreshed: params.OnRefreshed,
		ExchangeStrategy: &oauth.FormEncodedStrategy{},
	})
}

// NewDeviceFlowProvider creates a DeviceFlowProvider configured for xAI OAuth.
func NewDeviceFlowProvider(params oauth.DeviceFlowProviderParams) *oauth.DeviceFlowProvider {
	if params.Config.DeviceAuthURL == "" && params.Config.TokenURL == "" && params.Config.ClientID == "" {
		params.Config = DefaultDeviceFlowConfig()
	} else {
		if params.Config.DeviceAuthURL == "" {
			params.Config.DeviceAuthURL = DeviceAuthURL
		}
		if params.Config.TokenURL == "" {
			params.Config.TokenURL = TokenURL
		}
		if params.Config.ClientID == "" {
			params.Config.ClientID = ClientID
		}
		if len(params.Config.Scopes) == 0 {
			params.Config.Scopes = DefaultOAuthScopes
		}
	}

	return oauth.NewDeviceFlowProvider(params)
}
