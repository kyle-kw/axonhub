package xai

// OAuth / device-flow constants for the public Grok CLI client against auth.x.ai.
// Aligned with CLIProxyAPI internal/auth/xai (OIDC discovery + device flow).
const (
	// Issuer is xAI's OAuth issuer.
	Issuer = "https://auth.x.ai"

	// DiscoveryURL is the OIDC discovery endpoint used to resolve OAuth endpoints.
	DiscoveryURL = Issuer + "/.well-known/openid-configuration"

	// DeviceAuthURL is the fallback RFC 8628 device authorization endpoint.
	DeviceAuthURL = "https://auth.x.ai/oauth2/device/code"

	// TokenURL is the fallback OAuth2 token endpoint (device_code + refresh_token grants).
	//nolint:gosec // public OAuth endpoint URL, not a credential
	TokenURL = "https://auth.x.ai/oauth2/token"

	// AuthorizeURL is the browser authorization endpoint (for completeness; device flow is primary).
	AuthorizeURL = "https://auth.x.ai/oauth2/auth"

	// ClientID is the public xAI Grok CLI OAuth client ID.
	//nolint:gosec // public OAuth client id
	ClientID = "b1a00492-073a-47ea-816f-4c329264a828"

	// Scopes is the OAuth scope set required for xAI API access (CLIProxyAPI / Grok CLI).
	// Order matches CLIProxyAPI: offline_access then grok-cli:access then api:access.
	Scopes = "openid profile email offline_access grok-cli:access api:access"
)

// DefaultOAuthScopes is the scope list used by device-flow start and token providers.
var DefaultOAuthScopes = []string{
	"openid",
	"profile",
	"email",
	"offline_access",
	"grok-cli:access",
	"api:access",
}
