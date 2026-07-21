package biz

import (
	"context"
	"testing"
	"time"

	"github.com/samber/lo"
	"github.com/stretchr/testify/require"

	"github.com/looplj/axonhub/internal/authz"
	"github.com/looplj/axonhub/internal/ent/channel"
	"github.com/looplj/axonhub/internal/ent/enttest"
	"github.com/looplj/axonhub/internal/objects"
	"github.com/looplj/axonhub/llm"
	"github.com/looplj/axonhub/llm/oauth"
	"github.com/looplj/axonhub/llm/transformer/xai"
)

func TestXaiChannel_APIKeyPath(t *testing.T) {
	client := enttest.NewEntClient(t, "sqlite3", "file:ent?mode=memory&_fk=0")
	defer client.Close()

	ctx := authz.WithTestBypass(context.Background())

	entChannel := client.Channel.Create().
		SetName("xAI API Key").
		SetType(channel.TypeXai).
		SetBaseURL("https://api.x.ai/v1").
		SetCredentials(objects.ChannelCredentials{APIKeys: []string{"xai-api-key"}}).
		SetSupportedModels([]string{"grok-3"}).
		SetDefaultTestModel("grok-3").
		SaveX(ctx)

	channelSvc := NewChannelServiceForTest(client)
	built, err := channelSvc.buildChannelWithTransformer(entChannel)
	require.NoError(t, err)
	require.NotNil(t, built.Outbound)

	xaiOut, ok := built.Outbound.(*xai.OutboundTransformer)
	require.True(t, ok)
	require.Nil(t, xaiOut.TokenProvider())

	req, err := built.Outbound.TransformRequest(ctx, &llm.Request{
		Model: "grok-3",
		Messages: []llm.Message{
			{Role: "user", Content: llm.MessageContent{Content: lo.ToPtr("hi")}},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, req.Auth)
	require.Equal(t, "bearer", req.Auth.Type)
	require.Equal(t, "xai-api-key", req.Auth.APIKey)
}

func TestXaiChannel_OAuthPath_BearerAndTokenProvider(t *testing.T) {
	client := enttest.NewEntClient(t, "sqlite3", "file:ent?mode=memory&_fk=0")
	defer client.Close()

	ctx := authz.WithTestBypass(context.Background())

	oauthCreds := &oauth.OAuthCredentials{
		AccessToken:  "xai-oauth-access",
		RefreshToken: "xai-oauth-refresh",
		ClientID:     xai.ClientID,
		ExpiresAt:    time.Now().Add(time.Hour),
		TokenType:    "bearer",
		Scopes:       xai.DefaultOAuthScopes,
	}
	credJSON, err := oauthCreds.ToJSON()
	require.NoError(t, err)

	entChannel := client.Channel.Create().
		SetName("xAI OAuth").
		SetType(channel.TypeXai).
		SetBaseURL("https://api.x.ai/v1").
		SetCredentials(objects.ChannelCredentials{
			APIKey: credJSON,
			OAuth:  oauthCreds,
		}).
		SetSupportedModels([]string{"grok-3"}).
		SetDefaultTestModel("grok-3").
		SaveX(ctx)

	channelSvc := NewChannelServiceForTest(client)
	built, err := channelSvc.buildChannelWithTransformer(entChannel)
	require.NoError(t, err)
	require.NotNil(t, built.Outbound)

	xaiOut, ok := built.Outbound.(*xai.OutboundTransformer)
	require.True(t, ok)
	require.NotNil(t, xaiOut.TokenProvider())

	req, err := built.Outbound.TransformRequest(ctx, &llm.Request{
		Model: "grok-3",
		Messages: []llm.Message{
			{Role: "user", Content: llm.MessageContent{Content: lo.ToPtr("hi")}},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, req.Auth)
	require.Equal(t, "bearer", req.Auth.Type)
	require.Equal(t, "xai-oauth-access", req.Auth.APIKey)
}

func TestXaiChannel_MissingCredentials(t *testing.T) {
	client := enttest.NewEntClient(t, "sqlite3", "file:ent?mode=memory&_fk=0")
	defer client.Close()

	ctx := authz.WithTestBypass(context.Background())

	entChannel := client.Channel.Create().
		SetName("xAI Empty").
		SetType(channel.TypeXai).
		SetBaseURL("https://api.x.ai/v1").
		SetCredentials(objects.ChannelCredentials{}).
		SetSupportedModels([]string{"grok-3"}).
		SetDefaultTestModel("grok-3").
		SaveX(ctx)

	channelSvc := NewChannelServiceForTest(client)
	_, err := channelSvc.buildChannelWithTransformer(entChannel)
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing credentials")
}
