package issuance

import (
	"context"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/richauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func detailsAccessToken(t *testing.T, stored string) map[string]any {
	t.Helper()
	mockDB := datamocks.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", "http://localhost:9091", testDataCipher, nil)
	settings := &record.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		IncludeOpenIDConnectClaimsInAccessToken: true,
	}
	now := time.Now().UTC()

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(getTestPrivateKey(t))
	require.NoError(t, err)

	code := &record.Code{
		Id: 1, ClientId: 1, UserId: 1,
		Scope:                "openid profile",
		AuthenticatedAt:      now.Add(-time.Minute),
		SessionIdentifier:    "session-1",
		AcrLevel:             "urn:goiabada:pwd",
		AuthMethods:          "pwd",
		AuthorizationDetails: stored,
		Client: record.Client{
			Id: 1, ClientIdentifier: "test-client",
			IncludeOpenIDConnectClaimsInAccessToken: "on",
		},
		User: record.User{Id: 1, Subject: "sub-1"},
	}
	mockDB.On("UserHasProfilePicture", mock.Anything, mock.Anything, int64(1)).Return(false, nil)

	token, err := tokenIssuer.generateAccessToken(context.Background(), nil, settings, code, code.Scope, now, privKey, "test-key-id", nil)
	require.NoError(t, err)
	return verifyAndDecodeToken(t, token, getTestPublicKey(t))
}

func TestAccessToken_AuthorizationDetailsClaim(t *testing.T) {
	snapshot := richauth.CanonicalJSON([]richauth.Detail{{
		Type: richauth.ResourcePermissionDetailsType, Resource: "billing", Actions: []string{"read", "write"},
	}})
	claims := detailsAccessToken(t, snapshot)

	raw, ok := claims[richauth.ParameterName]
	require.True(t, ok, "the access token carries authorization_details")
	items, ok := raw.([]any)
	require.True(t, ok)
	require.Len(t, items, 1)
	item := items[0].(map[string]any)
	assert.Equal(t, richauth.ResourcePermissionDetailsType, item["type"])
	assert.Equal(t, "billing", item["resource"])
	assert.Equal(t, []any{"read", "write"}, item["actions"])
}

func TestAccessToken_NoAuthorizationDetailsClaimForScopeOnly(t *testing.T) {
	for _, stored := range []string{"", "[]"} {
		claims := detailsAccessToken(t, stored)
		_, present := claims[richauth.ParameterName]
		assert.False(t, present, "scope-only tokens omit the claim (stored=%q)", stored)
	}
}
