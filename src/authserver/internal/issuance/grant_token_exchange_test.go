package issuance

import (
	"context"
	"database/sql"
	"testing"
	"time"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// An idempotent replay returns the stored access token, with its remaining lifetime, and never
// mints or records a second lineage.
func TestIssueTokenExchangeGrant_IdempotentReplay(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", "http://localhost:9091", testDataCipher, nil)

	const originalToken = "header.payload.signature"
	encrypted, err := testDataCipher.Encrypt(originalToken)
	require.NoError(t, err)

	expiresAt := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second)
	existing := &record.TokenExchange{
		Id:                   1,
		ExchangeJti:          "exchange-jti",
		Scope:                "backend:read",
		IssuedTokenEncrypted: encrypted,
		ExpiresAt:            sql.NullTime{Time: expiresAt, Valid: true},
	}

	tx := &sql.Tx{}
	datamocks.ExpectRunInTransaction(mockDB, tx)
	mockDB.On("GetTokenExchangeByRequestHash", mock.Anything, (tx), mock.Anything).
		Return(existing, nil).Once()

	resp, err := tokenIssuer.IssueTokenExchangeGrant(context.Background(), &record.Settings{Issuer: "https://issuer.example"},
		&TokenExchangeInput{
			Client:      &record.Client{Id: 7, ClientIdentifier: "backend-service"},
			SubjectUser: &record.User{Id: 5, Subject: "user-subject"},
		})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, originalToken, resp.AccessToken)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Equal(t, "backend:read", resp.Scope)
	assert.Equal(t, "urn:ietf:params:oauth:token-type:access_token", resp.IssuedTokenType)
	assert.InDelta(t, 600, resp.ExpiresIn, 2)
}

// A fresh exchange mints the one access token carrying the inherited user claims, the
// intersected audience and scope and the act chain, and records the lineage.
func TestIssueTokenExchangeGrant_FreshMint(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", "http://localhost:9091", testDataCipher, nil)

	settings := &record.Settings{Issuer: "https://issuer.example", TokenExpirationInSeconds: 3600}
	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)
	client := &record.Client{Id: 7, ClientIdentifier: "backend-service", Enabled: true, TokenExchangeEnabled: true,
		// The ClientLoadPermissions mock below leaves the client's permissions as constructed, so
		// the recheck's membership comparison reads these, as the real loader would populate.
		Permissions: []record.Permission{{Id: 10, PermissionIdentifier: "read", ResourceId: 1}},
	}
	user := &record.User{Id: 5, Subject: "user-subject", Enabled: true}

	tx := &sql.Tx{}
	datamocks.ExpectRunInTransaction(mockDB, tx)
	mockDB.On("GetTokenExchangeByRequestHash", mock.Anything, (tx), mock.Anything).
		Return(nil, nil).Once()
	mockDB.On("AcquireClientRow", mock.Anything, (tx), int64(7)).Return(nil)
	mockDB.On("GetClientById", mock.Anything, (tx), int64(7)).Return(client, nil)
	mockDB.On("AcquireUserRow", mock.Anything, (tx), int64(5)).Return(nil)
	mockDB.On("GetUserById", mock.Anything, (tx), int64(5)).Return(user, nil)
	// Sessionless subject: no exchange ancestor row ends the chain at the original grant.
	mockDB.On("GetTokenExchangeByIssuedJti", mock.Anything, (tx), "subject-jti").
		Return(nil, nil)
	mockDB.On("ClientLoadPermissions", mock.Anything, tx, client).Return(nil)
	mockDB.On("PermissionsLoadResources", mock.Anything, tx, mock.Anything).Return(nil)
	// permissions.ResolveScope reads outside the transaction, with a nil tx.
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, (*sql.Tx)(nil), "backend").
		Return(&record.Resource{Id: 1, ResourceIdentifier: "backend"}, nil)
	mockDB.On("GetPermissionsByResourceId", mock.Anything, (*sql.Tx)(nil), int64(1)).
		Return([]record.Permission{{Id: 10, PermissionIdentifier: "read", ResourceId: 1}}, nil)
	mockDB.On("GetCurrentSigningKey", mock.Anything, (tx)).Return(&record.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
	}, nil)
	mockDB.On("CreateTokenExchange", mock.Anything, (tx), mock.AnythingOfType("*record.TokenExchange")).
		Run(func(args mock.Arguments) {
			row := args.Get(2).(*record.TokenExchange)
			assert.Equal(t, int64(7), row.ClientId)
			assert.Equal(t, int64(5), row.SubjectUserId.Int64)
			assert.Equal(t, "subject-jti", row.SubjectTokenJti)
			assert.Equal(t, "backend:read", row.Scope)
			assert.Equal(t, "backend", row.Audience)
			assert.NotEmpty(t, row.IssuedTokenEncrypted)
			assert.True(t, row.ExpiresAt.Valid)
		}).Return(nil).Once()

	input := &TokenExchangeInput{
		Client:              client,
		SubjectUser:         user,
		SubjectTokenString:  "subject-jwt",
		SubjectJti:          "subject-jti",
		SubjectTokenType:    "urn:ietf:params:oauth:token-type:access_token",
		Scope:               "backend:read",
		Audiences:           []string{"backend"},
		AuthStateGeneration: 0,
		AuthenticatedAt:     time.Now().Add(-time.Minute),
		Act:                 map[string]any{"sub": "backend-service"},
		RequestedTokenType:  "urn:ietf:params:oauth:token-type:access_token",
	}

	resp, err := tokenIssuer.IssueTokenExchangeGrant(context.Background(), settings, input)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, resp.IdToken, "an exchange issues an access token and nothing else")
	assert.Empty(t, resp.RefreshToken)
	assert.Equal(t, int64(3600), resp.ExpiresIn)

	claims := verifyAndDecodeToken(t, resp.AccessToken, publicKeyBytes)
	assert.Equal(t, "https://issuer.example", claims["iss"])
	assert.Equal(t, "user-subject", claims["sub"])
	assert.Equal(t, "backend", claims["aud"])
	assert.Equal(t, "backend:read", claims["scope"])
	assert.Equal(t, "Bearer", claims["typ"])
	act, ok := claims["act"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "backend-service", act["sub"])
	_, hasSid := claims["sid"]
	assert.False(t, hasSid, "a sessionless grant carries no sid")
	assert.InDelta(t, float64(0), claims["auth_state_generation"], 0)
}

// A requesting client disabled between validation and commit refuses inside the locked recheck
// and produces no token and no row.
func TestIssueTokenExchangeGrant_ClientDisabledAtCommit(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", "http://localhost:9091", testDataCipher, nil)

	tx := &sql.Tx{}
	datamocks.ExpectRunInTransaction(mockDB, tx)
	mockDB.On("GetTokenExchangeByRequestHash", mock.Anything, (tx), mock.Anything).
		Return(nil, nil).Once()
	mockDB.On("AcquireClientRow", mock.Anything, (tx), int64(7)).Return(nil)
	mockDB.On("GetClientById", mock.Anything, (tx), int64(7)).
		Return(&record.Client{Id: 7, Enabled: false}, nil)

	_, err := tokenIssuer.IssueTokenExchangeGrant(context.Background(),
		&record.Settings{Issuer: "https://issuer.example"},
		&TokenExchangeInput{
			Client:      &record.Client{Id: 7, ClientIdentifier: "backend-service", Enabled: true, TokenExchangeEnabled: true},
			SubjectUser: &record.User{Id: 5, Subject: "user-subject", Enabled: true},
		})
	require.Error(t, err)
	var detail *oauth.ErrorDetail
	require.ErrorAs(t, err, &detail)
	assert.Equal(t, "invalid_grant", detail.Code())
}

// The idempotency identity changes with any of its inputs, so distinct exchanges do not share a
// result.
func TestExchangeRequestHash(t *testing.T) {
	base := &TokenExchangeInput{
		Client:             &record.Client{Id: 7},
		SubjectTokenString: "subject-jwt",
		ActorTokenString:   "",
		RequestedAudience:  "backend",
		RequestedScope:     "backend:read",
		RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
	}
	first := exchangeRequestHash(base)

	otherScope := *base
	otherScope.RequestedScope = "backend:write"
	assert.NotEqual(t, first, exchangeRequestHash(&otherScope))

	otherClient := *base
	otherClient.Client = &record.Client{Id: 8}
	assert.NotEqual(t, first, exchangeRequestHash(&otherClient))

	assert.Len(t, first, 64, "SHA-256 hex")
}
