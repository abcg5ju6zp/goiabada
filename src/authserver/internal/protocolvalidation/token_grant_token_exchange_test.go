package protocolvalidation

import (
	"context"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/record"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	protocolvalidationmocks "github.com/leodip/goiabada/authserver/internal/protocolvalidation/mocks"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/mock"
)

type exchangeHarness struct {
	db       *datamocks.Database
	parser   *protocolvalidationmocks.TokenParser
	checker  *protocolvalidationmocks.PermissionChecker
	settings *record.Settings
}

func newExchangeHarness(t *testing.T) (*TokenValidator, *exchangeHarness) {
	t.Helper()
	h := &exchangeHarness{
		db:       datamocks.NewDatabase(t),
		parser:   protocolvalidationmocks.NewTokenParser(t),
		checker:  protocolvalidationmocks.NewPermissionChecker(t),
		settings: &record.Settings{Issuer: "https://issuer.example"},
	}
	return NewTokenValidator(h.db, h.parser, h.checker, testDataCipher), h
}

func exchangeClient() *record.Client {
	secretEnc, _ := testDataCipher.Encrypt("the-secret")
	return &record.Client{
		Id:                       100,
		ClientIdentifier:         "backend-service",
		Enabled:                  true,
		TokenExchangeEnabled:     true,
		ClientSecretEncrypted:    secretEnc,
		Permissions: []record.Permission{
			{Id: 10, PermissionIdentifier: "read", ResourceId: 1},
			{Id: 11, PermissionIdentifier: "write", ResourceId: 1},
		},
	}
}

func subjectClaims() map[string]any {
	return map[string]any{
		"iss":                   "https://issuer.example",
		"typ":                   "Bearer",
		"jti":                   "subject-jti",
		"sub":                   "user-subject",
		"scope":                 "backend:read backend:write",
		"auth_time":             time.Now().Unix(),
		"auth_state_generation": float64(0),
	}
}

// The distinguishable protocol errors RFC 8693 section 3.2.2 assigns, before any token work.
func TestTokenExchange_ProtocolErrors(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name      string
		input     *ValidateTokenRequestInput
		client    *record.Client
		code      string
		http      int
		setup     func(h *exchangeHarness)
	}{
		{
			name: "client not permitted",
			client: func() *record.Client { c := exchangeClient(); c.TokenExchangeEnabled = false; return c }(),
			input: &ValidateTokenRequestInput{GrantType: oidc.GrantTypeTokenExchange, ClientId: "backend-service",
				ClientSecret: "the-secret", SubjectToken: "s", SubjectTokenType: oidc.TokenTypeAccessURN},
			code: "unauthorized_client", http: 400,
		},
		{
			name: "public client refused",
			client: func() *record.Client { c := exchangeClient(); c.IsPublic = true; return c }(),
			input: &ValidateTokenRequestInput{GrantType: oidc.GrantTypeTokenExchange, ClientId: "backend-service",
				SubjectToken: "s", SubjectTokenType: oidc.TokenTypeAccessURN},
			code: "unauthorized_client", http: 400,
		},
		{
			name:   "missing subject_token",
			client: exchangeClient(),
			input:  &ValidateTokenRequestInput{GrantType: oidc.GrantTypeTokenExchange, ClientId: "backend-service", ClientSecret: "the-secret", SubjectTokenType: oidc.TokenTypeAccessURN},
			code:   "invalid_request", http: 400,
		},
		{
			name:   "missing subject_token_type",
			client: exchangeClient(),
			input:  &ValidateTokenRequestInput{GrantType: oidc.GrantTypeTokenExchange, ClientId: "backend-service", ClientSecret: "the-secret", SubjectToken: "s"},
			code:   "invalid_request", http: 400,
		},
		{
			name:   "unsupported subject_token_type",
			client: exchangeClient(),
			input:  &ValidateTokenRequestInput{GrantType: oidc.GrantTypeTokenExchange, ClientId: "backend-service", ClientSecret: "the-secret", SubjectToken: "s", SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt"},
			code:   "invalid_request", http: 400,
		},
		{
			name:   "actor token without its type",
			client: exchangeClient(),
			input:  &ValidateTokenRequestInput{GrantType: oidc.GrantTypeTokenExchange, ClientId: "backend-service", ClientSecret: "the-secret", SubjectToken: "s", SubjectTokenType: oidc.TokenTypeAccessURN, ActorToken: "a"},
			code:   "invalid_request", http: 400,
		},
		{
			name:   "unsupported actor_token_type",
			client: exchangeClient(),
			input:  &ValidateTokenRequestInput{GrantType: oidc.GrantTypeTokenExchange, ClientId: "backend-service", ClientSecret: "the-secret", SubjectToken: "s", SubjectTokenType: oidc.TokenTypeAccessURN, ActorToken: "a", ActorTokenType: oidc.TokenTypeRefreshURN},
			code:   "invalid_request", http: 400,
		},
		{
			name:   "unsupported requested_token_type",
			client: exchangeClient(),
			input:  &ValidateTokenRequestInput{GrantType: oidc.GrantTypeTokenExchange, ClientId: "backend-service", ClientSecret: "the-secret", SubjectToken: "s", SubjectTokenType: oidc.TokenTypeAccessURN, RequestedTokenType: oidc.TokenTypeRefreshURN},
			code:   "unsupported_grant_type", http: 400,
		},
		{
			name:   "unknown audience is invalid_target",
			client: exchangeClient(),
			input:  &ValidateTokenRequestInput{GrantType: oidc.GrantTypeTokenExchange, ClientId: "backend-service", ClientSecret: "the-secret", SubjectToken: "s", SubjectTokenType: oidc.TokenTypeAccessURN, Audience: "unknown-resource"},
			code:   "invalid_target", http: 400,
			setup: func(h *exchangeHarness) {
				h.db.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "unknown-resource").
					Return(nil, nil).Once()
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			validator, h := newExchangeHarness(t)
			h.db.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "backend-service").
				Return(tc.client, nil).Once()
			if tc.setup != nil {
				tc.setup(h)
			}

			grant, err := validator.ValidateTokenRequest(ctx, h.settings, tc.input)
			require.Error(t, err)
			assert.Nil(t, grant)
			var detail *oauth.ErrorDetail
			require.ErrorAs(t, err, &detail)
			assert.Equal(t, tc.code, detail.Code())
			assert.Equal(t, tc.http, detail.HTTPStatus())
		})
	}
}

func TestTokenExchange_SubjectTokenInvalid(t *testing.T) {
	validator, h := newExchangeHarness(t)
	h.db.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "backend-service").
		Return(exchangeClient(), nil).Once()
	h.parser.On("DecodeAndValidateTokenString", mock.Anything, "garbage", true).
		Return(nil, assert.AnError).Once()

	input := &ValidateTokenRequestInput{GrantType: oidc.GrantTypeTokenExchange, ClientId: "backend-service",
		ClientSecret: "the-secret", SubjectToken: "garbage", SubjectTokenType: oidc.TokenTypeAccessURN}
	grant, err := validator.ValidateTokenRequest(context.Background(), h.settings, input)
	require.Error(t, err)
	assert.Nil(t, grant)
	var detail *oauth.ErrorDetail
	require.ErrorAs(t, err, &detail)
	assert.Equal(t, "invalid_grant", detail.Code())
}

// The full intersection for an access-token subject: the issued scope is the subject's, the
// actor's, the client's and the user's grant intersected, bounded to the requested audience.
func TestTokenExchange_Intersection(t *testing.T) {
	ctx := context.Background()

	t.Run("grants the intersection and inherits the subject's context", func(t *testing.T) {
		validator, h := newExchangeHarness(t)
		client := exchangeClient()
		h.db.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "backend-service").Return(client, nil)
		h.db.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend").
			Return(&record.Resource{Id: 1, ResourceIdentifier: "backend"}, nil)
		h.parser.On("DecodeAndValidateTokenString", mock.Anything, "subject-jwt", true).
			Return(&oauth.JwtToken{Claims: subjectClaims()}, nil)
		h.db.On("GetUserBySubject", mock.Anything, mock.Anything, "user-subject").
			Return(&record.User{Id: 5, Subject: "user-subject", Enabled: true}, nil)
		h.db.On("ClientLoadPermissions", mock.Anything, mock.Anything, client).Return(nil)
		h.db.On("PermissionsLoadResources", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		h.db.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend").
			Return(&record.Resource{Id: 1, ResourceIdentifier: "backend"}, nil)
		h.db.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(1)).
			Return([]record.Permission{
				{Id: 10, PermissionIdentifier: "read", ResourceId: 1},
				{Id: 11, PermissionIdentifier: "write", ResourceId: 1},
			}, nil)
		h.checker.On("UserHasScopePermission", mock.Anything, int64(5), mock.Anything).Return(true, nil)

		input := &ValidateTokenRequestInput{GrantType: oidc.GrantTypeTokenExchange, ClientId: "backend-service",
			ClientSecret: "the-secret", SubjectToken: "subject-jwt", SubjectTokenType: oidc.TokenTypeAccessURN,
			Audience: "backend", Scope: "backend:read"}

		grant, err := validator.ValidateTokenRequest(ctx, h.settings, input)
		require.NoError(t, err)
		ex := grantAs[*TokenExchangeGrant](t, grant)
		assert.Equal(t, "backend:read", ex.Scope)
		assert.Equal(t, []string{"backend"}, ex.Audiences)
		assert.Equal(t, int64(5), ex.SubjectUser.Id)
		assert.Equal(t, "subject-jti", ex.SubjectJti)
		assert.Equal(t, "backend-service", ex.Act["sub"])
	})

	t.Run("the actor narrows the grant", func(t *testing.T) {
		validator, h := newExchangeHarness(t)
		client := exchangeClient()
		h.db.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "backend-service").Return(client, nil)
		h.db.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend").
			Return(&record.Resource{Id: 1, ResourceIdentifier: "backend"}, nil)
		h.parser.On("DecodeAndValidateTokenString", mock.Anything, "subject-jwt", true).
			Return(&oauth.JwtToken{Claims: subjectClaims()}, nil)
		actorClaims := map[string]any{
			"iss": "https://issuer.example", "typ": "Bearer", "jti": "actor-jti",
			"sub": "actor-service", "scope": "backend:read",
		}
		h.parser.On("DecodeAndValidateTokenString", mock.Anything, "actor-jwt", true).
			Return(&oauth.JwtToken{Claims: actorClaims}, nil)
		h.db.On("GetUserBySubject", mock.Anything, mock.Anything, "user-subject").
			Return(&record.User{Id: 5, Subject: "user-subject", Enabled: true}, nil)
		h.db.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "actor-service").
			Return(nil, nil)
		h.db.On("ClientLoadPermissions", mock.Anything, mock.Anything, client).Return(nil)
		h.db.On("PermissionsLoadResources", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		h.db.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend").
			Return(&record.Resource{Id: 1, ResourceIdentifier: "backend"}, nil)
		h.db.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(1)).
			Return([]record.Permission{
				{Id: 10, PermissionIdentifier: "read", ResourceId: 1},
				{Id: 11, PermissionIdentifier: "write", ResourceId: 1},
			}, nil)
		h.checker.On("UserHasScopePermission", mock.Anything, int64(5), mock.Anything).Return(true, nil)

		input := &ValidateTokenRequestInput{GrantType: oidc.GrantTypeTokenExchange, ClientId: "backend-service",
			ClientSecret: "the-secret", SubjectToken: "subject-jwt", SubjectTokenType: oidc.TokenTypeAccessURN,
			ActorToken: "actor-jwt", ActorTokenType: oidc.TokenTypeAccessURN, Audience: "backend"}

		grant, err := validator.ValidateTokenRequest(ctx, h.settings, input)
		require.NoError(t, err)
		ex := grantAs[*TokenExchangeGrant](t, grant)
		assert.Equal(t, "backend:read", ex.Scope, "write is not in the actor's token")
		assert.Equal(t, "actor-service", ex.Act["sub"])
		assert.Equal(t, "actor-jti", ex.ActorJti)
	})

	t.Run("an empty intersection is invalid_scope", func(t *testing.T) {
		validator, h := newExchangeHarness(t)
		client := exchangeClient()
		client.Permissions = nil
		h.db.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "backend-service").Return(client, nil)
		h.db.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend").
			Return(&record.Resource{Id: 1, ResourceIdentifier: "backend"}, nil)
		h.parser.On("DecodeAndValidateTokenString", mock.Anything, "subject-jwt", true).
			Return(&oauth.JwtToken{Claims: subjectClaims()}, nil)
		h.db.On("GetUserBySubject", mock.Anything, mock.Anything, "user-subject").
			Return(&record.User{Id: 5, Subject: "user-subject", Enabled: true}, nil)
		h.db.On("ClientLoadPermissions", mock.Anything, mock.Anything, client).Return(nil)
		h.db.On("PermissionsLoadResources", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		h.db.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "backend").
			Return(&record.Resource{Id: 1, ResourceIdentifier: "backend"}, nil)
		h.db.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(1)).
			Return([]record.Permission{{Id: 10, PermissionIdentifier: "read", ResourceId: 1}}, nil)
		h.checker.On("UserHasScopePermission", mock.Anything, int64(5), mock.Anything).Return(true, nil)

		input := &ValidateTokenRequestInput{GrantType: oidc.GrantTypeTokenExchange, ClientId: "backend-service",
			ClientSecret: "the-secret", SubjectToken: "subject-jwt", SubjectTokenType: oidc.TokenTypeAccessURN,
			Audience: "backend"}
		_, err := validator.ValidateTokenRequest(ctx, h.settings, input)
		require.Error(t, err)
		var detail *oauth.ErrorDetail
		require.ErrorAs(t, err, &detail)
		assert.Equal(t, "invalid_scope", detail.Code())
	})
}

// The act chain nesting rules: depth counts nested act objects and the new actor wraps the
// subject's chain.
func TestTokenExchange_ActChainHelpers(t *testing.T) {
	direct := map[string]any{"sub": "a"}
	nested := map[string]any{"sub": "b", "act": direct}
	twiceNested := map[string]any{"sub": "c", "act": nested}

	assert.Equal(t, 1, actorChainDepth(direct))
	assert.Equal(t, 2, actorChainDepth(nested))
	assert.Equal(t, 3, actorChainDepth(twiceNested))

	built := buildActClaim("actor", nested)
	assert.Equal(t, "actor", built["sub"])
	assert.Equal(t, nested, built["act"])
}
