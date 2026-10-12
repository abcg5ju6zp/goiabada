package protocolvalidation

import (
	"context"
	"testing"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	protocolvalidationmocks "github.com/leodip/goiabada/authserver/internal/protocolvalidation/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/richauth"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func assertInvalidGrant(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	var detail *oauth.ErrorDetail
	require.ErrorAs(t, err, &detail)
	assert.Equal(t, "invalid_grant", detail.Code())
	assert.Equal(t, 400, detail.HTTPStatus())
}

func recheckFixture(t *testing.T, clientPermissions []record.Permission, userHolds bool) (*TokenValidator, *record.Client, *datamocks.Database) {
	t.Helper()
	mockDB := datamocks.NewDatabase(t)
	mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)
	validator := NewTokenValidator(mockDB, nil, mockPermissionChecker, testDataCipher)

	client := &record.Client{Id: 3, ClientIdentifier: "client1"}
	mockDB.On("ClientLoadPermissions", mock.Anything, mock.Anything, client).Run(func(args mock.Arguments) {
		client.Permissions = clientPermissions
	}).Return(nil)
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "billing").
		Return(&record.Resource{Id: 10, ResourceIdentifier: "billing"}, nil).Maybe()
	mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(10)).
		Return([]record.Permission{{Id: 5, PermissionIdentifier: "read"}}, nil).Maybe()
	// Maybe: a failure of the type or client-license checks returns before the user's
	// grants are consulted.
	mockPermissionChecker.On("UserHasScopePermission", mock.Anything, int64(42), "billing:read").
		Return(userHolds, nil).Maybe()
	return validator, client, mockDB
}

func TestRecheckAuthorizationDetails(t *testing.T) {
	ctx := context.Background()

	t.Run("scope-only code is untouched", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		validator := NewTokenValidator(mockDB, nil, protocolvalidationmocks.NewPermissionChecker(t), testDataCipher)
		require.NoError(t, validator.recheckAuthorizationDetails(ctx, &record.Client{Id: 1},
			&record.Code{AuthorizationDetails: "[]"}))
	})

	t.Run("valid snapshot passes", func(t *testing.T) {
		validator, client, _ := recheckFixture(t,
			[]record.Permission{{Id: 5, PermissionIdentifier: "read"}}, true)
		code := &record.Code{UserId: 42, AuthorizationDetails: richauth.CanonicalJSON([]richauth.Detail{{
			Type: richauth.ResourcePermissionDetailsType, Resource: "billing", Actions: []string{"read"},
		}})}
		require.NoError(t, validator.recheckAuthorizationDetails(ctx, client, code))
	})

	t.Run("malformed snapshot is invalid_grant", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		validator := NewTokenValidator(mockDB, nil, protocolvalidationmocks.NewPermissionChecker(t), testDataCipher)
		err := validator.recheckAuthorizationDetails(ctx, &record.Client{Id: 1},
			&record.Code{UserId: 42, AuthorizationDetails: `[broken`})
		assertInvalidGrant(t, err)
		assert.ErrorContains(t, err, "Code is invalid.")
	})

	t.Run("unsupported type", func(t *testing.T) {
		validator, client, _ := recheckFixture(t,
			[]record.Permission{{Id: 5, PermissionIdentifier: "read"}}, true)
		code := &record.Code{UserId: 42, AuthorizationDetails: `[{"type":"urn:other","resource":"billing","actions":["read"]}]`}
		assertInvalidGrant(t, validator.recheckAuthorizationDetails(ctx, client, code))
	})

	t.Run("client lost the license", func(t *testing.T) {
		validator, client, _ := recheckFixture(t,
			[]record.Permission{{Id: 99, PermissionIdentifier: "other"}}, true)
		code := &record.Code{UserId: 42, AuthorizationDetails: richauth.CanonicalJSON([]richauth.Detail{{
			Type: richauth.ResourcePermissionDetailsType, Resource: "billing", Actions: []string{"read"},
		}})}
		err := validator.recheckAuthorizationDetails(ctx, client, code)
		assertInvalidGrant(t, err)
		assert.ErrorContains(t, err, "licensed")
	})

	t.Run("user lost the permission", func(t *testing.T) {
		validator, client, _ := recheckFixture(t,
			[]record.Permission{{Id: 5, PermissionIdentifier: "read"}}, false)
		code := &record.Code{UserId: 42, AuthorizationDetails: richauth.CanonicalJSON([]richauth.Detail{{
			Type: richauth.ResourcePermissionDetailsType, Resource: "billing", Actions: []string{"read"},
		}})}
		err := validator.recheckAuthorizationDetails(ctx, client, code)
		assertInvalidGrant(t, err)
		assert.ErrorContains(t, err, "no longer holds")
	})
}
