package protocolvalidation

import (
	"context"
	"testing"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/richauth"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// assertInvalidRequest asserts the failure is an oauth invalid_request detail.
func assertInvalidRequest(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	var detail *oauth.ErrorDetail
	require.ErrorAs(t, err, &detail)
	assert.Equal(t, "invalid_request", detail.Code())
	assert.Equal(t, 400, detail.HTTPStatus())
}

func detailRaw(body string) string {
	return `[{"type":"urn:goiabada:resource-permission","resource":"billing","actions":["read"]` + body + `}]`
}

func TestValidateAuthorizationDetails(t *testing.T) {
	ctx := context.Background()

	t.Run("empty raw is a scope-only request", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		validator := NewAuthorizeValidator(mockDB)
		client := &record.Client{Id: 1}

		details, err := validator.ValidateAuthorizationDetails(ctx,
			&ValidateAuthorizationDetailsInput{Client: client, Raw: "", ResponseType: "code"})
		require.NoError(t, err)
		assert.Nil(t, details)
	})

	t.Run("valid request is canonicalized", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		validator := NewAuthorizeValidator(mockDB)
		client := &record.Client{Id: 1}
		mockDB.On("ClientLoadPermissions", mock.Anything, mock.Anything, client).Run(func(args mock.Arguments) {
			client.Permissions = []record.Permission{{Id: 5, PermissionIdentifier: "read"}, {Id: 6, PermissionIdentifier: "write"}}
		}).Return(nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "billing").
			Return(&record.Resource{Id: 10, ResourceIdentifier: "billing"}, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(10)).
			Return([]record.Permission{{Id: 5, PermissionIdentifier: "read"}, {Id: 6, PermissionIdentifier: "write"}}, nil)

		raw := `[{"type":"urn:goiabada:resource-permission","resource":"billing","actions":["write","read"]}]`
		details, err := validator.ValidateAuthorizationDetails(ctx,
			&ValidateAuthorizationDetailsInput{Client: client, Raw: raw, ResponseType: "code"})
		require.NoError(t, err)
		assert.Equal(t, []richauth.Detail{{
			Type:     richauth.ResourcePermissionDetailsType,
			Resource: "billing",
			Actions:  []string{"read", "write"},
		}}, details)
	})

	t.Run("unknown resource", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		validator := NewAuthorizeValidator(mockDB)
		client := &record.Client{Id: 1}
		mockDB.On("ClientLoadPermissions", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "billing").Return(nil, nil)

		_, err := validator.ValidateAuthorizationDetails(ctx,
			&ValidateAuthorizationDetailsInput{Client: client, Raw: detailRaw(""), ResponseType: "code"})
		assertInvalidRequest(t, err)
		assert.Contains(t, err.Error(), "does not exist")
	})

	t.Run("unknown action", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		validator := NewAuthorizeValidator(mockDB)
		client := &record.Client{Id: 1}
		mockDB.On("ClientLoadPermissions", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "billing").
			Return(&record.Resource{Id: 10, ResourceIdentifier: "billing"}, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(10)).
			Return([]record.Permission{{Id: 9, PermissionIdentifier: "other"}}, nil)

		_, err := validator.ValidateAuthorizationDetails(ctx,
			&ValidateAuthorizationDetailsInput{Client: client, Raw: detailRaw(""), ResponseType: "code"})
		assertInvalidRequest(t, err)
		assert.Contains(t, err.Error(), "no such permission")
	})

	t.Run("client is not licensed", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		validator := NewAuthorizeValidator(mockDB)
		client := &record.Client{Id: 1}
		mockDB.On("ClientLoadPermissions", mock.Anything, mock.Anything, client).Run(func(args mock.Arguments) {
			client.Permissions = []record.Permission{{Id: 99, PermissionIdentifier: "read"}}
		}).Return(nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "billing").
			Return(&record.Resource{Id: 10, ResourceIdentifier: "billing"}, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(10)).
			Return([]record.Permission{{Id: 5, PermissionIdentifier: "read"}}, nil)

		_, err := validator.ValidateAuthorizationDetails(ctx,
			&ValidateAuthorizationDetailsInput{Client: client, Raw: detailRaw(""), ResponseType: "code"})
		assertInvalidRequest(t, err)
		assert.Contains(t, err.Error(), "not licensed")
	})

	t.Run("implicit response type is refused", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		validator := NewAuthorizeValidator(mockDB)
		client := &record.Client{Id: 1}

		_, err := validator.ValidateAuthorizationDetails(ctx,
			&ValidateAuthorizationDetailsInput{Client: client, Raw: detailRaw(""), ResponseType: "token"})
		assertInvalidRequest(t, err)
		assert.Contains(t, err.Error(), "authorization code flow")
	})

	t.Run("malformed json is invalid_request", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		validator := NewAuthorizeValidator(mockDB)
		client := &record.Client{Id: 1}

		_, err := validator.ValidateAuthorizationDetails(ctx,
			&ValidateAuthorizationDetailsInput{Client: client, Raw: `[`, ResponseType: "code"})
		assertInvalidRequest(t, err)
	})
}
