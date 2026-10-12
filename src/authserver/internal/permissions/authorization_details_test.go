package permissions

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/richauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// newDetailsDB is a mock database with a resource() helper for the authorization
// details filter tests.
func newDetailsDB(t *testing.T) *datamocks.Database {
	t.Helper()
	return datamocks.NewDatabase(t)
}

// resource stubs one resource lookup. With no permissions it is taken to not exist as
// a usable target only when nil is returned; the helper always returns the row.
func resourceExpectations(mockDB *datamocks.Database, identifier string, id int64, perms ...record.Permission) {
	res := &record.Resource{Id: id, ResourceIdentifier: identifier}
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, identifier).Return(res, nil)
	mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, id).Return(perms, nil)
}

func TestFilterAuthorizationDetails_KeepsHeldActions(t *testing.T) {
	mockDB := newDetailsDB(t)
	pc := NewChecker(mockDB)

	// The user holds read directly; write comes from a group; delete is not held.
	user := &record.User{
		Id:          1,
		Permissions: []record.Permission{{Id: 5, PermissionIdentifier: "read"}},
		Groups: []record.Group{
			{Id: 7, Permissions: []record.Permission{{Id: 6, PermissionIdentifier: "write"}}},
		},
	}
	expectUserLoaded(mockDB, user, 1)

	resourceExpectations(mockDB, "billing", 10,
		record.Permission{Id: 5, PermissionIdentifier: "read"},
		record.Permission{Id: 6, PermissionIdentifier: "write"},
		record.Permission{Id: 7, PermissionIdentifier: "delete"},
	)
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "missing").Return(nil, nil)

	details := []richauth.Detail{
		{Type: richauth.ResourcePermissionDetailsType, Resource: "billing", Actions: []string{"delete", "write", "read"}},
		{Type: richauth.ResourcePermissionDetailsType, Resource: "missing", Actions: []string{"read"}},
	}

	got, err := pc.FilterAuthorizationDetails(context.Background(), details, user)
	require.NoError(t, err)

	assert.Equal(t, []richauth.Detail{
		{Type: richauth.ResourcePermissionDetailsType, Resource: "billing", Actions: []string{"read", "write"}},
	}, got)
}

func TestFilterAuthorizationDetails_EmptyInput(t *testing.T) {
	pc := NewChecker(newDetailsDB(t))
	got, err := pc.FilterAuthorizationDetails(context.Background(), nil, &record.User{Id: 1})
	require.NoError(t, err)
	assert.Nil(t, got)

	_, err = pc.FilterAuthorizationDetails(context.Background(), nil, nil)
	require.Error(t, err)
}
