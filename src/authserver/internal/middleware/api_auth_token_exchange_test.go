package middleware

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// A token an RFC 8693 exchange issued carries auth_time (so the user/session path runs) and an act
// claim marking its lineage.
func exchangedToken() oauth.JwtToken {
	return oauth.JwtToken{Claims: map[string]interface{}{
		"sub":                   "user-1",
		"auth_time":             float64(1),
		"auth_state_generation": float64(0),
		"jti":                   "derived-jti",
		"act":                   map[string]any{"sub": "backend-service"},
	}}
}

func serveValidSession(t *testing.T, db *datamocks.Database, token oauth.JwtToken) (bool, int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req = req.WithContext(reqctx.WithBearerToken(req.Context(), token))
	rr := httptest.NewRecorder()
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalled = true })
	apiBearerForTest.RequireValidSession(db)(next).ServeHTTP(rr, req)
	return nextCalled, rr.Code
}

func TestRequireValidSession_TokenExchangeLineage(t *testing.T) {
	t.Run("valid lineage passes", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, "user-1").
			Return(&record.User{Id: 1, Enabled: true}, nil)
		mockDB.On("GetTokenExchangeByIssuedJti", mock.Anything, mock.Anything, "derived-jti").
			Return(&record.TokenExchange{
				ExchangeJti:   "derived-jti",
				ClientId:      7,
				SubjectUserId: sql.NullInt64{Int64: 1, Valid: true},
			}, nil)
		mockDB.On("GetClientById", mock.Anything, mock.Anything, int64(7)).
			Return(&record.Client{Id: 7, Enabled: true}, nil)

		next, code := serveValidSession(t, mockDB, exchangedToken())
		assert.True(t, next)
		assert.Equal(t, http.StatusOK, code)
	})

	t.Run("a missing lineage row fails closed", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, "user-1").
			Return(&record.User{Id: 1, Enabled: true}, nil)
		mockDB.On("GetTokenExchangeByIssuedJti", mock.Anything, mock.Anything, "derived-jti").
			Return(nil, nil)

		next, _ := serveValidSession(t, mockDB, exchangedToken())
		assert.False(t, next, "a token claiming a lineage nothing records must be refused")
	})

	t.Run("the requesting client disabled invalidates the derived token", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, "user-1").
			Return(&record.User{Id: 1, Enabled: true}, nil)
		mockDB.On("GetTokenExchangeByIssuedJti", mock.Anything, mock.Anything, "derived-jti").
			Return(&record.TokenExchange{
				ExchangeJti:   "derived-jti",
				ClientId:      7,
				SubjectUserId: sql.NullInt64{Int64: 1, Valid: true},
			}, nil)
		mockDB.On("GetClientById", mock.Anything, mock.Anything, int64(7)).
			Return(&record.Client{Id: 7, Enabled: false}, nil)

		next, _ := serveValidSession(t, mockDB, exchangedToken())
		assert.False(t, next)
	})

	t.Run("a revoked source code invalidates the derived token", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, "user-1").
			Return(&record.User{Id: 1, Enabled: true}, nil)
		mockDB.On("GetTokenExchangeByIssuedJti", mock.Anything, mock.Anything, "derived-jti").
			Return(&record.TokenExchange{
				ExchangeJti:   "derived-jti",
				ClientId:      7,
				SubjectUserId: sql.NullInt64{Int64: 1, Valid: true},
				SourceCodeId:  sql.NullInt64{Int64: 99, Valid: true},
			}, nil)
		mockDB.On("GetClientById", mock.Anything, mock.Anything, int64(7)).
			Return(&record.Client{Id: 7, Enabled: true}, nil)
		mockDB.On("GetCodeById", mock.Anything, mock.Anything, int64(99)).
			Return(&record.Code{Id: 99, Revoked: true}, nil)

		next, _ := serveValidSession(t, mockDB, exchangedToken())
		assert.False(t, next)
	})

	t.Run("a token without an act claim is not lineage-checked", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		token := oauth.JwtToken{Claims: map[string]interface{}{
			"sub":                   "user-1",
			"auth_time":             float64(1),
			"auth_state_generation": float64(0),
		}}
		mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, "user-1").
			Return(&record.User{Id: 1, Enabled: true}, nil)

		next, code := serveValidSession(t, mockDB, token)
		assert.True(t, next)
		assert.Equal(t, http.StatusOK, code)
		mockDB.AssertNotCalled(t, "GetTokenExchangeByIssuedJti", mock.Anything, mock.Anything, mock.Anything)
	})
}
