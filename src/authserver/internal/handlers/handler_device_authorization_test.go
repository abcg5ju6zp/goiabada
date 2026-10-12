package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/deviceflow"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const deviceAuthorizationTestURL = "https://auth.example.com"

func newDeviceDatabase(t *testing.T) *datamocks.Database {
	t.Helper()
	return datamocks.NewDatabase(t)
}

func deviceAuthorizationRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/auth/device", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestHandleDeviceAuthorizationPost(t *testing.T) {
	t.Run("issues the code pair for an enabled public client", func(t *testing.T) {
		jsonWriter := handlersmocks.NewJSONWriter(t)
		database := newDeviceDatabase(t)
		scopeValidator := handlersmocks.NewAuthorizeValidator(t)
		client := &record.Client{Id: 9, ClientIdentifier: "tv-device", Enabled: true, IsPublic: true,
			DeviceAuthorizationGrantEnabled: true}
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "tv-device").
			Return(client, nil).Once()
		scopeValidator.On("ValidateScopes", mock.Anything, "openid").Return(nil).Once()
		database.On("CreateDeviceCode", mock.Anything, mock.Anything,
			mock.MatchedBy(func(dc *record.DeviceCode) bool {
				return dc.ClientId == 9 && dc.Scope == "openid" &&
					dc.IntervalSeconds == deviceflow.IntervalSeconds &&
					len(dc.DeviceCodeHash) == 64 && len(dc.UserCodeHash) == 64 &&
					!dc.ExpiresAt.IsZero()
				// Status pending is stamped by CreateDeviceCode itself, not by the handler.
			})).Return(nil).Once()

		var response deviceAuthorizationResponse
		jsonWriter.On("EncodeJSON", mock.Anything, mock.Anything,
			mock.AnythingOfType("handlers.deviceAuthorizationResponse")).
			Run(func(args mock.Arguments) { response = args.Get(2).(deviceAuthorizationResponse) }).Return().Once()

		rr := httptest.NewRecorder()
		handler := HandleDeviceAuthorizationPost(jsonWriter, database, scopeValidator, testDataCipher, deviceAuthorizationTestURL)
		handler.ServeHTTP(rr, deviceAuthorizationRequest(t, "client_id=tv-device"))

		require.NotEmpty(t, response.DeviceCode)
		require.Len(t, response.UserCode, 9, "XXXX-XXXX")
		assert.Equal(t, deviceAuthorizationTestURL+"/device", response.VerificationURI)
		assert.Contains(t, response.VerificationURIComplete, response.VerificationURI+"?user_code=")
		assert.Equal(t, deviceflow.LifetimeSeconds, response.ExpiresIn)
		assert.Equal(t, deviceflow.IntervalSeconds, response.Interval)
		assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
	})

	t.Run("refuses a client with the grant disabled", func(t *testing.T) {
		jsonWriter := handlersmocks.NewJSONWriter(t)
		database := newDeviceDatabase(t)
		scopeValidator := handlersmocks.NewAuthorizeValidator(t)
		client := &record.Client{Id: 9, ClientIdentifier: "tv-device", Enabled: true,
			DeviceAuthorizationGrantEnabled: false}
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "tv-device").
			Return(client, nil).Once()
		jsonWriter.On("JSONError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			var detail *oauth.ErrorDetail
			return errors.As(err, &detail) && detail.Code() == "unauthorized_client"
		})).Return().Once()

		handler := HandleDeviceAuthorizationPost(jsonWriter, database, scopeValidator, testDataCipher, deviceAuthorizationTestURL)
		handler.ServeHTTP(httptest.NewRecorder(), deviceAuthorizationRequest(t, "client_id=tv-device"))

		database.AssertNotCalled(t, "CreateDeviceCode", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("refuses an unknown client as invalid_client", func(t *testing.T) {
		jsonWriter := handlersmocks.NewJSONWriter(t)
		database := newDeviceDatabase(t)
		scopeValidator := handlersmocks.NewAuthorizeValidator(t)
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ghost").
			Return(nil, nil).Once()
		jsonWriter.On("JSONError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			var detail *oauth.ErrorDetail
			return errors.As(err, &detail) && detail.Code() == "invalid_client" &&
				detail.HTTPStatus() == http.StatusUnauthorized
		})).Return().Once()

		handler := HandleDeviceAuthorizationPost(jsonWriter, database, scopeValidator, testDataCipher, deviceAuthorizationTestURL)
		handler.ServeHTTP(httptest.NewRecorder(), deviceAuthorizationRequest(t, "client_id=ghost"))
	})

	t.Run("rejects a repeated parameter", func(t *testing.T) {
		jsonWriter := handlersmocks.NewJSONWriter(t)
		database := newDeviceDatabase(t)
		scopeValidator := handlersmocks.NewAuthorizeValidator(t)
		jsonWriter.On("JSONError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			var detail *oauth.ErrorDetail
			return errors.As(err, &detail) && detail.Code() == "invalid_request"
		})).Return().Once()

		handler := HandleDeviceAuthorizationPost(jsonWriter, database, scopeValidator, testDataCipher, deviceAuthorizationTestURL)
		handler.ServeHTTP(httptest.NewRecorder(), deviceAuthorizationRequest(t, "client_id=a&client_id=b"))

		database.AssertNotCalled(t, "GetClientByClientIdentifier", mock.Anything, mock.Anything, mock.Anything)
	})
}
