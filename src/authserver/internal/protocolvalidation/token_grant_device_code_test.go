package protocolvalidation

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/deviceflow"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	protocolvalidationmocks "github.com/leodip/goiabada/authserver/internal/protocolvalidation/mocks"
)

func newDeviceValidator(t *testing.T) (*TokenValidator, *datamocks.Database) {
	t.Helper()
	mockDB := datamocks.NewDatabase(t)
	mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
	mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)
	return NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher), mockDB
}

func deviceClient(enabled bool) *record.Client {
	return &record.Client{Id: 7, ClientIdentifier: "tv-client", Enabled: true,
		DeviceAuthorizationGrantEnabled: enabled, IsPublic: true}
}

func deviceInput() *ValidateTokenRequestInput {
	return &ValidateTokenRequestInput{
		GrantType:  "urn:ietf:params:oauth:grant-type:device_code",
		ClientId:   "tv-client",
		DeviceCode: "DC-secret",
	}
}

func TestValidateTokenRequest_DeviceGrant_DisabledClient(t *testing.T) {
	validator, mockDB := newDeviceValidator(t)
	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "tv-client").
		Return(deviceClient(false), nil).Once()

	grant, err := validator.ValidateTokenRequest(context.Background(), &record.Settings{}, deviceInput())

	require.Error(t, err)
	assert.Nil(t, grant)
	var detail *oauth.ErrorDetail
	require.True(t, errors.As(err, &detail))
	assert.Equal(t, "unauthorized_client", detail.Code())
	assert.Equal(t, http.StatusBadRequest, detail.HTTPStatus())
}

func TestValidateTokenRequest_DeviceGrant_UnknownCode(t *testing.T) {
	validator, mockDB := newDeviceValidator(t)
	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "tv-client").
		Return(deviceClient(true), nil).Once()
	mockDB.On("GetDeviceCodeByDeviceCodeHash", mock.Anything, mock.Anything, mock.Anything).
		Return(nil, nil).Once()

	grant, err := validator.ValidateTokenRequest(context.Background(), &record.Settings{}, deviceInput())

	require.Error(t, err)
	assert.Nil(t, grant)
	var detail *oauth.ErrorDetail
	require.True(t, errors.As(err, &detail))
	assert.Equal(t, "invalid_grant", detail.Code())
}

func TestValidateTokenRequest_DeviceGrant_WrongClient(t *testing.T) {
	validator, mockDB := newDeviceValidator(t)
	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "tv-client").
		Return(deviceClient(true), nil).Once()
	mockDB.On("GetDeviceCodeByDeviceCodeHash", mock.Anything, mock.Anything, mock.Anything).
		Return(&record.DeviceCode{Id: 3, ClientId: 99}, nil).Once()

	_, err := validator.ValidateTokenRequest(context.Background(), &record.Settings{}, deviceInput())

	var detail *oauth.ErrorDetail
	require.ErrorAs(t, err, &detail)
	assert.Equal(t, "invalid_grant", detail.Code())
}

func TestValidateTokenRequest_DeviceGrant_PendingPolls(t *testing.T) {
	now := time.Now().UTC()

	t.Run("first poll answers authorization_pending and records the poll", func(t *testing.T) {
		validator, mockDB := newDeviceValidator(t)
		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "tv-client").
			Return(deviceClient(true), nil).Once()
		row := &record.DeviceCode{Id: 3, ClientId: 7, Status: string(deviceflow.StatusPending),
			ExpiresAt: now.Add(time.Minute), IntervalSeconds: deviceflow.IntervalSeconds}
		mockDB.On("GetDeviceCodeByDeviceCodeHash", mock.Anything, mock.Anything, mock.Anything).
			Return(row, nil).Once()
		mockDB.On("RecordDeviceCodePoll", mock.Anything, mock.Anything, int64(3),
			mock.Anything, deviceflow.IntervalSeconds).Return(nil).Once()

		_, err := validator.ValidateTokenRequest(context.Background(), &record.Settings{}, deviceInput())

		var pollErr *DevicePollError
		require.ErrorAs(t, err, &pollErr)
		assert.Equal(t, "authorization_pending", pollErr.Code)
		assert.Equal(t, deviceflow.IntervalSeconds, pollErr.IntervalSeconds)
	})

	t.Run("a poll inside the interval answers slow_down and raises it", func(t *testing.T) {
		validator, mockDB := newDeviceValidator(t)
		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "tv-client").
			Return(deviceClient(true), nil).Once()
		row := &record.DeviceCode{Id: 4, ClientId: 7, Status: string(deviceflow.StatusPending),
			ExpiresAt: now.Add(time.Minute), IntervalSeconds: deviceflow.IntervalSeconds,
			LastPolledAt: sql.NullTime{Time: now.Add(-time.Second), Valid: true}}
		mockDB.On("GetDeviceCodeByDeviceCodeHash", mock.Anything, mock.Anything, mock.Anything).
			Return(row, nil).Once()
		mockDB.On("RecordDeviceCodePoll", mock.Anything, mock.Anything, int64(4),
			mock.Anything, deviceflow.IntervalSeconds+deviceflow.SlowDownIncrementSeconds).Return(nil).Once()

		_, err := validator.ValidateTokenRequest(context.Background(), &record.Settings{}, deviceInput())

		var pollErr *DevicePollError
		require.ErrorAs(t, err, &pollErr)
		assert.Equal(t, "slow_down", pollErr.Code)
		assert.Equal(t, deviceflow.IntervalSeconds+deviceflow.SlowDownIncrementSeconds, pollErr.IntervalSeconds)
	})
}

func TestValidateTokenRequest_DeviceGrant_Expired(t *testing.T) {
	validator, mockDB := newDeviceValidator(t)
	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "tv-client").
		Return(deviceClient(true), nil).Once()
	row := &record.DeviceCode{Id: 5, ClientId: 7, Status: string(deviceflow.StatusPending),
		ExpiresAt: time.Now().Add(-time.Second)}
	mockDB.On("GetDeviceCodeByDeviceCodeHash", mock.Anything, mock.Anything, mock.Anything).
		Return(row, nil).Once()

	_, err := validator.ValidateTokenRequest(context.Background(), &record.Settings{}, deviceInput())

	var pollErr *DevicePollError
	require.ErrorAs(t, err, &pollErr)
	assert.Equal(t, "expired_token", pollErr.Code)
}

func TestValidateTokenRequest_DeviceGrant_DenialIsConsumedOnce(t *testing.T) {
	t.Run("first poll consumes and answers access_denied", func(t *testing.T) {
		validator, mockDB := newDeviceValidator(t)
		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "tv-client").
			Return(deviceClient(true), nil).Once()
		row := &record.DeviceCode{Id: 6, ClientId: 7, Status: string(deviceflow.StatusDenied),
			ExpiresAt: time.Now().Add(time.Minute), Consumed: false}
		mockDB.On("GetDeviceCodeByDeviceCodeHash", mock.Anything, mock.Anything, mock.Anything).
			Return(row, nil).Once()
		mockDB.On("MarkDeviceCodeConsumed", mock.Anything, mock.Anything, int64(6),
			string(deviceflow.StatusDenied)).Return(true, nil).Once()

		_, err := validator.ValidateTokenRequest(context.Background(), &record.Settings{}, deviceInput())

		var pollErr *DevicePollError
		require.ErrorAs(t, err, &pollErr)
		assert.Equal(t, "access_denied", pollErr.Code)
	})

	t.Run("second poll is the generic invalid_grant, not access_denied", func(t *testing.T) {
		validator, mockDB := newDeviceValidator(t)
		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "tv-client").
			Return(deviceClient(true), nil).Once()
		row := &record.DeviceCode{Id: 6, ClientId: 7, Status: string(deviceflow.StatusDenied),
			ExpiresAt: time.Now().Add(time.Minute), Consumed: true}
		mockDB.On("GetDeviceCodeByDeviceCodeHash", mock.Anything, mock.Anything, mock.Anything).
			Return(row, nil).Once()

		_, err := validator.ValidateTokenRequest(context.Background(), &record.Settings{}, deviceInput())

		var pollErr *DevicePollError
		require.False(t, errors.As(err, &pollErr), "a consumed denial is no longer a poll answer")
		var detail *oauth.ErrorDetail
		require.ErrorAs(t, err, &detail)
		assert.Equal(t, "invalid_grant", detail.Code())
	})
}

func TestValidateTokenRequest_DeviceGrant_Approved(t *testing.T) {
	now := time.Now().UTC()
	approvedRow := func() *record.DeviceCode {
		return &record.DeviceCode{Id: 8, ClientId: 7, Status: string(deviceflow.StatusApproved),
			ExpiresAt: now.Add(time.Minute), Consumed: false, ConsentedScope: "openid",
			UserId: 11, AuthStateGeneration: 3}
	}

	t.Run("approved and unconsumed returns the grant, leaving the claim to the issuer", func(t *testing.T) {
		validator, mockDB := newDeviceValidator(t)
		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "tv-client").
			Return(deviceClient(true), nil).Once()
		mockDB.On("GetDeviceCodeByDeviceCodeHash", mock.Anything, mock.Anything, mock.Anything).
			Return(approvedRow(), nil).Once()
		mockDB.On("DeviceCodeLoadUser", mock.Anything, mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) {
				dc := args.Get(2).(*record.DeviceCode)
				dc.User = record.User{Id: 11, Enabled: true, AuthStateGeneration: 3}
			}).Return(nil).Once()
		mockDB.On("DeviceCodeLoadClient", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

		grant, err := validator.ValidateTokenRequest(context.Background(), &record.Settings{}, deviceInput())
		require.NoError(t, err)
		require.NotNil(t, grant)
		assert.Equal(t, oidc.GrantTypeDeviceCode, grant.GrantType())
		deviceGrant, ok := grant.(*DeviceCodeGrant)
		require.True(t, ok)
		assert.Equal(t, int64(8), deviceGrant.DeviceCode.Id)
	})

	t.Run("a disabled user is refused before the grant returns", func(t *testing.T) {
		validator, mockDB := newDeviceValidator(t)
		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "tv-client").
			Return(deviceClient(true), nil).Once()
		mockDB.On("GetDeviceCodeByDeviceCodeHash", mock.Anything, mock.Anything, mock.Anything).
			Return(approvedRow(), nil).Once()
		mockDB.On("DeviceCodeLoadUser", mock.Anything, mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) {
				dc := args.Get(2).(*record.DeviceCode)
				dc.User = record.User{Id: 11, Enabled: false}
			}).Return(nil).Once()

		_, err := validator.ValidateTokenRequest(context.Background(), &record.Settings{}, deviceInput())
		var detail *oauth.ErrorDetail
		require.ErrorAs(t, err, &detail)
		assert.Equal(t, "invalid_grant", detail.Code())
	})

	t.Run("a stale generation is refused", func(t *testing.T) {
		validator, mockDB := newDeviceValidator(t)
		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "tv-client").
			Return(deviceClient(true), nil).Once()
		mockDB.On("GetDeviceCodeByDeviceCodeHash", mock.Anything, mock.Anything, mock.Anything).
			Return(approvedRow(), nil).Once()
		mockDB.On("DeviceCodeLoadUser", mock.Anything, mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) {
				dc := args.Get(2).(*record.DeviceCode)
				dc.User = record.User{Id: 11, Enabled: true, AuthStateGeneration: 4}
			}).Return(nil).Once()

		_, err := validator.ValidateTokenRequest(context.Background(), &record.Settings{}, deviceInput())
		var detail *oauth.ErrorDetail
		require.ErrorAs(t, err, &detail)
		assert.Equal(t, "invalid_grant", detail.Code())
	})
}
