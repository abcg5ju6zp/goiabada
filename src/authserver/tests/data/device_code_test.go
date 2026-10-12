package datatests

import (
	"context"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/deviceflow"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestDeviceCodeWithExpiry(t *testing.T, clientId int64, expiresAt time.Time) *record.DeviceCode {
	t.Helper()
	// The columns hold the 64-character SHA-256 hex hashes production stores, on every engine;
	// a long readable label overflows varchar(64) on postgres and SQL Server.
	hashInput := t.Name() + "-" + expiresAt.Format("150405.000000000")
	deviceCode := &record.DeviceCode{
		ExpiresAt:       expiresAt,
		DeviceCodeHash:  hashutil.HashString("device-" + hashInput),
		UserCodeHash:    hashutil.HashString("user-" + hashInput),
		ClientId:        clientId,
		Scope:           "openid profile",
		Status:          string(deviceflow.StatusPending),
		IntervalSeconds: deviceflow.IntervalSeconds,
	}
	require.NoError(t, database.CreateDeviceCode(context.Background(), nil, deviceCode))
	return deviceCode
}

func createTestDeviceCode(t *testing.T, clientId int64) *record.DeviceCode {
	t.Helper()
	return createTestDeviceCodeWithExpiry(t, clientId, time.Now().UTC().Add(30*time.Minute))
}

func TestCreateAndGetDeviceCode(t *testing.T) {
	client := createTestClient(t)
	deviceCode := createTestDeviceCode(t, client.Id)

	assert.NotZero(t, deviceCode.Id)
	assert.True(t, deviceCode.CreatedAt.Valid)
	assert.Equal(t, string(deviceflow.StatusPending), deviceCode.Status)

	byId, err := database.GetDeviceCodeById(context.Background(), nil, deviceCode.Id)
	require.NoError(t, err)
	require.NotNil(t, byId)
	assert.Equal(t, client.Id, byId.ClientId)
	assert.Equal(t, "openid profile", byId.Scope)

	byHash, err := database.GetDeviceCodeByDeviceCodeHash(context.Background(), nil, deviceCode.DeviceCodeHash)
	require.NoError(t, err)
	require.NotNil(t, byHash)
	assert.Equal(t, deviceCode.Id, byHash.Id)

	missing, err := database.GetDeviceCodeByDeviceCodeHash(context.Background(), nil, "does-not-exist")
	require.NoError(t, err)
	assert.Nil(t, missing)
}

func TestGetPendingDeviceCodeByUserCodeHash(t *testing.T) {
	client := createTestClient(t)
	now := time.Now().UTC()

	t.Run("a live pending row is found", func(t *testing.T) {
		dc := createTestDeviceCode(t, client.Id)
		got, err := database.GetPendingDeviceCodeByUserCodeHash(context.Background(), nil, dc.UserCodeHash, now)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, dc.Id, got.Id)
	})

	t.Run("an expired row reads as absent", func(t *testing.T) {
		dc := createTestDeviceCodeWithExpiry(t, client.Id, now.Add(-time.Minute))
		got, err := database.GetPendingDeviceCodeByUserCodeHash(context.Background(), nil, dc.UserCodeHash, now)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("a confirmed row reads as absent but stays approved", func(t *testing.T) {
		user := createTestUser(t)
		dc := createTestDeviceCode(t, client.Id)
		approval := &record.DeviceCodeApproval{
			UserId:              user.Id,
			ConsentedScope:      "openid",
			SessionIdentifier:   "session-1",
			AuthenticatedAt:     now.Add(-time.Minute),
			AcrLevel:            record.AcrLevel2Optional,
			AuthMethods:         "pwd",
			AuthStateGeneration: 1,
		}
		approved, err := database.ApproveDeviceCode(context.Background(), nil, dc.Id, approval, now)
		require.NoError(t, err)
		assert.True(t, approved)

		got, err := database.GetPendingDeviceCodeByUserCodeHash(context.Background(), nil, dc.UserCodeHash, now)
		require.NoError(t, err)
		assert.Nil(t, got, "the entry page admits only pending rows")

		loaded, err := database.GetDeviceCodeById(context.Background(), nil, dc.Id)
		require.NoError(t, err)
		assert.Equal(t, string(deviceflow.StatusApproved), loaded.Status)
		assert.Equal(t, user.Id, loaded.UserId.Int64)
		assert.Equal(t, "openid", loaded.ConsentedScope)
		assert.Equal(t, "session-1", loaded.SessionIdentifier)
	})
}

func TestDeviceCodeApproveIsOneWinner(t *testing.T) {
	client := createTestClient(t)
	user := createTestUser(t)
	dc := createTestDeviceCode(t, client.Id)
	now := time.Now().UTC()

	approval := &record.DeviceCodeApproval{UserId: user.Id, ConsentedScope: "openid",
		AuthenticatedAt: now, AuthStateGeneration: 1}

	first, err := database.ApproveDeviceCode(context.Background(), nil, dc.Id, approval, now)
	require.NoError(t, err)
	assert.True(t, first)

	// A racing denial cannot move an approved row, and no second approval can bind it.
	denied, err := database.DenyDeviceCode(context.Background(), nil, dc.Id, now)
	require.NoError(t, err)
	assert.False(t, denied)
	second, err := database.ApproveDeviceCode(context.Background(), nil, dc.Id, approval, now)
	require.NoError(t, err)
	assert.False(t, second)

	loaded, err := database.GetDeviceCodeById(context.Background(), nil, dc.Id)
	require.NoError(t, err)
	assert.Equal(t, string(deviceflow.StatusApproved), loaded.Status)
}

func TestDeviceCodeConsumedIsOneWinner(t *testing.T) {
	client := createTestClient(t)
	dc := createTestDeviceCode(t, client.Id)

	denied, err := database.DenyDeviceCode(context.Background(), nil, dc.Id, time.Now().UTC())
	require.NoError(t, err)
	require.True(t, denied)

	first, err := database.MarkDeviceCodeConsumed(context.Background(), nil, dc.Id, string(deviceflow.StatusDenied))
	require.NoError(t, err)
	assert.True(t, first)
	second, err := database.MarkDeviceCodeConsumed(context.Background(), nil, dc.Id, string(deviceflow.StatusDenied))
	require.NoError(t, err)
	assert.False(t, second, "the terminal answer is delivered once")

	// An approval transition also loses once consumed.
	approved, err := database.ApproveDeviceCode(context.Background(), nil, dc.Id,
		&record.DeviceCodeApproval{UserId: 1, AuthenticatedAt: time.Now().UTC()}, time.Now().UTC())
	require.NoError(t, err)
	assert.False(t, approved)
}

func TestDeviceCodePoll(t *testing.T) {
	client := createTestClient(t)
	dc := createTestDeviceCode(t, client.Id)
	now := time.Now().UTC()

	require.NoError(t, database.RecordDeviceCodePoll(context.Background(), nil, dc.Id, now, 8))
	loaded, err := database.GetDeviceCodeById(context.Background(), nil, dc.Id)
	require.NoError(t, err)
	assert.True(t, loaded.LastPolledAt.Valid)
	assert.Equal(t, 8, loaded.IntervalSeconds)
}

func TestDeleteExpiredDeviceCodes(t *testing.T) {
	client := createTestClient(t)
	now := time.Now().UTC()
	alive := createTestDeviceCode(t, client.Id)
	dead := createTestDeviceCodeWithExpiry(t, client.Id, now.Add(-time.Minute))

	require.NoError(t, database.DeleteExpiredDeviceCodes(context.Background(), nil, now))

	gotDead, err := database.GetDeviceCodeById(context.Background(), nil, dead.Id)
	require.NoError(t, err)
	assert.Nil(t, gotDead, "an expired row is reaped")
	gotAlive, err := database.GetDeviceCodeById(context.Background(), nil, alive.Id)
	require.NoError(t, err)
	assert.NotNil(t, gotAlive, "a row inside its lifetime is never reaped")
}
