package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/deviceflow"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// CreateDeviceCode inserts one pending device authorization.
func (d *Database) CreateDeviceCode(ctx context.Context, tx *sql.Tx, deviceCode *record.DeviceCode) error {

	if deviceCode.ClientId == 0 {
		return errs.New("client id must be greater than 0")
	}
	if deviceCode.DeviceCodeHash == "" {
		return errs.New("can't create a device code with an empty device code hash")
	}
	if deviceCode.UserCodeHash == "" {
		return errs.New("can't create a device code with an empty user code hash")
	}
	if deviceCode.ExpiresAt.IsZero() {
		return errs.New("can't create a device code that never expires")
	}

	now := time.Now().UTC()

	originalCreatedAt := deviceCode.CreatedAt
	originalUpdatedAt := deviceCode.UpdatedAt
	deviceCode.CreatedAt = sql.NullTime{Time: now, Valid: true}
	deviceCode.UpdatedAt = sql.NullTime{Time: now, Valid: true}
	deviceCode.Status = string(deviceflow.StatusPending)
	deviceCode.Consumed = false

	deviceCodeStruct := sqlbuilder.NewStruct(new(record.DeviceCode)).
		For(d.Flavor)

	insertBuilder := deviceCodeStruct.WithoutTag("pk").InsertInto("device_codes", deviceCode)

	id, err := d.insertReturningId(ctx, tx, insertBuilder, "device code")
	if err != nil {
		deviceCode.CreatedAt = originalCreatedAt
		deviceCode.UpdatedAt = originalUpdatedAt
		return err
	}

	deviceCode.Id = id
	return nil
}

func (d *Database) getDeviceCodeCommon(ctx context.Context, tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	deviceCodeStruct *sqlbuilder.Struct) (*record.DeviceCode, error) {

	query, args := selectBuilder.Build()
	rows, err := d.QuerySQL(ctx, tx, query, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var deviceCode record.DeviceCode
	if rows.Next() {
		addr := deviceCodeStruct.Addr(&deviceCode)
		if err := rows.Scan(addr...); err != nil {
			return nil, errs.Wrap(err, "unable to scan device code")
		}
		return &deviceCode, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return nil, nil
}

// GetDeviceCodeById returns the row whatever its state, or nil when there is none.
func (d *Database) GetDeviceCodeById(ctx context.Context, tx *sql.Tx, deviceCodeId int64) (*record.DeviceCode, error) {

	deviceCodeStruct := sqlbuilder.NewStruct(new(record.DeviceCode)).
		For(d.Flavor)

	selectBuilder := deviceCodeStruct.SelectFrom("device_codes")
	selectBuilder.Where(selectBuilder.Equal("id", deviceCodeId))

	return d.getDeviceCodeCommon(ctx, tx, selectBuilder, deviceCodeStruct)
}

// GetDeviceCodeByDeviceCodeHash returns the device authorization a polling device presents,
// whatever its state, or nil when there is none. Expiry is decided by the caller, against the
// row's expires_at, because the answer distinguishes an expired code from an unknown one
// (expired_token vs invalid_grant).
func (d *Database) GetDeviceCodeByDeviceCodeHash(ctx context.Context, tx *sql.Tx,
	deviceCodeHash string) (*record.DeviceCode, error) {

	if deviceCodeHash == "" {
		return nil, errs.New("can't get a device code with an empty device code hash")
	}

	deviceCodeStruct := sqlbuilder.NewStruct(new(record.DeviceCode)).
		For(d.Flavor)

	selectBuilder := deviceCodeStruct.SelectFrom("device_codes")
	selectBuilder.Where(selectBuilder.Equal("device_code_hash", deviceCodeHash))

	deviceCode, err := d.getDeviceCodeCommon(ctx, tx, selectBuilder, deviceCodeStruct)
	if err != nil {
		return nil, err
	}
	// SQL Server pads for `=` under every collation; compare the fixed-width digest in Go, the
	// same term the authorize-request lookup carries.
	if deviceCode != nil && deviceCode.DeviceCodeHash != deviceCodeHash {
		return nil, nil
	}
	return deviceCode, nil
}

// GetPendingDeviceCodeByUserCodeHash returns the live, still-pending authorization whose user
// code a person entered, or nil. `now` is an active-expiry AND state predicate: an expired or
// already-answered code reads as absent, so the verification page cannot confirm one twice or
// extend one that has lapsed, whether or not the sweep has deleted it.
func (d *Database) GetPendingDeviceCodeByUserCodeHash(ctx context.Context, tx *sql.Tx,
	userCodeHash string, now time.Time) (*record.DeviceCode, error) {

	if userCodeHash == "" {
		return nil, errs.New("can't get a device code with an empty user code hash")
	}

	deviceCodeStruct := sqlbuilder.NewStruct(new(record.DeviceCode)).
		For(d.Flavor)

	selectBuilder := deviceCodeStruct.SelectFrom("device_codes")
	selectBuilder.Where(
		selectBuilder.Equal("user_code_hash", userCodeHash),
		selectBuilder.Equal("status", string(deviceflow.StatusPending)),
		selectBuilder.GreaterThan("expires_at", now),
	)

	deviceCode, err := d.getDeviceCodeCommon(ctx, tx, selectBuilder, deviceCodeStruct)
	if err != nil {
		return nil, err
	}
	if deviceCode != nil && deviceCode.UserCodeHash != userCodeHash {
		return nil, nil
	}
	return deviceCode, nil
}

// ApproveDeviceCode atomically moves one authorization from pending to approved, binding the
// approval, and reports whether THIS call did it. The compare-and-set's terms are id + status
// pending + not past expiry: the single approval the row allows, refused to a second tab, a
// denial that landed first, or the expiry sweep's window. The row lock the UPDATE takes is also
// what orders a confirmation against a poll: the poll either reads pending or approved, never a
// half-bound row.
func (d *Database) ApproveDeviceCode(ctx context.Context, tx *sql.Tx, deviceCodeId int64,
	input *record.DeviceCodeApproval, now time.Time) (bool, error) {

	if deviceCodeId == 0 {
		return false, errs.New("can't approve a device code with id 0")
	}
	if input == nil || input.UserId == 0 {
		return false, errs.New("can't approve a device code without the approving user")
	}

	return d.transitionDeviceCode(ctx, tx, deviceCodeId, deviceflow.StatusApproved, now, func(ub *sqlbuilder.UpdateBuilder) {
		ub.Set(
			ub.Assign("user_id", input.UserId),
			ub.Assign("consented_scope", input.ConsentedScope),
			ub.Assign("session_identifier", input.SessionIdentifier),
			ub.Assign("authenticated_at", input.AuthenticatedAt.UTC()),
			ub.Assign("acr_level", string(input.AcrLevel)),
			ub.Assign("auth_methods", input.AuthMethods),
			ub.Assign("auth_state_generation", input.AuthStateGeneration),
		)
	})
}

// DenyDeviceCode atomically moves one authorization from pending to denied, the consent page's
// cancel. Its false answer is the same set ApproveDeviceCode documents: another tab, an approval
// that landed first, or expiry.
func (d *Database) DenyDeviceCode(ctx context.Context, tx *sql.Tx, deviceCodeId int64, now time.Time) (bool, error) {

	if deviceCodeId == 0 {
		return false, errs.New("can't deny a device code with id 0")
	}

	return d.transitionDeviceCode(ctx, tx, deviceCodeId, deviceflow.StatusDenied, now, nil)
}

// transitionDeviceCode is the shared pending -> terminal compare-and-set. extra assigns the
// approval binding columns on the approved transition; denied carries none.
func (d *Database) transitionDeviceCode(ctx context.Context, tx *sql.Tx, deviceCodeId int64,
	toStatus deviceflow.Status, now time.Time, extra func(ub *sqlbuilder.UpdateBuilder)) (bool, error) {

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("device_codes")
	ub.Set(
		ub.Assign("status", string(toStatus)),
		ub.Assign("updated_at", now),
	)
	if extra != nil {
		extra(ub)
	}
	ub.Where(
		ub.Equal("id", deviceCodeId),
		ub.Equal("status", string(deviceflow.StatusPending)),
		ub.GreaterThan("expires_at", now),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSQL(ctx, tx, query, args...)
	if err != nil {
		return false, errs.Wrap(err, "unable to transition device code")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errs.Wrap(err, "unable to get rows affected when transitioning device code")
	}

	return rowsAffected == 1, nil
}

// MarkDeviceCodeConsumed claims one terminal authorization: the one approved poll allowed to
// mint tokens, or the one denied poll allowed to deliver access_denied. It transitions consumed
// false -> true only while the row's status is the one the caller expects, so the winner is
// unique across two concurrent polls and across an approval and a denial that raced. A false
// answer means the code was consumed, changed state or never existed, and the caller refuses
// invalid_grant.
func (d *Database) MarkDeviceCodeConsumed(ctx context.Context, tx *sql.Tx, deviceCodeId int64,
	status string) (bool, error) {

	if deviceCodeId == 0 {
		return false, errs.New("can't consume a device code with id 0")
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("device_codes")
	ub.Set(
		ub.Assign("consumed", true),
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(
		ub.Equal("id", deviceCodeId),
		ub.Equal("status", status),
		ub.Equal("consumed", false),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSQL(ctx, tx, query, args...)
	if err != nil {
		return false, errs.Wrap(err, "unable to mark device code consumed")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errs.Wrap(err, "unable to get rows affected when marking device code consumed")
	}

	return rowsAffected == 1, nil
}

// RecordDeviceCodePoll records one pending poll: when it happened and the interval the next poll
// must respect. It touches a pending row alone, so a terminal authorization is never written and
// the slow_down bookkeeping cannot race an approval: the row lock serializes the two. The new
// interval is decided by the caller (the current one, or one raised on slow_down).
func (d *Database) RecordDeviceCodePoll(ctx context.Context, tx *sql.Tx, deviceCodeId int64,
	polledAt time.Time, intervalSeconds int) error {

	if deviceCodeId == 0 {
		return errs.New("can't record a poll for a device code with id 0")
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("device_codes")
	ub.Set(
		ub.Assign("last_polled_at", polledAt),
		ub.Assign("interval_seconds", intervalSeconds),
		ub.Assign("updated_at", polledAt),
	)
	ub.Where(
		ub.Equal("id", deviceCodeId),
		ub.Equal("status", string(deviceflow.StatusPending)),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	if _, err := d.ExecSQL(ctx, tx, query, args...); err != nil {
		return errs.Wrap(err, "unable to record device code poll")
	}

	return nil
}

// DeviceCodeLoadClient loads the authorizing client.
func (d *Database) DeviceCodeLoadClient(ctx context.Context, tx *sql.Tx, deviceCode *record.DeviceCode) error {

	if deviceCode == nil {
		return nil
	}

	client, err := d.GetClientById(ctx, tx, deviceCode.ClientId)
	if err != nil {
		return errs.Wrap(err, "unable to load client")
	}
	if client != nil {
		deviceCode.Client = *client
	}
	return nil
}

// DeviceCodeLoadUser loads the approving user.
func (d *Database) DeviceCodeLoadUser(ctx context.Context, tx *sql.Tx, deviceCode *record.DeviceCode) error {

	if deviceCode == nil || deviceCode.UserId == 0 {
		return nil
	}

	user, err := d.GetUserById(ctx, tx, deviceCode.UserId)
	if err != nil {
		return errs.Wrap(err, "unable to load user")
	}
	if user != nil {
		deviceCode.User = *user
	}
	return nil
}

// DeleteExpiredDeviceCodes reaps rows past expires_at. The predicate is expiry alone, so an
// authorization still within its lifetime is never deleted whether it is pending, approved and
// waiting for its one poll, or consumed: the sweep cannot repeat an issuance by removing the row
// a successful poll then fails to find, nor remove the replay marker a consumed row is.
func (d *Database) DeleteExpiredDeviceCodes(ctx context.Context, tx *sql.Tx, now time.Time) error {

	deleteBuilder := d.Flavor.NewDeleteBuilder()
	deleteBuilder.DeleteFrom("device_codes")
	deleteBuilder.Where(deleteBuilder.LessThan("expires_at", now))

	query, args := deleteBuilder.BuildWithFlavor(d.Flavor)
	if _, err := d.ExecSQL(ctx, tx, query, args...); err != nil {
		return errs.Wrap(err, "unable to delete expired device codes")
	}

	return nil
}
