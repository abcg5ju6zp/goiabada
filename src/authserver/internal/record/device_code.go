package record

import (
	"database/sql"
	"time"
)

// DeviceCode is one OAuth 2.0 Device Authorization Grant (RFC 8628): the pair the device
// authorization endpoint issues, what the browser confirmation binds to it, and the state the
// device polls.
//
// Only the SHA-256 digests of the two codes are stored (DeviceCode/UserCode are db:"-"), the
// shape codes and parked authorize requests already use: the device_code is a high-entropy
// secret the device presents, and the user_code is an easier-to-type secret a person enters.
//
// Status moves pending -> approved or pending -> denied once, by a compare-and-set, never back.
// Consumed marks the single terminal delivery the grant allows: the one approved poll that
// minted tokens, or the one denied poll that delivered access_denied. A second poll for either
// terminal state is answered invalid_grant, so one device_code can be spent exactly once.
type DeviceCode struct {
	Id        int64          `db:"id" fieldtag:"pk"`
	CreatedAt sql.NullTime   `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt sql.NullTime   `db:"updated_at"`
	ExpiresAt time.Time      `db:"expires_at"`
	DeviceCode string       `db:"-"`
	DeviceCodeHash string   `db:"device_code_hash"`
	UserCode string         `db:"-"`
	UserCodeHash string     `db:"user_code_hash"`
	ClientId int64          `db:"client_id"`
	Client   Client         `db:"-"`
	// Scope is the requested scope the device authorization endpoint accepted, never narrowed.
	Scope string `db:"scope"`
	// Status is deviceflow.StatusPending, StatusApproved or StatusDenied.
	Status string `db:"status"`
	// Consumed is the one-winner flag that makes the terminal answer single-use.
	Consumed bool `db:"consumed"`
	// IntervalSeconds is the poll interval this row currently demands, raised by SlowDownSeconds
	// on every slow_down answer.
	IntervalSeconds int          `db:"interval_seconds"`
	LastPolledAt    sql.NullTime `db:"last_polled_at"`

	// The approval binding, zero-valued while pending: whoever confirmed, the scope they
	// consented to, and the session, instant, level, methods and generation they confirmed with,
	// so the tokens the device receives match the approval, as an authorization code's do.
	UserId                       int64        `db:"user_id"`
	User                         User         `db:"-"`
	ConsentedScope               string       `db:"consented_scope"`
	SessionIdentifier            string       `db:"session_identifier"`
	AuthenticatedAt              sql.NullTime `db:"authenticated_at"`
	AcrLevel                     AcrLevel     `db:"acr_level"`
	AuthMethods                  string       `db:"auth_methods"`
	AuthStateGeneration          int64        `db:"auth_state_generation"`
}

// DeviceCodeApproval is what the browser confirmation binds to the device authorization it
// approves: the user, the scope that survived consent, and the session, instant, level, methods
// and generation the approval was made with. The tokens the device later receives are minted
// from exactly these.
type DeviceCodeApproval struct {
	UserId              int64
	ConsentedScope      string
	SessionIdentifier   string
	AuthenticatedAt     time.Time
	AcrLevel            AcrLevel
	AuthMethods         string
	AuthStateGeneration int64
}
