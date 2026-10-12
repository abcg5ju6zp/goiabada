// Package deviceflow is the OAuth 2.0 Device Authorization Grant, RFC 8628: the values the
// device authorization endpoint mints and the rules the device's polling follows. Persistence
// lives in commondb, the endpoints in handlers, the redemption's validation in
// protocolvalidation and its tokens in issuance; this package is the one list of what the three
// share, so the endpoint's interval and the token endpoint's slow_down answer cannot disagree.
package deviceflow

import (
	"strings"

	"github.com/leodip/goiabada/core/securerandom"
)

const (
	// Lifetime is how long a device code and its user code are valid, RFC 8628 section 3.2's
	// expires_in: 30 minutes, the section 6.1 recommendation's upper bound.
	LifetimeSeconds = 1800

	// IntervalSeconds is the RFC 8628 section 3.2 interval the response suggests: the minimum
	// time, in seconds, the device waits between two polls.
	IntervalSeconds = 5

	// SlowDownIncrementSeconds is what a slow_down answer (RFC 8628 section 3.5) adds to the
	// interval the row records, each time a poll arrives too soon.
	SlowDownIncrementSeconds = 5

	// deviceCodeLength is the device_code's length over securerandom's 66-character alphabet,
	// ~240 bits: a high-entropy secret presented only by the device it was issued to.
	deviceCodeLength = 40

	// userCodeLength is the user_code's length over UserCodeAlphabet. Eight characters from a
	// 30-character alphabet are ~39 bits: short enough to retype from a television, long enough
	// that an online guess cannot enumerate it within the lifetime.
	userCodeLength = 8

	// userCodeGroupSize groups the displayed code, as RFC 8628 section 6.1 illustrates
	// ("WDJB-MJHT"); both the entry page and the response normalize the dash away.
	userCodeGroupSize = 4
)

// Status is a device authorization's state, spelled as it is stored on device_codes.status.
type Status string

const (
	// StatusPending: issued, waiting for the user to confirm at the verification page.
	StatusPending Status = "pending"
	// StatusApproved: the user approved at the existing login and consent pages; the device has
	// not consumed the code yet.
	StatusApproved Status = "approved"
	// StatusDenied: the user refused at the consent page.
	StatusDenied Status = "denied"
)

// UserCodeAlphabet is RFC 8628 section 6.1's "apples to oranges" alphabet: upper-case letters and
// digits with the visually confusable ones removed (0/O, 1/I/L, 5/S, 8/B, 2/Z, 6/G, 9/Q), so a
// code read off a television is unambiguous in either case.
const UserCodeAlphabet = "ACDEFGHJKMNPRTUWXY347"

// NewDeviceCode returns a fresh high-entropy device_code.
func NewDeviceCode() string {
	return securerandom.String(deviceCodeLength)
}

// NewUserCode returns a fresh user_code as the USER types it: grouped, upper case, e.g.
// "WDJB-MJHT". What is stored and compared is its normalized form, so the dash is presentation.
func NewUserCode() string {
	code := securerandom.StringFromAlphabet(userCodeLength, UserCodeAlphabet)
	if len(code) <= userCodeGroupSize {
		return code
	}
	return code[:userCodeGroupSize] + "-" + code[userCodeGroupSize:]
}

// NormalizeUserCode reduces a typed or displayed user code to what is stored and looked up:
// upper case, separators and surrounding whitespace removed. It accepts lower case, spaces and
// dashes, the ways a person retypes "WDJB-MJHT".
func NormalizeUserCode(value string) string {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	var b strings.Builder
	b.Grow(len(normalized))
	for _, r := range normalized {
		switch r {
		case '-', ' ', '\t':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
