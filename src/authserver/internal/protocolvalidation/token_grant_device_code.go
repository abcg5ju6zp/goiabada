package protocolvalidation

import (
	"context"
	"net/http"
	"time"

	"github.com/leodip/goiabada/authserver/internal/deviceflow"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/oauth"
)

// DeviceCodeGrant is a validated, approved and still unconsumed device authorization: the row
// the device presented, loaded with its client and user. The claim that consumes it is the
// issuer's, the one-winner mark that makes the redemption single-use, as it is for an
// authorization code.
type DeviceCodeGrant struct {
	DeviceCode *record.DeviceCode
}

func (*DeviceCodeGrant) GrantType() oidc.GrantType { return oidc.GrantTypeDeviceCode }

// DevicePollError is an RFC 8628 section 3.5 answer that is not an ordinary RFC 6749 refusal:
// authorization_pending, slow_down, access_denied and expired_token. IntervalSeconds is carried
// on the JSON response when the server is telling the device to wait (pending, slow_down).
//
// It is its own type rather than an *oauth.ErrorDetail because of the interval field, and it is
// the error the token handler's refusal writer recognises to render the section 3.5 body.
type DevicePollError struct {
	Code            string
	Description     string
	IntervalSeconds int
}

func (e *DevicePollError) Error() string {
	return "code: " + e.Code + "; description: " + e.Description
}

// ErrorCode is the wire code, so tokenmetrics counts the refusal under the RFC 8628 code rather
// than server_error.
func (e *DevicePollError) ErrorCode() string { return e.Code }

// The four RFC 8628 section 3.5 error codes, as the client receives and distinguishes them.
const (
	deviceErrAuthorizationPending = "authorization_pending"
	deviceErrSlowDown             = "slow_down"
	deviceErrAccessDenied         = "access_denied"
	deviceErrExpiredToken         = "expired_token"
)

func devicePollError(code, description string, intervalSeconds int) *DevicePollError {
	return &DevicePollError{Code: code, Description: description, IntervalSeconds: intervalSeconds}
}

// validateDeviceCodeGrant validates one poll of the device_code grant (RFC 8628 section 3.4)
// for a client ValidateTokenRequest has already found and found enabled.
//
// Unlike the other grants it owns two writes: the last-poll bookkeeping a pending answer needs
// and the one-winner consumption of a denial. Both are state of THIS grant rather than side
// effects of its answer, and splitting them into the responder would put the slow_down interval
// arithmetic on both sides of the validator/handler seam; the row's compare-and-sets keep the
// writes safe against the concurrent browser confirmation.
func (val *TokenValidator) validateDeviceCodeGrant(ctx context.Context, client *record.Client,
	input *ValidateTokenRequestInput) (*DeviceCodeGrant, error) {

	if !client.DeviceAuthorizationGrantEnabled {
		return nil, oauth.NewErrorDetailWithHTTPStatus("unauthorized_client",
			"The client associated with the provided client_id does not support the device authorization grant.",
			http.StatusBadRequest)
	}

	if len(input.DeviceCode) == 0 {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_request",
			"Missing required device_code parameter.", http.StatusBadRequest)
	}

	// RFC 8628 section 3.4: a confidential client authenticates exactly as at the token endpoint
	// for the other grants; a public client sends its client_id in the body.
	if err := val.authenticateClient(client, input.ClientSecret); err != nil {
		return nil, err
	}

	deviceCodeHash := hashutil.HashString(input.DeviceCode)
	deviceCode, err := val.database.GetDeviceCodeByDeviceCodeHash(ctx, nil, deviceCodeHash)
	if err != nil {
		return nil, err
	}
	if deviceCode == nil {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			"The device code is invalid.", http.StatusBadRequest)
	}

	// The code is bound to the client it was issued to; another client presenting it gets the
	// generic answer, as it does for a foreign authorization code.
	if deviceCode.ClientId != client.Id {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			"The device code is invalid.", http.StatusBadRequest)
	}

	now := time.Now().UTC()

	// A consumed code is spent whatever the clock says: the one successful redemption or the one
	// denial delivery already happened, so a later poll can never revive it. Checked ahead of
	// expiry so a replay is invalid_grant even past the row's lifetime.
	if deviceCode.Consumed {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			"The device code has already been consumed.", http.StatusBadRequest)
	}

	// Expiry is next and applies to every still-unconsumed state: a pending code nobody
	// confirmed, and an approved code the device never polled within the lifetime, both stop
	// being redeemable. It is a distinct code, RFC 8628 section 3.5, telling the device to stop
	// polling rather than to retry.
	if now.After(deviceCode.ExpiresAt) {
		return nil, devicePollError(deviceErrExpiredToken,
			"The device code has expired. The user did not confirm it in time.", 0)
	}

	switch deviceflow.Status(deviceCode.Status) {
	case deviceflow.StatusApproved:
		return val.validateApprovedDeviceCode(ctx, deviceCode)
	case deviceflow.StatusDenied:
		// The first poll after the refusal consumes the denied state and is told access_denied;
		// the compare-and-set makes that delivery single-use, so a second poll (or a concurrent
		// duplicate) gets invalid_grant.
		claimed, claimErr := val.database.MarkDeviceCodeConsumed(ctx, nil, deviceCode.Id, string(deviceflow.StatusDenied))
		if claimErr != nil {
			return nil, claimErr
		}
		if !claimed {
			return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
				"The device code has already been consumed.", http.StatusBadRequest)
		}
		return nil, devicePollError(deviceErrAccessDenied,
			"The user denied the authorization request.", 0)
	default:
		// StatusPending (and any value the enum does not know, read as "not yet approved").
		return val.validatePendingDeviceCodePoll(ctx, deviceCode, now)
	}
}

// validatePendingDeviceCodePoll answers one poll for an unconfirmed authorization: slow_down
// for a poll that arrived inside the interval the previous answer demanded, and
// authorization_pending otherwise. Both answers record the poll, so the interval decision is
// made against the actual time of this request.
func (val *TokenValidator) validatePendingDeviceCodePoll(ctx context.Context,
	deviceCode *record.DeviceCode, now time.Time) (*DeviceCodeGrant, error) {

	interval := deviceCode.IntervalSeconds
	if interval <= 0 {
		interval = deviceflow.IntervalSeconds
	}

	slowDown := false
	if deviceCode.LastPolledAt.Valid {
		elapsed := now.Sub(deviceCode.LastPolledAt.Time.UTC())
		if elapsed >= 0 && elapsed < time.Duration(interval)*time.Second {
			slowDown = true
			interval += deviceflow.SlowDownIncrementSeconds
		}
	}

	if err := val.database.RecordDeviceCodePoll(ctx, nil, deviceCode.Id, now, interval); err != nil {
		return nil, err
	}

	if slowDown {
		return nil, devicePollError(deviceErrSlowDown,
			"Polling too frequently. The requested interval has been increased.", interval)
	}
	return nil, devicePollError(deviceErrAuthorizationPending,
		"The authorization request is still pending as the user has not yet completed the user interaction steps.", interval)
}

// validateApprovedDeviceCode runs the checks an approved code shares with an authorization code
// at redemption, so a change in the user's standing between approval and exchange is honored:
// the user is still enabled and the generation the approval captured has not been superseded by
// a credential change.
func (val *TokenValidator) validateApprovedDeviceCode(ctx context.Context,
	deviceCode *record.DeviceCode) (*DeviceCodeGrant, error) {

	err := val.database.DeviceCodeLoadUser(ctx, nil, deviceCode)
	if err != nil {
		return nil, err
	}
	if deviceCode.User.Id == 0 {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			"The device code is invalid.", http.StatusBadRequest)
	}

	if !deviceCode.User.Enabled {
		return nil, userDisabled("The device code is invalid.", deviceCode.User.Id)
	}

	if deviceCode.AuthStateGeneration != deviceCode.User.AuthStateGeneration {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			"The device code is invalid.", http.StatusBadRequest)
	}

	err = val.database.DeviceCodeLoadClient(ctx, nil, deviceCode)
	if err != nil {
		return nil, err
	}

	return &DeviceCodeGrant{DeviceCode: deviceCode}, nil
}
