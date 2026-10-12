package handlers

import (
	"errors"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
)

// DeviceCodeNotAuthorizedErrorMsg is the refusal a client without the device authorization grant
// gets: at the device_code redemption, at the device authorization endpoint, and when a refresh
// token a device grant issued is redeemed after the switch was turned off. One wording in all
// three places, as the other grants' refusals are.
const DeviceCodeNotAuthorizedErrorMsg = "The client associated with the provided client_id does not support the device authorization grant. " +
	"Enable 'OAuth2 device authorization grant' in the client's settings in the admin console."

// respondDeviceCode redeems a validated, approved device authorization and answers with its
// token set. The poll refusals never reach here: the validator returned them as
// DevicePollError and the handler's refusal wrote their RFC 8628 body.
func (tr tokenResponder) respondDeviceCode(w http.ResponseWriter, r *http.Request,
	settings *record.Settings, grant *protocolvalidation.DeviceCodeGrant) {

	tokenResponse, err := tr.issuer.IssueDeviceCodeGrant(r.Context(), settings, grant.DeviceCode)
	if err != nil {
		// A lost claim (a concurrent poll that won the one consumption) is the grant's generic
		// invalid_grant, never a 500: nothing went wrong server-side, the code was simply spent.
		if errors.Is(err, issuance.ErrDeviceCodeNotClaimed) {
			err = oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
				"The device code has already been consumed.", http.StatusBadRequest)
		}
		tr.refuse(w, r, oidc.GrantTypeDeviceCode, err)
		return
	}

	tr.auditLogger.Log(r.Context(), audit.EventTokenIssuedDeviceCodeResponse, map[string]interface{}{
		"user_id":        grant.DeviceCode.UserId,
		"client_id":      grant.DeviceCode.ClientId,
		"device_code_id": grant.DeviceCode.Id,
		"scope":          tokenResponse.Scope,
	})

	tr.writeTokenResponse(w, r, oidc.GrantTypeDeviceCode, tokenResponse)
}
