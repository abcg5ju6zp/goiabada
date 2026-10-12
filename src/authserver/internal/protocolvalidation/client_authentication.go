package protocolvalidation

import (
	"crypto/subtle"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
)

const clientSecretRequiredErrorMsg = "This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed."

// One message for a superfluous secret, so the grants that refuse one cannot drift into several
// spellings of one fact (#245).
const clientSecretNotRequiredErrorMsg = "This client is configured as public, which means a client_secret is not required. To proceed, please remove the client_secret from your request."

// The one answer a wrong secret gets, whichever grant carried it. Client credentials and password
// answered a shorter text until #437, so the same failure read two ways depending on the grant.
const wrongClientSecretErrorMsg = "Client authentication failed. Please review your client_secret."

// The prelude's two refusals, which ValidateTokenRequest answers before any grant is looked at.
const (
	clientDoesNotExistErrorMsg = "Client does not exist."
	clientDisabledErrorMsg     = "Client is disabled."
)

// authenticateClient is the one client authentication at the token endpoint: every grant calls
// it at the point in its own order where it authenticates the client (#437).
//
// A confidential client must present its secret (RFC 6749 section 3.2.1); a missing or wrong one
// is invalid_client. The comparison is constant-time.
//
// A public client that presents a secret is refused invalid_request. That is symmetry, not a
// defect fix (#245 decision 11): no specification requires refusing a superfluous secret and
// nothing was exposed by ignoring one; what it buys is that one request gets one answer whichever
// grant carries it. The client credentials grant never reaches that branch, because it refuses a
// public client before authenticating.
func (val *TokenValidator) authenticateClient(client *record.Client, presentedSecret string) error {
	if client.IsPublic {
		if len(presentedSecret) > 0 {
			return oauth.NewErrorDetailWithHTTPStatus("invalid_request",
				clientSecretNotRequiredErrorMsg, http.StatusBadRequest)
		}
		return nil
	}

	if len(presentedSecret) == 0 {
		return invalidClientError(clientSecretRequiredErrorMsg)
	}

	clientSecret, err := val.dataCipher.Decrypt(client.ClientSecretEncrypted)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(clientSecret), []byte(presentedSecret)) != 1 {
		return invalidClientError(wrongClientSecretErrorMsg)
	}
	return nil
}

// AuthenticateClient is authenticateClient's exported arm for the other endpoints that
// authenticate a client outside the token endpoint: the device authorization endpoint
// (RFC 8628 section 3.1), which must accept the same credentials and refuse them with the same
// answers as the token endpoint so a device cannot be told two stories about one secret.
func AuthenticateClient(dataCipher *encryption.DataCipher, client *record.Client, presentedSecret string) error {
	val := &TokenValidator{dataCipher: dataCipher}
	return val.authenticateClient(client, presentedSecret)
}

// ClientDoesNotExistErrorMsg and ClientDisabledErrorMsg are the prelude's two refusals the
// device authorization endpoint answers as the token endpoint does.
const ClientDoesNotExistErrorMsg = clientDoesNotExistErrorMsg
const ClientDisabledErrorMsg = clientDisabledErrorMsg

// ClientSecretRequiredErrorMsg is exported for the device endpoint's identical refusal.
const ClientSecretRequiredErrorMsg = clientSecretRequiredErrorMsg

// invalidClientError is every invalid_client the token endpoint answers: an unknown client, a
// disabled one, and a missing or wrong secret. Always 401 with BasicChallenge, whether the client
// used the Authorization header or the form body (#437).
//
// RFC 6749 section 5.2 makes 401 a MAY in general and a MUST, with a challenge, only for a client
// that tried the Authorization header; RFC 9110 section 15.5.2 then requires a challenge on every
// 401. Answering every invalid_client the one way satisfies both and gives a client one shape to
// handle. What it costs: a browser app calling this endpoint with a mistyped or disabled client_id
// now gets a 401 with a Basic challenge, which some browsers answer with their login prompt in a
// same-origin setup.
func invalidClientError(description string) *oauth.ErrorDetail {
	return NewErrorDetailWithHTTPStatusAndWWWAuthenticate("invalid_client",
		description, http.StatusUnauthorized, BasicChallenge)
}
