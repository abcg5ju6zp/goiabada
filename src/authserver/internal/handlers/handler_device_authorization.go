package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"net/url"
	"time"

	"github.com/leodip/goiabada/authserver/internal/deviceflow"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/oauth"
)

// DeviceAuthorizationPath is the verification endpoint's path and, with /auth/device, one of
// the two URLs the device authorization response names.
const DeviceAuthorizationPath = "/device"

// deviceAuthorizationTokenPath is the device authorization endpoint itself, RFC 8628 section 3.1.
const deviceAuthorizationTokenPath = "/auth/device"

// deviceAuthorizationParameters are the parameters the endpoint reads, so a repeated one is
// refused with the token endpoint's same shape.
var deviceAuthorizationParameters = []string{"client_id", "client_secret", "scope"}

// deviceAuthorizationDatabase is what POST /auth/device needs: the authenticating client and the
// row it issues.
type deviceAuthorizationDatabase interface {
	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*record.Client, error)
	CreateDeviceCode(ctx context.Context, tx *sql.Tx, deviceCode *record.DeviceCode) error
}

type deviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// HandleDeviceAuthorizationPost serves the device authorization endpoint, RFC 8628 section 3.1
// and 3.2: an enabled client that may use the device grant authenticates (a confidential client
// with its secret, a public client with its client_id), names an optional scope, and receives the
// high-entropy device_code, the typeable user_code, the verification URI, the lifetime and the
// suggested poll interval.
func HandleDeviceAuthorizationPost(
	jsonWriter JSONWriter,
	database deviceAuthorizationDatabase,
	scopeValidator AuthorizeValidator,
	dataCipher *encryption.DataCipher,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		if err := r.ParseForm(); err != nil {
			jsonWriter.JSONError(w, r, oauth.NewErrorDetailWithHTTPStatus("invalid_request",
				"Unable to parse the request body.", http.StatusBadRequest))
			return
		}
		if err := protocolvalidation.ValidateNoRepeatedParameters(r.PostForm, deviceAuthorizationParameters); err != nil {
			jsonWriter.JSONError(w, r, err)
			return
		}

		clientId, clientSecret, err := extractClientCredentials(r)
		if err != nil {
			jsonWriter.JSONError(w, r, err)
			return
		}
		if clientId == "" {
			jsonWriter.JSONError(w, r, protocolvalidation.NewErrorDetailWithHTTPStatusAndWWWAuthenticate("invalid_client",
				protocolvalidation.ClientDoesNotExistErrorMsg, http.StatusUnauthorized,
				protocolvalidation.BasicChallenge))
			return
		}

		client, err := database.GetClientByClientIdentifier(r.Context(), nil, clientId)
		if err != nil {
			jsonWriter.JSONError(w, r, err)
			return
		}
		if client == nil {
			jsonWriter.JSONError(w, r, protocolvalidation.NewErrorDetailWithHTTPStatusAndWWWAuthenticate("invalid_client",
				protocolvalidation.ClientDoesNotExistErrorMsg, http.StatusUnauthorized,
				protocolvalidation.BasicChallenge))
			return
		}
		if !client.Enabled {
			jsonWriter.JSONError(w, r, protocolvalidation.NewErrorDetailWithHTTPStatusAndWWWAuthenticate("invalid_client",
				protocolvalidation.ClientDisabledErrorMsg, http.StatusUnauthorized,
				protocolvalidation.BasicChallenge))
			return
		}

		if !client.DeviceAuthorizationGrantEnabled {
			jsonWriter.JSONError(w, r, oauth.NewErrorDetailWithHTTPStatus("unauthorized_client",
				DeviceCodeNotAuthorizedErrorMsg, http.StatusBadRequest))
			return
		}

		if err := protocolvalidation.AuthenticateClient(dataCipher, client, clientSecret); err != nil {
			jsonWriter.JSONError(w, r, err)
			return
		}

		// Scope is optional. An omitted one defaults to openid, the same default the password
		// grant gives; the user still narrows it to what they hold and consent to at the
		// verification page.
		scope := oidc.NormalizeScope(r.PostForm.Get("scope"))
		if scope == "" {
			scope = "openid"
		}
		if err := scopeValidator.ValidateScopes(r.Context(), scope); err != nil {
			jsonWriter.JSONError(w, r, err)
			return
		}
		if refused := protocolvalidation.RefusedAdministrativeScopes(client, scope); len(refused) > 0 {
			jsonWriter.JSONError(w, r, &protocolvalidation.AdministrativeScopeRefusedError{
				Detail: protocolvalidation.AdministrativeScopeRefusal(refused),
				Client: client,
				Scopes: refused,
			})
			return
		}

		now := time.Now().UTC()
		deviceCodeRaw := deviceflow.NewDeviceCode()
		userCodeRaw := deviceflow.NewUserCode()

		deviceCode := &record.DeviceCode{
			ExpiresAt:       now.Add(time.Duration(deviceflow.LifetimeSeconds) * time.Second),
			DeviceCodeHash:  hashutil.HashString(deviceCodeRaw),
			UserCodeHash:    hashutil.HashString(deviceflow.NormalizeUserCode(userCodeRaw)),
			ClientId:        client.Id,
			Scope:           scope,
			IntervalSeconds: deviceflow.IntervalSeconds,
		}
		if err := database.CreateDeviceCode(r.Context(), nil, deviceCode); err != nil {
			jsonWriter.JSONError(w, r, err)
			return
		}

		verificationURI := baseURL + DeviceAuthorizationPath
		response := deviceAuthorizationResponse{
			DeviceCode:              deviceCodeRaw,
			UserCode:                userCodeRaw,
			VerificationURI:         verificationURI,
			VerificationURIComplete: verificationURI + "?user_code=" + url.QueryEscape(deviceflow.NormalizeUserCode(userCodeRaw)),
			ExpiresIn:               deviceflow.LifetimeSeconds,
			Interval:                deviceflow.IntervalSeconds,
		}

		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		jsonWriter.EncodeJSON(w, r, response)
	}
}
