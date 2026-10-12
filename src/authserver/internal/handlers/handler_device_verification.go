package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/deviceflow"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hashutil"
)

// deviceVerificationDatabase is what the verification page needs: the live row the entered code
// names, its client (for the ceremony's target level), and the approval's two compare-and-sets.
type deviceVerificationDatabase interface {
	GetPendingDeviceCodeByUserCodeHash(ctx context.Context, tx *sql.Tx, userCodeHash string, now time.Time) (*record.DeviceCode, error)
	GetClientById(ctx context.Context, tx *sql.Tx, clientId int64) (*record.Client, error)
	ApproveDeviceCode(ctx context.Context, tx *sql.Tx, deviceCodeId int64, input *record.DeviceCodeApproval, now time.Time) (bool, error)
	DenyDeviceCode(ctx context.Context, tx *sql.Tx, deviceCodeId int64, now time.Time) (bool, error)
}

// deviceCodeTransitioner is the two compare-and-sets the consent handler calls from the
// ceremony; the verification page handler takes the wider port that also reads the rows.
type deviceCodeTransitioner interface {
	ApproveDeviceCode(ctx context.Context, tx *sql.Tx, deviceCodeId int64, input *record.DeviceCodeApproval, now time.Time) (bool, error)
	DenyDeviceCode(ctx context.Context, tx *sql.Tx, deviceCodeId int64, now time.Time) (bool, error)
}

// deviceUserCodeFormField is the form field the verification page reads, mirroring the protocol's
// parameter name.
const deviceUserCodeFormField = "user_code"

// deviceResultQuery is the result page's query parameter.
const deviceResultQuery = "result"

// The three outcomes the completed page renders.
const (
	deviceResultApproved = "approved"
	deviceResultDenied  = "denied"
	deviceResultExpired = "expired"
)

// HandleDeviceVerificationGet renders the page where a person enters the user code their device
// displayed. The verification_uri_complete link pre-fills it. The page is served whether or not
// the visitor is signed in: signing in, if it is needed, is the ceremony this page starts.
func HandleDeviceVerificationGet(pageRenderer PageRenderer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bind := map[string]interface{}{
			"prefilledUserCode": r.URL.Query().Get(deviceUserCodeFormField),
		}
		if err := pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/device_user_code.html", bind); err != nil {
			pageRenderer.InternalServerError(w, r, err)
		}
	}
}

// HandleDeviceVerificationPost accepts the entered user code and, when it names a live, still
// pending device authorization, starts the existing login and consent ceremony bound to that
// row: the visitor signs in (or reuses their session) and reaches the same consent page an
// authorization-code sign in uses, which approves or denies the device authorization.
func HandleDeviceVerificationPost(
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	database deviceVerificationDatabase,
	baseURL string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCode := deviceflow.NormalizeUserCode(r.PostFormValue(deviceUserCodeFormField))

		renderWithError := func() {
			bind := map[string]interface{}{
				"prefilledUserCode": r.PostFormValue(deviceUserCodeFormField),
				"invalidUserCode":   true,
			}
			if err := pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/device_user_code.html", bind); err != nil {
				pageRenderer.InternalServerError(w, r, err)
			}
		}

		if userCode == "" {
			renderWithError()
			return
		}

		now := time.Now().UTC()
		deviceCode, err := database.GetPendingDeviceCodeByUserCodeHash(r.Context(), nil,
			hashutil.HashString(userCode), now)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		if deviceCode == nil {
			// A wrong, confirmed or expired code reads the same way on this page, so the entry
			// box cannot be used to probe which codes exist.
			renderWithError()
			return
		}

		client, err := database.GetClientById(r.Context(), nil, deviceCode.ClientId)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			pageRenderer.InternalServerError(w, r, errs.New("client not found for device code"))
			return
		}

		// The ceremony that follows is the ordinary one; the device markers are what its consent
		// step reads to bind its answer to this row instead of issuing an authorization code.
		authContext := &ceremony.AuthContext{
			CeremonyId:      ceremony.NewId(),
			ClientId:        client.ClientIdentifier,
			ResponseType:    "code",
			Scope:           deviceCode.Scope,
			RequestedScope:  deviceCode.Scope,
			UserAgent:       r.UserAgent(),
			IpAddress:       middleware.ClientIP(r),
			AuthState:       ceremony.AuthStateRequiresLevel1,
			DeviceCodeId:    deviceCode.Id,
			DeviceUserCode:  userCode,
			// The device grant has no way to carry an authorization prompt, but RFC 8628 needs the
			// person to confirm THIS device, so the consent screen is always owed.
			Prompt: "consent",
		}
		authContext.SetTargetAcrLevel(client.DefaultAcrLevel)

		if err := ceremonyStore.SaveAuthContext(w, r, authContext); err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, ceremonyStepURL(baseURL, "/auth/level1", authContext), http.StatusFound)
	}
}

// HandleDeviceCompletedGet renders the page that ends the browser half of a device authorization:
// the approval confirmed, the refusal recorded, or the code that lapsed.
func HandleDeviceCompletedGet(pageRenderer PageRenderer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := r.URL.Query().Get(deviceResultQuery)
		switch result {
		case deviceResultApproved, deviceResultDenied, deviceResultExpired:
		default:
			result = deviceResultApproved
		}
		bind := map[string]interface{}{
			"deviceResult": result,
		}
		if err := pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/device_completed.html", bind); err != nil {
			pageRenderer.InternalServerError(w, r, err)
		}
	}
}

// approveDeviceConsent binds an approved consent ceremony to its device authorization, clears
// the ceremony and sends the browser to the completed page. It is the consent handler's device
// branch. The compare-and-set means a second tab, a racing denial or an expiry cannot also bind
// it; a lost approval is shown as expired.
func approveDeviceConsent(w http.ResponseWriter, r *http.Request,
	pageRenderer PageRenderer, ceremonyStore CeremonyStore, database deviceCodeTransitioner,
	auditLogger AuditLogger, authContext *ceremony.AuthContext, user *record.User,
	client *record.Client, consentedScope string, baseURL string) {

	sessionIdentifier, _ := reqctx.SessionIdentifierFrom(r.Context())
	authenticatedAt := time.Now().UTC()
	if authContext.AuthenticatedAt != nil {
		authenticatedAt = authContext.AuthenticatedAt.UTC()
	}

	approval := &record.DeviceCodeApproval{
		UserId:              user.Id,
		ConsentedScope:      consentedScope,
		SessionIdentifier:   sessionIdentifier,
		AuthenticatedAt:     authenticatedAt,
		AcrLevel:            authContext.AcrLevel,
		AuthMethods:         authContext.AuthMethods,
		AuthStateGeneration: authContext.AuthStateGeneration,
	}

	approved, err := database.ApproveDeviceCode(r.Context(), nil, authContext.DeviceCodeId, approval, time.Now().UTC())
	if err != nil {
		pageRenderer.InternalServerError(w, r, err)
		return
	}

	auditLogger.Log(r.Context(), audit.EventDeviceAuthorizationApproved, map[string]interface{}{
		"user_id":         user.Id,
		"client_id":       client.Id,
		"device_code_id":  authContext.DeviceCodeId,
		"scope":           consentedScope,
		"session_bound":   sessionIdentifier != "",
	})

	if err := ceremonyStore.ClearAuthContext(w, r); err != nil {
		pageRenderer.InternalServerError(w, r, err)
		return
	}

	result := deviceResultApproved
	if !approved {
		result = deviceResultExpired
	}
	http.Redirect(w, r, baseURL+DeviceAuthorizationPath+"/completed?"+deviceResultQuery+"="+result, http.StatusFound)
}

// denyDeviceConsent marks the device authorization denied, clears the ceremony and shows the
// completed page. A lost transition (a racing approval or expiry) is reported as expired.
func denyDeviceConsent(w http.ResponseWriter, r *http.Request,
	pageRenderer PageRenderer, ceremonyStore CeremonyStore, database deviceCodeTransitioner,
	auditLogger AuditLogger, authContext *ceremony.AuthContext, client *record.Client,
	baseURL string) {

	denied, err := database.DenyDeviceCode(r.Context(), nil, authContext.DeviceCodeId, time.Now().UTC())
	if err != nil {
		pageRenderer.InternalServerError(w, r, err)
		return
	}

	denialDetails := map[string]interface{}{
		"device_code_id": authContext.DeviceCodeId,
		"user_id":        authContext.UserId,
	}
	if client != nil {
		denialDetails["client_id"] = client.Id
	}
	auditLogger.Log(r.Context(), audit.EventDeviceAuthorizationDenied, denialDetails)

	if err := ceremonyStore.ClearAuthContext(w, r); err != nil {
		pageRenderer.InternalServerError(w, r, err)
		return
	}

	result := deviceResultDenied
	if !denied {
		result = deviceResultExpired
	}
	http.Redirect(w, r, baseURL+DeviceAuthorizationPath+"/completed?"+deviceResultQuery+"="+result, http.StatusFound)
}
