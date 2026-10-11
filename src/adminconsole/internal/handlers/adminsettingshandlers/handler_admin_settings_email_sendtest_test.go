package adminsettingshandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// sendTestAPI refuses the test send with sendErr.
type sendTestAPI struct {
	sendErr error
}

func (a *sendTestAPI) SendTestEmail(context.Context, string, *api.SendTestEmailRequest) error {
	return a.sendErr
}

// The rest of the port, which the send never reaches.

func (*sendTestAPI) GetSettingsEmail(context.Context, string) (*api.SettingsEmailResponse, error) {
	panic("unexpected call to GetSettingsEmail")
}

func (*sendTestAPI) UpdateSettingsEmail(context.Context, string, *api.UpdateSettingsEmailRequest) (*api.SettingsEmailResponse, error) {
	panic("unexpected call to UpdateSettingsEmail")
}

// Every 400 the send answers is about the address typed or the email settings, which the
// administrator can act on, so the form is drawn again with the address and the API's sentence,
// whatever the code. A malformed address is refused by the auth server's email validator, whose
// localized error carries a code of its own, and naming codes sent exactly that refusal to the 500
// page (#562 decision 7).
func TestHandleEmailSendTestPost_AnyBadRequestIsDrawnOnTheForm(t *testing.T) {
	testCases := []struct {
		name    string
		code    string
		message string
	}{
		{"a malformed address", "validator.email.invalid_format", "Please enter a valid email address."},
		{"a missing address", "VALIDATION_ERROR", "Destination email is required."},
		{"email switched off", "SMTP_NOT_ENABLED", "SMTP is not enabled"},
		{"a send the mail server refused", "SEND_FAILED", "The mail server refused the message."},
		{"a code the console has never seen", "SOME_FUTURE_CODE", "Something the administrator can fix."},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_email_sendtest.html").Once()
			apiClient := &sendTestAPI{sendErr: &apiclient.APIError{
				Code: tc.code, Message: tc.message, StatusCode: http.StatusBadRequest,
			}}

			rec := httptest.NewRecorder()
			HandleEmailSendTestPost(httpHelper, nil, apiClient, consoleBaseURL).
				ServeHTTP(rec, handlertest.Request(http.MethodPost, "/admin/settings/email/send-test-email",
					handlertest.WithAccessToken(),
					handlertest.WithForm(url.Values{"destinationEmail": {"not an address"}})))

			bind := handlertest.Bind(t, httpHelper)
			assert.Equal(t, tc.message, bind["error"])
			assert.Equal(t, "not an address", bind["destinationEmail"], "the address as typed")
			assert.Empty(t, rec.Header().Get("Location"), "drawn again, not redirected")
		})
	}
}

// A status that is not the administrator's to fix stays with the classifier: a server fault is the
// 500 page, and the form is not drawn with its sentence.
func TestHandleEmailSendTestPost_AServerFaultIsNotDrawnOnTheForm(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Return().Once()
	apiClient := &sendTestAPI{sendErr: &apiclient.APIError{
		Code: "INTERNAL_SERVER_ERROR", Message: "the database is on fire", StatusCode: http.StatusInternalServerError,
	}}

	HandleEmailSendTestPost(httpHelper, nil, apiClient, consoleBaseURL).
		ServeHTTP(httptest.NewRecorder(), handlertest.Request(http.MethodPost, "/admin/settings/email/send-test-email",
			handlertest.WithAccessToken(),
			handlertest.WithForm(url.Values{"destinationEmail": {"someone@example.com"}})))

	httpHelper.AssertNotCalled(t, "RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything)
}
