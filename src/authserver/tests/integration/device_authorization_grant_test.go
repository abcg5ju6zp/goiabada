package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/deviceflow"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The OAuth 2.0 Device Authorization Grant (RFC 8628) end to end: a device with no browser asks
// for a device_code and a typeable user_code, a person confirms the authorization through the
// ordinary login and consent ceremony in another browser, and the device polls the token endpoint
// until it receives the tokens bound to that approval. The poll answers, the one-time
// consumption, the expiry and the client switch are observed on the wire.

// createDeviceFlowClient creates an enabled client whose only OAuth 2 flow is the device
// authorization grant. The authorization code flow is deliberately off so no test here can pass
// by leaning on it.
func createDeviceFlowClient(t *testing.T, clientSecret string, isPublic bool) *record.Client {
	t.Helper()
	client := &record.Client{
		ClientIdentifier:                "device-client-" + fake.LetterN(8),
		Enabled:                         true,
		IsPublic:                        isPublic,
		AuthorizationCodeEnabled:        false,
		DeviceAuthorizationGrantEnabled: true,
		DefaultAcrLevel:                 record.AcrLevel1,
	}

	if !isPublic && clientSecret != "" {
		encrypted, err := dataCipher.Encrypt(clientSecret)
		require.NoError(t, err)
		client.ClientSecretEncrypted = encrypted
	}

	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	return client
}

func createDeviceUser(t *testing.T) (*record.User, string) {
	t.Helper()
	password := fake.Password(12)
	passwordHashed, err := passwordhash.Hash(password)
	require.NoError(t, err)

	user := &record.User{
		Subject:      fake.UUID(),
		Enabled:      true,
		Email:        fake.Email(),
		PasswordHash: passwordHashed,
		GivenName:    fake.FirstName(),
		FamilyName:   fake.LastName(),
	}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	return user, password
}

// postDeviceAuthorization POSTs one device authorization request and returns the status and the
// parsed JSON body.
func postDeviceAuthorization(t *testing.T, form url.Values) (int, map[string]interface{}) {
	t.Helper()
	destUrl := appConfig.AuthServer.BaseURL + "/auth/device"
	req, err := http.NewRequest("POST", destUrl, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", destUrl)
	req.Header.Set("Origin", appConfig.AuthServer.BaseURL)

	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &body), "status %d, body: %s", resp.StatusCode, string(raw))
	return resp.StatusCode, body
}

// pollDeviceToken POSTs one device_code grant poll, the way the device polls, and returns the
// status and parsed JSON body.
func pollDeviceToken(t *testing.T, httpClient *http.Client, client *record.Client, clientSecret, deviceCode string) (int, map[string]interface{}) {
	t.Helper()
	form := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"client_id":   {client.ClientIdentifier},
		"device_code": {deviceCode},
	}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}

	destUrl := appConfig.AuthServer.BaseURL + "/auth/token/"
	req, err := http.NewRequest("POST", destUrl, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", destUrl)
	req.Header.Set("Origin", appConfig.AuthServer.BaseURL)

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &body), "status %d, body: %s", resp.StatusCode, string(raw))
	return resp.StatusCode, body
}

// postDeviceUserCode submits the user code at the verification page, with the Origin a browser
// sends, and returns its redirect.
func postDeviceUserCode(t *testing.T, browser *http.Client, userCode string) *http.Response {
	t.Helper()
	destUrl := appConfig.AuthServer.BaseURL + "/device"
	form := url.Values{"user_code": {userCode}}
	req, err := http.NewRequest("POST", destUrl, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", destUrl)
	req.Header.Set("Origin", appConfig.AuthServer.BaseURL)

	resp, err := browser.Do(req)
	require.NoError(t, err)
	return resp
}

// confirmDeviceInBrowser is the person at another browser: it opens the verification page, enters
// the code, completes the ordinary login ceremony and answers the consent screen. approve=false
// cancels the consent, which denies the device authorization. It returns the result query the
// completed page landed on.
func confirmDeviceInBrowser(t *testing.T, browser *http.Client, userCode string, user *record.User,
	password string, approve bool, consentTicks []int) string {

	t.Helper()

	entryPage := loadPage(t, browser, appConfig.AuthServer.BaseURL+"/device")
	require.Equal(t, http.StatusOK, entryPage.StatusCode, "the verification page renders for a visitor who is not signed in")
	_ = entryPage.Body.Close()

	resp := postDeviceUserCode(t, browser, userCode)
	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	_ = resp.Body.Close()

	resp = loadPage(t, browser, redirectLocation)
	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	_ = resp.Body.Close()

	resp = loadPage(t, browser, redirectLocation)
	pwdPage := resp
	resp = authenticateWithPassword(t, browser, redirectLocation, pwdPage, user.Email, password)
	_ = pwdPage.Body.Close()
	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	_ = resp.Body.Close()

	resp = loadPage(t, browser, redirectLocation)
	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()

	resp = loadPage(t, browser, redirectLocation)
	// A device ceremony always owes the consent screen, even though the client itself does not
	// ordinarily require one: the screen is where the device is explicitly approved.
	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	_ = resp.Body.Close()

	consentPage := loadPage(t, browser, redirectLocation)
	var consentResp *http.Response
	if approve {
		consentResp = postConsent(t, browser, redirectLocation, consentPage, consentTicks)
	} else {
		consentResp = postConsent(t, browser, redirectLocation, consentPage, nil)
	}
	_ = consentPage.Body.Close()

	require.Equal(t, http.StatusFound, consentResp.StatusCode)
	completed, err := url.Parse(consentResp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "/device/completed", completed.Path)
	_ = consentResp.Body.Close()
	return completed.Query().Get("result")
}

// expireDeviceCode moves a device code's expiry into the past without going through any handler,
// the way the background reaper's clock eventually would.
func expireDeviceCode(t *testing.T, deviceCodeId int64) {
	t.Helper()

	tx, err := database.BeginTransaction(context.Background())
	require.NoError(t, err)
	defer func() { _ = database.RollbackTransaction(context.Background(), tx) }()

	query := "UPDATE device_codes SET expires_at = ? WHERE id = ?"
	dialect, dialectErr := data.ParseDialect(appConfig.Database.Type)
	require.NoError(t, dialectErr)
	if dialect == data.Postgres {
		query = "UPDATE device_codes SET expires_at = $1 WHERE id = $2"
	}
	_, err = tx.ExecContext(context.Background(), query, time.Now().UTC().Add(-time.Minute), deviceCodeId)
	require.NoError(t, err)
	require.NoError(t, database.CommitTransaction(context.Background(), tx))
}

// deviceCodeIdByHash loads the id of a freshly issued device code through the same hash the token
// endpoint computes.
func deviceCodeIdByHash(t *testing.T, deviceCode string) int64 {
	t.Helper()
	row, err := database.GetDeviceCodeByDeviceCodeHash(context.Background(), nil, hashutil.HashString(deviceCode))
	require.NoError(t, err)
	require.NotNil(t, row)
	return row.Id
}

// TestDeviceAuthorizationGrant_Success is RFC 8628 end to end for a public client asking openid:
// the issued codes, the two wait answers while pending, the browser approval, the delivered
// tokens bound to the approving user and session, and the code's single consumption.
func TestDeviceAuthorizationGrant_Success(t *testing.T) {
	client := createDeviceFlowClient(t, "", true)
	user, password := createDeviceUser(t)

	status, issued := postDeviceAuthorization(t, url.Values{
		"client_id": {client.ClientIdentifier},
		"scope":     {"openid"},
	})
	require.Equal(t, http.StatusOK, status, "the device authorization endpoint answers 200: %v", issued)

	deviceCode, _ := issued["device_code"].(string)
	userCode, _ := issued["user_code"].(string)
	assert.Len(t, deviceCode, 40, "a high-entropy device code")
	assert.Regexp(t, `^[ACDEFGHJKMNPRTUWXY347]{4}-[ACDEFGHJKMNPRTUWXY347]{4}$`,
		userCode, "a typeable, grouped user code from the ambiguity-free alphabet")
	assert.Equal(t, appConfig.AuthServer.BaseURL+"/device", issued["verification_uri"])
	assert.Equal(t, appConfig.AuthServer.BaseURL+"/device?user_code="+
		strings.ReplaceAll(userCode, "-", ""), issued["verification_uri_complete"])
	assert.EqualValues(t, deviceflow.LifetimeSeconds, issued["expires_in"])
	assert.EqualValues(t, deviceflow.IntervalSeconds, issued["interval"])

	device := createHttpClient(t)

	// First poll: never yet polled, so authorization_pending with the suggested interval.
	status, pending := pollDeviceToken(t, device, client, "", deviceCode)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "authorization_pending", pending["error"])
	assert.EqualValues(t, deviceflow.IntervalSeconds, pending["interval"])
	assert.Nil(t, pending["access_token"])

	// An immediate second poll violates the interval just demanded: slow_down, and the demanded
	// interval grows by five seconds. It is a different code from authorization_pending.
	_, slowed := pollDeviceToken(t, device, client, "", deviceCode)
	assert.Equal(t, "slow_down", slowed["error"])
	assert.EqualValues(t, deviceflow.IntervalSeconds+deviceflow.SlowDownIncrementSeconds, slowed["interval"])

	// The person signs in at another browser and approves.
	browser := createHttpClient(t)
	result := confirmDeviceInBrowser(t, browser, userCode, user, password, true, []int{0})
	assert.Equal(t, "approved", result)

	// The next poll exchanges the one approval for tokens.
	status, tokens := pollDeviceToken(t, device, client, "", deviceCode)
	require.Equal(t, http.StatusOK, status, "the approved code is redeemed: %v", tokens)

	accessToken, ok := tokens["access_token"].(string)
	require.True(t, ok, "an access token is issued: %v", tokens)
	idToken, ok := tokens["id_token"].(string)
	require.True(t, ok, "openid was approved, so an id token is issued: %v", tokens)
	assert.NotEmpty(t, tokens["refresh_token"], "a refresh token is issued as for the password grant")
	assert.Equal(t, "Bearer", tokens["token_type"])
	assert.Equal(t, "openid", tokens["scope"])

	for name, token := range map[string]string{"access token": accessToken, "id token": idToken} {
		claims := decodeJWTPayload(t, token)
		assert.Equal(t, user.Subject, claims["sub"], "the %s is bound to the approving user", name)
		assert.Equal(t, "urn:goiabada:level1", claims["acr"], name)
		assert.Equal(t, []interface{}{"pwd"}, claims["amr"], name)
	}

	// A non-offline grant carries the sid of the browser session that approved it, on both tokens,
	// so the issued tokens are provably the ones that approval bound.
	assert.NotEmpty(t, decodeJWTPayload(t, accessToken)["sid"])
	assert.NotEmpty(t, decodeJWTPayload(t, idToken)["sid"])

	// The code is consumed once: a replay is invalid_grant, never a second token set.
	status, replay := pollDeviceToken(t, device, client, "", deviceCode)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", replay["error"])
	assert.Nil(t, replay["access_token"])
}

// TestDeviceAuthorizationGrant_Denied pins the person's refusal: the first poll after it is told
// access_denied, and the denial is delivered once because its compare-and-set consumes the code.
func TestDeviceAuthorizationGrant_Denied(t *testing.T) {
	client := createDeviceFlowClient(t, "", true)
	user, password := createDeviceUser(t)

	_, issued := postDeviceAuthorization(t, url.Values{
		"client_id": {client.ClientIdentifier},
		"scope":     {"openid"},
	})
	deviceCode := issued["device_code"].(string)
	userCode := issued["user_code"].(string)

	device := createHttpClient(t)
	_, pending := pollDeviceToken(t, device, client, "", deviceCode)
	assert.Equal(t, "authorization_pending", pending["error"])

	browser := createHttpClient(t)
	result := confirmDeviceInBrowser(t, browser, userCode, user, password, false, nil)
	assert.Equal(t, "denied", result)

	_, denied := pollDeviceToken(t, device, client, "", deviceCode)
	assert.Equal(t, "access_denied", denied["error"])
	assert.Nil(t, denied["access_token"])

	// The terminal answer is one delivery.
	_, replay := pollDeviceToken(t, device, client, "", deviceCode)
	assert.Equal(t, "invalid_grant", replay["error"])
}

// TestDeviceAuthorizationGrant_Expired polls a code whose lifetime lapsed without a confirmation:
// expired_token tells the device to stop polling, a distinct code from the other three.
func TestDeviceAuthorizationGrant_Expired(t *testing.T) {
	client := createDeviceFlowClient(t, "", true)

	_, issued := postDeviceAuthorization(t, url.Values{
		"client_id": {client.ClientIdentifier},
		"scope":     {"openid"},
	})
	deviceCode := issued["device_code"].(string)

	expireDeviceCode(t, deviceCodeIdByHash(t, deviceCode))

	device := createHttpClient(t)
	status, expired := pollDeviceToken(t, device, client, "", deviceCode)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "expired_token", expired["error"])
	assert.Nil(t, expired["access_token"])
}

// TestDeviceAuthorizationGrant_ClientSwitchOff pins the per-client enablement at the device
// authorization endpoint: a client without the grant is refused unauthorized_client, exactly as
// the other flows refuse theirs, and no codes are issued.
func TestDeviceAuthorizationGrant_ClientSwitchOff(t *testing.T) {
	client := createDeviceFlowClient(t, "", true)
	client.DeviceAuthorizationGrantEnabled = false
	require.NoError(t, database.UpdateClient(context.Background(), nil, client))

	status, refused := postDeviceAuthorization(t, url.Values{
		"client_id": {client.ClientIdentifier},
		"scope":     {"openid"},
	})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "unauthorized_client", refused["error"])
	assert.Nil(t, refused["device_code"])
}

// TestDeviceAuthorizationGrant_ConfidentialOfflineAccess observes a confidential client approving
// openid offline_access: the tokens carry the session the approval bound (sid), and a refresh
// token the device grant issued stops the moment that client's device switch is turned off, so a
// code-less token family cannot outlive the flow that created it.
func TestDeviceAuthorizationGrant_ConfidentialOfflineAccess(t *testing.T) {
	clientSecret := fake.Password(32)
	client := createDeviceFlowClient(t, clientSecret, false)
	user, password := createDeviceUser(t)

	_, issued := postDeviceAuthorization(t, url.Values{
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"scope":         {"openid offline_access"},
	})
	deviceCode := issued["device_code"].(string)
	userCode := issued["user_code"].(string)

	browser := createHttpClient(t)
	result := confirmDeviceInBrowser(t, browser, userCode, user, password, true, []int{0, 1})
	require.Equal(t, "approved", result)

	device := createHttpClient(t)
	status, tokens := pollDeviceToken(t, device, client, clientSecret, deviceCode)
	require.Equal(t, http.StatusOK, status, "the confidential client exchanges its approval: %v", tokens)

	accessToken := tokens["access_token"].(string)
	accessClaims := decodeJWTPayload(t, accessToken)
	assert.Equal(t, user.Subject, accessClaims["sub"])
	assert.Contains(t, tokens["scope"].(string), "offline_access")
	// The codebase's offline convention: an access token outlives the browser session and carries
	// no sid, while the id token keeps the approving session's sid for RP-initiated logout (#106).
	assert.Nil(t, accessClaims["sid"], "an offline access token is not bound to a browser session")
	idClaims := decodeJWTPayload(t, tokens["id_token"].(string))
	assert.NotEmpty(t, idClaims["sid"], "the id token stays bound to the approving session")

	refreshToken, ok := tokens["refresh_token"].(string)
	require.True(t, ok, "offline_access issues a refresh token: %v", tokens)

	tokenUrl := appConfig.AuthServer.BaseURL + "/auth/token/"
	refreshed := postToTokenEndpointWithBasicAuth(t, device, tokenUrl, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}, client.ClientIdentifier, clientSecret)
	require.Nil(t, refreshed["error"], "the device-issued refresh token works while the switch is on: %v", refreshed)
	refreshToken, ok = refreshed["refresh_token"].(string)
	require.True(t, ok, "rotation returns a successor refresh token: %v", refreshed)

	client.DeviceAuthorizationGrantEnabled = false
	require.NoError(t, database.UpdateClient(context.Background(), nil, client))

	stopped := postToTokenEndpointWithBasicAuth(t, device, tokenUrl, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}, client.ClientIdentifier, clientSecret)
	assert.Equal(t, "unauthorized_client", stopped["error"],
		"a device-issued refresh stops the moment the device grant is turned off")
	assert.Nil(t, stopped["access_token"])
}

// TestDeviceAuthorizationGrant_DiscoveryAdvertisesSupport pins that discovery publishes the
// device authorization endpoint and grant type while the server implements the flow, and omits
// neither.
func TestDeviceAuthorizationGrant_DiscoveryAdvertisesSupport(t *testing.T) {
	fields := fetchDiscoveryFields(t)

	var endpoint string
	require.NoError(t, json.Unmarshal(fields["device_authorization_endpoint"], &endpoint))
	assert.Equal(t, appConfig.AuthServer.BaseURL+"/auth/device", endpoint)

	var grantTypes []string
	require.NoError(t, json.Unmarshal(fields["grant_types_supported"], &grantTypes))
	assert.Contains(t, grantTypes, "urn:ietf:params:oauth:grant-type:device_code")
}
