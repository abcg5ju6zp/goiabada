package integration

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rarFixture is one signed-in ceremony parked on its consent screen with an
// authorization_details request, plus everything the cases below mutate or redeem.
type rarFixture struct {
	httpClient   *http.Client
	client       *record.Client
	clientSecret string
	redirectURI  *record.RedirectURI
	user         *record.User
	write        *record.Permission
	consentURL   string
	consentPage  *http.Response
	state        string
}

func rarDetails(resource string, actions ...string) string {
	quoted := make([]string, len(actions))
	for i, a := range actions {
		quoted[i] = `"` + a + `"`
	}
	return `[{"type":"urn:goiabada:resource-permission","resource":"` + resource + `","actions":[` +
		strings.Join(quoted, ",") + `]}]`
}

// setupRarCeremony creates resource, permissions, a licensed client, a user holding
// the named permissions, and drives the browser to the consent screen.
func setupRarCeremony(t *testing.T, resourceIdentifier string, userActions, clientActions []string, rawDetails string) *rarFixture {
	t.Helper()

	resource := createResourceWithId(t, resourceIdentifier)
	read := createPermissionWithId(t, resource.Id, "read")
	write := createPermissionWithId(t, resource.Id, "write")

	clientSecret := fake.LetterN(32)
	secretEncrypted, err := dataCipher.Encrypt(clientSecret)
	require.NoError(t, err)

	client := &record.Client{
		ClientIdentifier:         "rar-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		DefaultAcrLevel:          record.AcrLevel1,
		ClientSecretEncrypted:    secretEncrypted,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	redirectURI := &record.RedirectURI{ClientId: client.Id, URI: fake.URL()}
	require.NoError(t, database.CreateRedirectURI(context.Background(), nil, redirectURI))

	for _, action := range clientActions {
		perm := rarPermission(resource, read, write, action)
		require.NoError(t, database.CreateClientPermission(context.Background(), nil,
			&record.ClientPermission{ClientId: client.Id, PermissionId: perm.Id}))
	}

	password := fake.Password(10)
	passwordHashed, err := passwordhash.Hash(password)
	require.NoError(t, err)
	user := &record.User{
		Subject:      fake.UUID(),
		Enabled:      true,
		Email:        fake.Email(),
		PasswordHash: passwordHashed,
	}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	for _, action := range userActions {
		perm := rarPermission(resource, read, write, action)
		assignPermissionToUser(t, user.Id, perm.Id)
	}

	httpClient := createHttpClient(t)
	state := fake.LetterN(8)
	authorizeURL := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI.URI) +
		"&response_type=code&scope=openid+" + resource.ResourceIdentifier + ":read" +
		"&state=" + state + "&nonce=" + fake.LetterN(8) +
		"&code_challenge_method=S256&code_challenge=" + oauth.GeneratePKCECodeChallenge(testCodeVerifier) +
		"&authorization_details=" + url.QueryEscape(rawDetails)

	resp, err := httpClient.Get(authorizeURL)
	require.NoError(t, err)
	location := assertRedirect(t, resp, "/auth/level1")
	require.NoError(t, resp.Body.Close())
	resp = loadPage(t, httpClient, location)

	location = assertRedirect(t, resp, "/auth/pwd")
	require.NoError(t, resp.Body.Close())
	pwdPage := loadPage(t, httpClient, location)

	resp = authenticateWithPassword(t, httpClient, location, pwdPage, user.Email, password)
	require.NoError(t, pwdPage.Body.Close())
	location = assertRedirect(t, resp, "/auth/level1completed")
	require.NoError(t, resp.Body.Close())
	resp = loadPage(t, httpClient, location)

	location = assertRedirect(t, resp, "/auth/completed")
	require.NoError(t, resp.Body.Close())
	resp = loadPage(t, httpClient, location)

	consentURL := assertRedirect(t, resp, "/auth/consent")
	require.NoError(t, resp.Body.Close())

	return &rarFixture{
		httpClient:   httpClient,
		client:       client,
		clientSecret: clientSecret,
		redirectURI:  redirectURI,
		user:         user,
		write:        write,
		consentURL:   consentURL,
		consentPage:  loadPage(t, httpClient, consentURL),
		state:        state,
	}
}

func rarPermission(resource *record.Resource, read, write *record.Permission, action string) *record.Permission {
	if action == "write" {
		return write
	}
	return read
}

// postRarConsent ticks the scope and detail checkboxes the page rendered and submits.
func (f *rarFixture) postRarConsent(t *testing.T, scopeBoxes, detailBoxes []int) *http.Response {
	t.Helper()
	form := url.Values{}
	form.Set("ceremonyId", getCeremonyIdFromPage(t, f.consentPage))
	for _, i := range scopeBoxes {
		form.Add("consent"+strconv.Itoa(i), "on")
	}
	for _, i := range detailBoxes {
		form.Add("authDetail"+strconv.Itoa(i), "on")
	}
	form.Set("btnSubmit", "submit")

	req, err := http.NewRequest("POST", f.consentURL, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", f.consentURL)
	req.Header.Set("Origin", appConfig.AuthServer.BaseURL)
	resp, err := f.httpClient.Do(req)
	require.NoError(t, err)
	return resp
}

// consentHTML reads the consent page body once and re-buffers it, so a later
// form submission still has the hidden inputs to read.
func (f *rarFixture) consentHTML(t *testing.T) string {
	t.Helper()
	body, err := io.ReadAll(f.consentPage.Body)
	require.NoError(t, err)
	f.consentPage.Body = io.NopCloser(bytes.NewReader(body))
	return string(body)
}

// finishToCode follows from the consent POST through /auth/issue to the client
// redirect and extracts the code.
func (f *rarFixture) finishToCode(t *testing.T, resp *http.Response) string {
	t.Helper()
	location := assertRedirect(t, resp, "/auth/issue")
	require.NoError(t, resp.Body.Close())
	resp = loadPage(t, f.httpClient, location)
	clientLocation := assertRedirectToURI(t, resp, f.redirectURI.URI)
	require.NoError(t, resp.Body.Close())

	parsed, err := url.Parse(clientLocation)
	require.NoError(t, err)
	assert.Equal(t, f.state, parsed.Query().Get("state"))
	code := parsed.Query().Get("code")
	require.NotEmpty(t, code)
	return code
}

func (f *rarFixture) redeem(t *testing.T, code string) map[string]interface{} {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {f.client.ClientIdentifier},
		"client_secret": {f.clientSecret},
		"code":          {code},
		"redirect_uri":  {f.redirectURI.URI},
		"code_verifier": {testCodeVerifier},
	}
	return postToTokenEndpoint(t, f.httpClient, appConfig.AuthServer.BaseURL+"/auth/token/", form)
}

// The happy path: the approved canonical set reaches the access token unchanged.
func TestRichAuthorizationRequests_ApprovedSetReachesAccessToken(t *testing.T) {
	resourceID := "rar-invoicing-" + fake.LetterN(6)
	f := setupRarCeremony(t, resourceID, []string{"read", "write"}, []string{"read", "write"}, rarDetails(resourceID, "write", "read"))
	defer func() { _ = f.consentPage.Body.Close() }()

	// The consent screen shows the target resource and every action it will grant.
	page := f.consentHTML(t)
	assert.Contains(t, page, resourceID)
	assert.Contains(t, page, "write")
	assert.Contains(t, page, "read")

	resp := f.postRarConsent(t, []int{0, 1}, []int{0})
	defer func() { _ = resp.Body.Close() }()
	code := f.finishToCode(t, resp)

	token := f.redeem(t, code)
	accessToken, ok := token["access_token"].(string)
	require.True(t, ok, "expected an access token, got: %v", token)

	claims := decodeJWTPayload(t, accessToken)
	raw, ok := claims["authorization_details"]
	require.True(t, ok, "the access token carries the claim")
	items, ok := raw.([]interface{})
	require.True(t, ok)
	require.Len(t, items, 1)
	item := items[0].(map[string]interface{})
	assert.Equal(t, "urn:goiabada:resource-permission", item["type"])
	assert.Equal(t, resourceID, item["resource"])
	assert.Equal(t, []interface{}{"read", "write"}, item["actions"], "the claim is canonical, sorted")
}

// The user holds only read: the consent screen narrows the request, and the token
// never carries write, although the client is licensed for it.
func TestRichAuthorizationRequests_NarrowedToUserGrants(t *testing.T) {
	resourceID := "rar-narrow-" + fake.LetterN(6)
	f := setupRarCeremony(t, resourceID, []string{"read"}, []string{"read", "write"}, rarDetails(resourceID, "write", "read"))
	defer func() { _ = f.consentPage.Body.Close() }()

	assert.NotContains(t, f.consentHTML(t), "write,", "write is not offered when the user does not hold it")

	resp := f.postRarConsent(t, []int{0, 1}, []int{0})
	defer func() { _ = resp.Body.Close() }()
	code := f.finishToCode(t, resp)

	claims := decodeJWTPayload(t, f.redeem(t, code)["access_token"].(string))
	item := claims["authorization_details"].([]interface{})[0].(map[string]interface{})
	assert.Equal(t, []interface{}{"read"}, item["actions"])
}

// A permission withdrawn between consent and redemption fails the exchange with
// invalid_grant: the snapshot is re-checked, not narrowed.
func TestRichAuthorizationRequests_PermissionWithdrawnBeforeRedemption(t *testing.T) {
	resourceID := "rar-withdrawn-" + fake.LetterN(6)
	f := setupRarCeremony(t, resourceID, []string{"read", "write"}, []string{"read", "write"}, rarDetails(resourceID, "read", "write"))
	defer func() { _ = f.consentPage.Body.Close() }()

	resp := f.postRarConsent(t, []int{0, 1}, []int{0})
	defer func() { _ = resp.Body.Close() }()
	code := f.finishToCode(t, resp)

	userPermissions, err := database.GetUserPermissionsByUserId(context.Background(), nil, f.user.Id)
	require.NoError(t, err)
	for _, p := range userPermissions {
		if p.PermissionId == f.write.Id {
			require.NoError(t, database.DeleteUserPermission(context.Background(), nil, p.Id))
		}
	}

	token := f.redeem(t, code)
	if !assert.Equal(t, "invalid_grant", token["error"]) {
		t.Logf("token response: %#v", token)
	}
}

// prompt=none can never approve a rich authorization request.
func TestRichAuthorizationRequests_PromptNoneIsConsentRequired(t *testing.T) {
	resource := createResourceWithId(t, "rar-silent-"+fake.LetterN(6))
	read := createPermissionWithId(t, resource.Id, "read")

	clientSecret := fake.LetterN(32)
	secretEncrypted, err := dataCipher.Encrypt(clientSecret)
	require.NoError(t, err)
	client := &record.Client{
		ClientIdentifier:         "rar-silent-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		DefaultAcrLevel:          record.AcrLevel1,
		ClientSecretEncrypted:    secretEncrypted,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	redirectURI := &record.RedirectURI{ClientId: client.Id, URI: fake.URL()}
	require.NoError(t, database.CreateRedirectURI(context.Background(), nil, redirectURI))
	require.NoError(t, database.CreateClientPermission(context.Background(), nil,
		&record.ClientPermission{ClientId: client.Id, PermissionId: read.Id}))

	httpClient, _, _, user := createSessionWithAcrLevel1(t)
	assignPermissionToUser(t, user.Id, read.Id)

	authorizeURL := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI.URI) +
		"&response_type=code&scope=openid+" + resource.ResourceIdentifier + ":read" +
		"&state=state12345678&nonce=" + fake.LetterN(8) +
		"&code_challenge_method=S256&code_challenge=" + oauth.GeneratePKCECodeChallenge(testCodeVerifier) +
		"&prompt=none&authorization_details=" + url.QueryEscape(rarDetails(resource.ResourceIdentifier, "read"))

	resp, err := httpClient.Get(authorizeURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	if !assert.Equal(t, "consent_required", location.Query().Get("error")) {
		t.Logf("full location: %s", resp.Header.Get("Location"))
	}
}

// A syntactically invalid authorization_details is an invalid_request delivered
// to the registered redirect URI. With a signed-in session the error route answers
// immediately.
func TestRichAuthorizationRequests_MalformedDetailsAreInvalidRequest(t *testing.T) {
	resource := createResourceWithId(t, "rar-malformed-"+fake.LetterN(6))
	read := createPermissionWithId(t, resource.Id, "read")

	clientSecret := fake.LetterN(32)
	secretEncrypted, err := dataCipher.Encrypt(clientSecret)
	require.NoError(t, err)
	client := &record.Client{
		ClientIdentifier:         "rar-malformed-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		DefaultAcrLevel:          record.AcrLevel1,
		ClientSecretEncrypted:    secretEncrypted,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	redirectURI := &record.RedirectURI{ClientId: client.Id, URI: fake.URL()}
	require.NoError(t, database.CreateRedirectURI(context.Background(), nil, redirectURI))
	require.NoError(t, database.CreateClientPermission(context.Background(), nil,
		&record.ClientPermission{ClientId: client.Id, PermissionId: read.Id}))

	httpClient, _, _, user := createSessionWithAcrLevel1(t)
	assignPermissionToUser(t, user.Id, read.Id)

	authorizeURL := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI.URI) +
		"&response_type=code&scope=openid+" + resource.ResourceIdentifier + ":read" +
		"&state=state12345678&nonce=" + fake.LetterN(8) +
		"&code_challenge_method=S256&code_challenge=" + oauth.GeneratePKCECodeChallenge(testCodeVerifier) +
		"&authorization_details=" + url.QueryEscape(`[`)

	resp, err := httpClient.Get(authorizeURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "invalid_request", location.Query().Get("error"))
}

// assertRedirectToURI asserts a redirect to an absolute URL on the given registered
// URI and returns the Location value.
func assertRedirectToURI(t *testing.T, resp *http.Response, registeredURI string) string {
	t.Helper()
	location := resp.Header.Get("Location")
	require.NotEmpty(t, location, "expected a redirect")
	require.True(t, strings.HasPrefix(location, registeredURI),
		"expected a redirect to %s, got %s", registeredURI, location)
	return location
}
