package issuance

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/deviceflow"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
)

// ErrDeviceCodeNotClaimed is a device redemption that lost the claim on its code: the one
// approved poll allowed to consume it already did, or the row changed state between validation
// and the claim. Concurrent duplicates are the ordinary cause, and both are refused generically,
// the same answer ErrCodeNotClaimed gives.
var ErrDeviceCodeNotClaimed = errors.New("the device code was no longer approved and unconsumed when it was claimed")

// IssueDeviceCodeGrant redeems one approved device authorization (RFC 8628 section 3.4): it
// claims the code with a compare-and-set, then mints the access token, the ID token when openid
// was approved, and the first refresh token, all from the approval the browser confirmation
// bound to the row, so they match the user, client, consented scope, session, level, methods and
// authentication instant that were confirmed.
//
// The claim is the same one-winner mark the authorization code grant uses, made BEFORE anything
// is minted: two devices (or two polls) presenting one code cannot both receive tokens. Refresh
// tokens are code-less like the password grant's, marked with the device origin so the refresh
// redemption gates on the device switch; the access token carries the approval session's sid
// unless offline_access was approved.
func (t *TokenIssuer) IssueDeviceCodeGrant(ctx context.Context, settings *record.Settings,
	deviceCode *record.DeviceCode) (*oauth.TokenResponse, error) {

	claimed, err := t.database.MarkDeviceCodeConsumed(ctx, nil, deviceCode.Id, string(deviceflow.StatusApproved))
	if err != nil {
		return nil, err
	}
	if !claimed {
		slog.DebugContext(ctx, "device code could not be claimed, rejecting the redemption",
			"grant_type", oidc.GrantTypeDeviceCode.String(),
			"device_code_id", deviceCode.Id)
		return nil, ErrDeviceCodeNotClaimed
	}

	return t.mintDeviceCodeTokens(ctx, settings, deviceCode)
}

func (t *TokenIssuer) mintDeviceCodeTokens(ctx context.Context, settings *record.Settings,
	deviceCode *record.DeviceCode) (*oauth.TokenResponse, error) {

	err := t.database.DeviceCodeLoadClient(ctx, nil, deviceCode)
	if err != nil {
		return nil, err
	}
	err = t.database.DeviceCodeLoadUser(ctx, nil, deviceCode)
	if err != nil {
		return nil, err
	}

	tokenExpirationInSeconds := tokenLifetimeSeconds(settings, &deviceCode.Client)
	response := &oauth.TokenResponse{
		TokenType: TokenTypeBearer.String(),
		ExpiresIn: int64(tokenExpirationInSeconds),
	}

	privKey, keyIdentifier, err := t.loadSigningKey(ctx, nil)
	if err != nil {
		return nil, err
	}

	err = t.database.UserLoadGroups(ctx, nil, &deviceCode.User)
	if err != nil {
		return nil, err
	}
	err = t.database.GroupsLoadAttributes(ctx, nil, deviceCode.User.Groups)
	if err != nil {
		return nil, err
	}
	err = t.database.UserLoadAttributes(ctx, nil, &deviceCode.User)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	scope := deviceCode.ConsentedScope
	authenticatedAt := deviceCode.AuthenticatedAt.Time
	if authenticatedAt.IsZero() {
		// The approval statement always sets this; zero would only come from a row written outside
		// the server, which must not mint a token claiming an impossible auth_time.
		authenticatedAt = now
	}

	input := &tokenGenerationInput{
		User:                &deviceCode.User,
		Client:              &deviceCode.Client,
		Scope:               scope,
		AcrLevel:            deviceCode.AcrLevel,
		AuthMethods:         authMethodsToArray(deviceCode.AuthMethods),
		AuthenticatedAt:     authenticatedAt,
		SessionIdentifier:   deviceCode.SessionIdentifier,
		AuthStateGeneration: deviceCode.AuthStateGeneration,
		// An offline grant outlives the browser session that approved it; anything else keeps the
		// sid of the session that confirmed it, as an authorization code grant would.
		GrantIsOffline: oidc.HasOfflineAccessScope(scope),
	}

	accessTokenStr, err := t.generateAccessTokenCore(ctx, nil, settings, input, now, privKey, keyIdentifier)
	if err != nil {
		return nil, err
	}
	response.AccessToken = accessTokenStr
	response.Scope = scope

	if slices.Contains(strings.Split(scope, " "), "openid") {
		idTokenStr, err := t.generateIdTokenCore(ctx, nil, settings, input, now, privKey, keyIdentifier)
		if err != nil {
			return nil, err
		}
		response.IdToken = idTokenStr
	}

	// The first refresh token, code-less with the direct user and client, origin device_code so
	// its rotations stay governed by this client's device switch. The user snapshot carries the
	// approval's generation rather than a reloaded one: the first refresh token records the
	// generation of the credential that authorized THIS issuance, never a live read.
	refreshUser := deviceCode.User
	refreshUser.AuthStateGeneration = deviceCode.AuthStateGeneration
	codelessInput := &ROPCGrantInput{
		Client:          &deviceCode.Client,
		User:            &refreshUser,
		Scope:           scope,
		AuthenticatedAt: authenticatedAt,
	}
	refreshToken, refreshExpiresIn, err := t.generateRefreshTokenForCodelessGrant(ctx, nil, settings,
		codelessInput, scope, now, privKey, keyIdentifier, nil, oidc.GrantOriginDeviceCode)
	if err != nil {
		return nil, err
	}
	response.RefreshToken = refreshToken
	response.RefreshExpiresIn = refreshExpiresIn

	return response, nil
}
