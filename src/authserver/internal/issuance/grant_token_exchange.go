package issuance

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/permissions"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/uuid"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

// TokenExchangeInput is everything one validated RFC 8693 exchange proved and asked for. The
// protocol validator builds it from the presented tokens and the token endpoint's responder hands
// it to IssueTokenExchangeGrant; issuance reads no request parameter itself.
type TokenExchangeInput struct {
	Client      *record.Client
	SubjectUser *record.User

	// The subject: its token (for the idempotency hash), its jti and the URN naming its type.
	// SubjectIsRefresh selects the refresh-token revalidation path.
	SubjectTokenString string
	SubjectJti         string
	SubjectTokenType   string
	SubjectIsRefresh   bool

	// The optional acting party.
	ActorTokenString string
	ActorJti         string
	ActorSubject     string
	ActorClientId    int64

	// The intersection that was granted.
	Scope     string
	Audiences []string

	// The authorization context inherited from the subject grant.
	SessionIdentifier   string
	AuthStateGeneration int64
	AuthenticatedAt     time.Time
	AcrLevel            record.AcrLevel
	AuthMethods         []string

	// The act claim the issued token carries.
	Act map[string]any

	// The raw request values the idempotency hash is computed over.
	RequestedScope     string
	RequestedAudience  string
	RequestedResource  string
	RequestedTokenType string
}

// IssueTokenExchangeGrant performs one RFC 8693 token exchange end to end, inside ONE
// transaction:
//
//  1. Idempotency first. The canonical request hash is looked up before anything is minted, so an
//     uncertain response, a retried submission or a concurrent identical exchange returns the
//     stored access token (decrypted from the row) instead of minting a second lineage. The
//     request_hash unique key makes the loser of a race retry the body and read the winner's row.
//  2. Revalidation under row locks. The requesting client, the subject user and session, the
//     actor client, the source refresh token or code and every exchange ancestor are re-read with
//     their rows taken, so a revocation that lands after validation but before commit produces no
//     usable token.
//  3. Mint and record. The access token inherits the subject's user, session identifier and
//     authentication generation, carries the intersected scope and audience and the act chain, and
//     the token_exchanges row written in the same transaction records the full derivation.
//
// It issues an access token and nothing else, as RFC 8693 section 2.2.1 says a successful exchange
// does: no refresh token, no ID token.
func (t *TokenIssuer) IssueTokenExchangeGrant(ctx context.Context, settings *record.Settings,
	input *TokenExchangeInput) (*oauth.TokenResponse, error) {

	requestHash := exchangeRequestHash(input)

	var tokenResponse *oauth.TokenResponse
	err := data.RunInTransactionRetryingConflict(ctx, t.database, func(tx *sql.Tx) error {
		existing, err := t.database.GetTokenExchangeByRequestHash(ctx, tx, requestHash)
		if err != nil {
			return err
		}
		if existing != nil {
			var replayErr error
			tokenResponse, replayErr = t.replayTokenExchange(existing)
			if replayErr != nil {
				return replayErr
			}
			return nil
		}

		stampedGeneration, sourceRefreshId, sourceCodeId, err := t.recheckTokenExchange(ctx, tx, settings, input)
		if err != nil {
			return err
		}

		accessToken, exchangeJti, expiresAt, err := t.signTokenExchangeAccessToken(ctx, tx, settings, input, stampedGeneration)
		if err != nil {
			return err
		}

		encrypted, err := t.dataCipher.Encrypt(accessToken)
		if err != nil {
			return errs.Wrap(err, "unable to encrypt the exchanged access token")
		}

		row := &record.TokenExchange{
			ExchangeJti:          exchangeJti,
			RequestHash:          requestHash,
			ClientId:             input.Client.Id,
			SubjectUserId:        sql.NullInt64{Int64: input.SubjectUser.Id, Valid: true},
			SubjectTokenJti:      input.SubjectJti,
			SubjectTokenType:     input.SubjectTokenType,
			SessionIdentifier:    input.SessionIdentifier,
			Scope:                input.Scope,
			Audience:             strings.Join(input.Audiences, " "),
			IssuedTokenEncrypted: encrypted,
			ExpiresAt:            sql.NullTime{Time: expiresAt, Valid: true},
		}
		if input.ActorJti != "" {
			row.ActorTokenJti = input.ActorJti
		}
		if input.ActorClientId != 0 {
			row.ActorClientId = sql.NullInt64{Int64: input.ActorClientId, Valid: true}
		}
		if sourceRefreshId != 0 {
			row.SourceRefreshTokenId = sql.NullInt64{Int64: sourceRefreshId, Valid: true}
		}
		if sourceCodeId != 0 {
			row.SourceCodeId = sql.NullInt64{Int64: sourceCodeId, Valid: true}
		}
		if err := t.database.CreateTokenExchange(ctx, tx, row); err != nil {
			return err
		}

		tokenResponse = &oauth.TokenResponse{
			AccessToken:     accessToken,
			TokenType:       TokenTypeBearer.String(),
			ExpiresIn:       int64(tokenLifetimeSeconds(settings, input.Client)),
			Scope:           input.Scope,
			IssuedTokenType: oidc.TokenTypeAccessURN,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return tokenResponse, nil
}

// replayTokenExchange answers an idempotent retry: the same access token the first attempt was
// answered with, with expires_in recomputed against its original exp. A replay of an exchange whose
// token has expired cannot extend it and is refused invalid_grant; the client exchanges again.
func (t *TokenIssuer) replayTokenExchange(row *record.TokenExchange) (*oauth.TokenResponse, error) {
	accessToken, err := t.dataCipher.Decrypt(row.IssuedTokenEncrypted)
	if err != nil {
		return nil, errs.Wrap(err, "unable to decrypt the stored exchanged access token")
	}

	expiresIn := int64(0)
	if row.ExpiresAt.Valid {
		expiresIn = int64(time.Until(row.ExpiresAt.Time).Seconds())
	}
	if expiresIn <= 0 {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			"The exchanged access token has expired. Perform a new token exchange.", http.StatusBadRequest)
	}

	return &oauth.TokenResponse{
		AccessToken:     accessToken,
		TokenType:       TokenTypeBearer.String(),
		ExpiresIn:       expiresIn,
		Scope:           row.Scope,
		IssuedTokenType: oidc.TokenTypeAccessURN,
	}, nil
}

// recheckTokenExchange re-validates the exchange inside the issuing transaction, under locks, and
// returns the authentication generation the new token is stamped with and the source grant ids the
// lineage row records. It is the boundary between a token that was valid when validated and one
// that is valid when committed: a client disabled, a user disabled or advanced, a terminated or
// expired session, a revoked source grant or a disabled exchange ancestor all refuse here, so no
// usable derived token is produced.
func (t *TokenIssuer) recheckTokenExchange(ctx context.Context, tx *sql.Tx, settings *record.Settings,
	input *TokenExchangeInput) (stampedGeneration int64, sourceRefreshTokenId int64, sourceCodeId int64, err error) {

	refuse := func(msg string) error {
		return oauth.NewErrorDetailWithHTTPStatus("invalid_grant", msg, http.StatusBadRequest)
	}

	// Take the client rows first, ordered by id, when the actor is a different client, so two
	// exchanges across the same two clients cannot deadlock taking them in opposite orders.
	clientIds := []int64{input.Client.Id}
	if input.ActorClientId != 0 && input.ActorClientId != input.Client.Id {
		clientIds = append(clientIds, input.ActorClientId)
	}
	slices.Sort(clientIds)
	for _, id := range clientIds {
		err = t.database.AcquireClientRow(ctx, tx, id)
		if err != nil {
			return 0, 0, 0, err
		}
		locked, lockedErr := t.database.GetClientById(ctx, tx, id)
		if lockedErr != nil {
			return 0, 0, 0, lockedErr
		}
		if locked == nil || !locked.Enabled {
			return 0, 0, 0, refuse("A client of this exchange is disabled, so the exchange is refused.")
		}
		if id == input.Client.Id && (!locked.TokenExchangeEnabled || locked.IsPublic) {
			return 0, 0, 0, refuse("The client is no longer permitted to exchange tokens.")
		}
	}

	err = t.database.AcquireUserRow(ctx, tx, input.SubjectUser.Id)
	if err != nil {
		return 0, 0, 0, err
	}
	user, err := t.database.GetUserById(ctx, tx, input.SubjectUser.Id)
	if err != nil {
		return 0, 0, 0, err
	}
	if user == nil || !user.Enabled {
		return 0, 0, 0, refuse("The subject user is disabled, so the exchange is refused.")
	}

	if input.SessionIdentifier != "" {
		found, err := t.database.AcquireUserSessionRow(ctx, tx, input.SessionIdentifier)
		if err != nil {
			return 0, 0, 0, err
		}
		if !found {
			return 0, 0, 0, refuse("The subject token's session has been terminated.")
		}
		session, err := t.database.GetUserSessionBySessionIdentifier(ctx, tx, input.SessionIdentifier)
		if err != nil {
			return 0, 0, 0, err
		}
		// The session must belong to the subject user, be within its lifetime and still be on the
		// user's current generation: the same four checks the bearer session guard makes.
		if session == nil || session.UserId != user.Id {
			return 0, 0, 0, refuse("The subject token's session has been terminated.")
		}
		if !session.IsValid(time.Now().UTC(), settings.UserSessionIdleTimeoutInSeconds,
			settings.UserSessionMaxLifetimeInSeconds, nil) {
			return 0, 0, 0, refuse("The subject token's session has expired.")
		}
		if session.AuthStateGeneration != user.AuthStateGeneration {
			return 0, 0, 0, refuse("The subject token's authentication state has been superseded.")
		}
		// A new token minted from a live session inherits the session's generation, as a token
		// minted by that session does: a self-service credential change promotes the session
		// forward while already-issued tokens lag it.
		stampedGeneration = session.AuthStateGeneration
	} else {
		if input.AuthStateGeneration != user.AuthStateGeneration {
			return 0, 0, 0, refuse("The subject token's authentication state has been superseded.")
		}
		stampedGeneration = input.AuthStateGeneration
	}

	// The refresh-token subject and its source code are re-read: the validator's read and this
	// insert must not straddle a revocation.
	if input.SubjectIsRefresh {
		live, err := t.database.GetRefreshTokenByJti(ctx, tx, input.SubjectJti)
		if err != nil {
			return 0, 0, 0, err
		}
		if live == nil || live.Revoked {
			return 0, 0, 0, refuse("The subject refresh token has been revoked.")
		}
		familyRevoked, err := t.database.IsRefreshTokenFamilyRevoked(ctx, tx, live.FirstRefreshTokenJti)
		if err != nil {
			return 0, 0, 0, err
		}
		if familyRevoked {
			return 0, 0, 0, refuse("The subject refresh token's family has been revoked.")
		}
		sourceRefreshTokenId = live.Id
		if live.CodeId.Valid {
			if err := t.database.RefreshTokenLoadCode(ctx, tx, live); err != nil {
				return 0, 0, 0, err
			}
			if live.Code.Revoked {
				return 0, 0, 0, refuse("The subject token's source grant has been revoked.")
			}
			sourceCodeId = live.Code.Id
		}
	}

	// An exchanged subject token: every ancestor exchange's requesting client must still be
	// enabled. The walk ends at the first jti with no exchange row, which is the original grant.
	if err := t.recheckExchangeAncestry(ctx, tx, input.SubjectJti, input.SubjectIsRefresh); err != nil {
		return 0, 0, 0, err
	}

	// The client allowance half of the intersection, re-read with the client row locked, so a
	// permission withdrawn between validation and commit cannot be delegated.
	if err := t.database.ClientLoadPermissions(ctx, tx, input.Client); err != nil {
		return 0, 0, 0, err
	}
	if err := t.database.PermissionsLoadResources(ctx, tx, input.Client.Permissions); err != nil {
		return 0, 0, 0, err
	}
	for _, scopeStr := range strings.Fields(input.Scope) {
		resolution, err := permissions.ResolveScope(ctx, t.database, scopeStr)
		if err != nil {
			return 0, 0, 0, err
		}
		if resolution.Outcome != permissions.ScopeOK {
			return 0, 0, 0, oauth.NewErrorDetailWithHTTPStatus("invalid_scope",
				"The client no longer holds a permission the exchange would grant: "+scopeStr,
				http.StatusBadRequest)
		}
		held := false
		for _, perm := range input.Client.Permissions {
			if perm.Id == resolution.Permission.Id {
				held = true
				break
			}
		}
		if !held {
			return 0, 0, 0, oauth.NewErrorDetailWithHTTPStatus("invalid_scope",
				"Permission to access scope '"+scopeStr+"' is no longer granted to the client.",
				http.StatusBadRequest)
		}
	}

	return stampedGeneration, sourceRefreshTokenId, sourceCodeId, nil
}

// recheckExchangeAncestry walks recorded exchange rows by issued jti until the original,
// non-exchanged grant, refusing when any ancestor's client is gone or disabled. Bounded the same
// way the issued chain is bounded. A refresh-token subject has no exchange row by construction and
// ends the walk immediately.
func (t *TokenIssuer) recheckExchangeAncestry(ctx context.Context, tx *sql.Tx, jti string, subjectIsRefresh bool) error {
	if subjectIsRefresh {
		return nil
	}
	currentJti := jti
	for range oidc.MaxActorChainDepth + 1 {
		row, err := t.database.GetTokenExchangeByIssuedJti(ctx, tx, currentJti)
		if err != nil {
			return err
		}
		if row == nil {
			// Not an exchanged token: the walk reached the original grant.
			return nil
		}
		ancestor, err := t.database.GetClientById(ctx, tx, row.ClientId)
		if err != nil {
			return err
		}
		if ancestor == nil || !ancestor.Enabled {
			return oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
				"A client in the exchange chain is disabled, so the exchange is refused.", http.StatusBadRequest)
		}
		currentJti = row.SubjectTokenJti
	}
	return nil
}

// signTokenExchangeAccessToken builds and signs the exchanged access token with the inherited
// user/session/generation claims, the intersected audience and scope and the act chain.
func (t *TokenIssuer) signTokenExchangeAccessToken(ctx context.Context, tx *sql.Tx, settings *record.Settings,
	input *TokenExchangeInput, stampedGeneration int64) (tokenString string, jti string, expiresAt time.Time, err error) {

	privKey, keyIdentifier, err := t.loadSigningKey(ctx, tx)
	if err != nil {
		return "", "", time.Time{}, err
	}

	lifetimeSeconds := tokenLifetimeSeconds(settings, input.Client)
	now := time.Now().UTC()
	expiresAt = now.Add(time.Second * time.Duration(lifetimeSeconds))
	jti = uuid.New()

	claims := jwt.MapClaims{
		"iss":                   settings.Issuer,
		"sub":                   input.SubjectUser.Subject,
		"iat":                   now.Unix(),
		"nbf":                   now.Unix(),
		"jti":                   jti,
		"typ":                   TokenTypeBearer.String(),
		"exp":                   expiresAt.Unix(),
		"scope":                 input.Scope,
		"auth_time":             input.AuthenticatedAt.Unix(),
		"auth_state_generation": stampedGeneration,
		"act":                   input.Act,
	}
	if input.AcrLevel != "" {
		claims["acr"] = input.AcrLevel.String()
	}
	if len(input.AuthMethods) > 0 {
		claims["amr"] = input.AuthMethods
	}
	if input.SessionIdentifier != "" {
		claims["sid"] = input.SessionIdentifier
	}
	switch len(input.Audiences) {
	case 0:
		return "", "", time.Time{}, errs.Errorf("unable to generate an exchanged access token without an audience")
	case 1:
		claims["aud"] = input.Audiences[0]
	default:
		claims["aud"] = input.Audiences
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyIdentifier
	signed, err := token.SignedString(privKey)
	if err != nil {
		return "", "", time.Time{}, errs.Wrap(err, "unable to sign exchanged access_token")
	}
	return signed, jti, expiresAt, nil
}

// exchangeRequestHash is the idempotency identity of one logical exchange: the authenticated
// client, the exact subject and actor tokens presented, the requested target, the requested scope
// and the requested token type. NUL-separated because none of these form values can contain a NUL.
// Two submissions hashing alike are the same exchange and return the same result.
func exchangeRequestHash(input *TokenExchangeInput) string {
	var b strings.Builder
	parts := []string{
		strconv.FormatInt(input.Client.Id, 10),
		input.SubjectTokenString,
		input.ActorTokenString,
		input.RequestedAudience,
		input.RequestedResource,
		input.RequestedScope,
		input.RequestedTokenType,
	}
	for i, p := range parts {
		if i > 0 {
			b.WriteByte(0)
		}
		b.WriteString(p)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}
