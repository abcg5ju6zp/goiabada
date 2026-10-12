package protocolvalidation

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/permissions"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
)

// RFC 8693 token exchange's distinguishable refusals. The codes are the ones section 3.2.2 names:
// invalid_request for a malformed request or a token type this server does not accept,
// unsupported_grant_type for a requested_token_type it cannot issue, invalid_target for an
// audience or resource that identifies no resource, invalid_grant for a subject or actor token
// that is invalid, expired or from another issuer, and invalid_scope for a permission the
// intersection cannot grant.
const (
	tokenExchangeSubjectTokenMissingMsg      = "Missing required subject_token parameter."
	tokenExchangeSubjectTokenTypeMissingMsg  = "Missing required subject_token_type parameter."
	tokenExchangeSubjectTokenTypeUnsupported = "The subject_token_type is not supported. This server accepts " +
		"urn:ietf:params:oauth:token-type:access_token and urn:ietf:params:oauth:token-type:refresh_token."
	tokenExchangeActorTokenTypeUnsupported = "The actor_token_type is not supported. This server accepts " +
		"urn:ietf:params:oauth:token-type:access_token."
	tokenExchangeRequestedTokenTypeUnsupportedMsg = "The requested_token_type is not supported. This server issues " +
		"urn:ietf:params:oauth:token-type:access_token."
	tokenExchangeActorPairMsg    = "The actor_token and actor_token_type parameters must be sent together."
	tokenExchangeInvalidTokenMsg = "The subject token is invalid, expired, revoked or was not issued by this authorization server."
	tokenExchangeInvalidActorMsg = "The actor token is invalid, expired or was not issued by this authorization server."
)

// TokenExchangeGrant is a validated RFC 8693 exchange: the authenticated confidential client, the
// subject user and grant, the optional actor, and the scope and audiences the intersection
// granted. The issuer inherits the subject's session, authentication generation and instant from
// the fields below, which is what lets the existing session and revocation checks invalidate the
// issued token.
type TokenExchangeGrant struct {
	Client      *record.Client
	SubjectUser *record.User

	// SubjectTokenType is the URN the request named; SubjectJti is the presented token's jti and
	// SubjectTokenString the exact token presented, both part of the idempotency identity.
	SubjectTokenType   string
	SubjectJti         string
	SubjectTokenString string
	// SubjectRefreshToken is set when the subject token was a refresh token; it carries the
	// loaded source code lineage. Nil for an access-token subject. SourceCode is the refresh
	// token's source code when it descends from one.
	SubjectRefreshToken *record.RefreshToken
	SourceCode          *record.Code

	// ActorTokenString is "" when no actor token was presented. ActorJti and ActorSubject name
	// the actor when one was; ActorClientId resolves the actor to a client (0 otherwise).
	ActorTokenString string
	ActorJti         string
	ActorSubject     string
	ActorClientId    int64

	// Scope and Audiences are exactly what the issued token carries: the intersection of the
	// subject's authorization, the actor's permissions, the client's permissions, the user's
	// current grants and the requested target resources.
	Scope     string
	Audiences []string

	// The authorization context inherited from the subject grant.
	SessionIdentifier   string
	AuthStateGeneration int64
	AuthenticatedAt     time.Time
	AcrLevel            record.AcrLevel
	AuthMethods         []string

	// Act is the act claim the issued token carries: {"sub": immediateActor, "act": subjectChain}.
	Act map[string]any

	// The raw request parameters the idempotency hash is computed over.
	RequestedScope     string
	RequestedAudience  string
	RequestedResource  string
	RequestedTokenType string
}

func (*TokenExchangeGrant) GrantType() oidc.GrantType { return oidc.GrantTypeTokenExchange }

// validateTokenExchangeGrant validates an RFC 8693 token exchange for a client
// ValidateTokenRequest already found and found enabled.
func (val *TokenValidator) validateTokenExchangeGrant(ctx context.Context, settings *record.Settings,
	client *record.Client, input *ValidateTokenRequestInput) (*TokenExchangeGrant, error) {

	if !client.TokenExchangeEnabled {
		return nil, oauth.NewErrorDetailWithHTTPStatus("unauthorized_client",
			"The client associated with the provided client_id is not permitted to use the token exchange grant.",
			http.StatusBadRequest)
	}
	if client.IsPublic {
		return nil, oauth.NewErrorDetailWithHTTPStatus("unauthorized_client",
			"A public client is not eligible for token exchange, which requires a confidential client.",
			http.StatusBadRequest)
	}
	if err := val.authenticateClient(client, input.ClientSecret); err != nil {
		return nil, err
	}

	// Required parameters and the token type vocabulary, before any token is parsed.
	if input.SubjectToken == "" {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_request",
			tokenExchangeSubjectTokenMissingMsg, http.StatusBadRequest)
	}
	if input.SubjectTokenType == "" {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_request",
			tokenExchangeSubjectTokenTypeMissingMsg, http.StatusBadRequest)
	}
	if input.SubjectTokenType != oidc.TokenTypeAccessURN && input.SubjectTokenType != oidc.TokenTypeRefreshURN {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_request",
			tokenExchangeSubjectTokenTypeUnsupported, http.StatusBadRequest)
	}
	if input.ActorToken == "" && input.ActorTokenType != "" || input.ActorToken != "" && input.ActorTokenType == "" {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_request",
			tokenExchangeActorPairMsg, http.StatusBadRequest)
	}
	if input.ActorTokenType != "" && input.ActorTokenType != oidc.TokenTypeAccessURN {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_request",
			tokenExchangeActorTokenTypeUnsupported, http.StatusBadRequest)
	}
	requestedTokenType := input.RequestedTokenType
	if requestedTokenType == "" {
		requestedTokenType = oidc.TokenTypeAccessURN
	}
	if requestedTokenType != oidc.TokenTypeAccessURN {
		return nil, oauth.NewErrorDetailWithHTTPStatus("unsupported_grant_type",
			tokenExchangeRequestedTokenTypeUnsupportedMsg, http.StatusBadRequest)
	}

	// The target set named by audience and resource must identify resources this server knows;
	// an unknown one is RFC 8693's invalid_target rather than a scope denial.
	targetResources := map[string]struct{}{}
	for _, target := range []string{input.Audience, input.Resource} {
		if target == "" {
			continue
		}
		res, err := val.database.GetResourceByResourceIdentifier(ctx, nil, target)
		if err != nil {
			return nil, err
		}
		if res == nil {
			return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_target",
				fmt.Sprintf("The audience or resource '%s' is not a resource this authorization server recognizes.", target),
				http.StatusBadRequest)
		}
		targetResources[target] = struct{}{}
	}

	grant := &TokenExchangeGrant{
		Client:             client,
		SubjectTokenType:   input.SubjectTokenType,
		SubjectTokenString: input.SubjectToken,
		ActorTokenString:   input.ActorToken,
		RequestedScope:     input.Scope,
		RequestedAudience:  input.Audience,
		RequestedResource:  input.Resource,
		RequestedTokenType: requestedTokenType,
	}

	subjectScopes, subjectChain, err := val.validateExchangeSubject(ctx, settings, input, grant)
	if err != nil {
		return nil, err
	}

	actorScopes, err := val.validateExchangeActor(ctx, settings, grant)
	if err != nil {
		return nil, err
	}

	// The chain the new act claim would nest: one for the immediate actor plus whatever chain the
	// subject token already carries. Refused before any intersection work.
	depth := 1 + actorChainDepth(subjectChain)
	if depth > oidc.MaxActorChainDepth {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_request",
			fmt.Sprintf("The acting-party chain would reach depth %d, which exceeds the maximum supported depth of %d.",
				depth, oidc.MaxActorChainDepth),
			http.StatusBadRequest)
	}
	grant.Act = buildActClaim(grant.ActorSubjectOrClient(client), subjectChain)

	// The client's permissions are one side of the intersection.
	if err := val.database.ClientLoadPermissions(ctx, nil, client); err != nil {
		return nil, err
	}
	if err := val.database.PermissionsLoadResources(ctx, nil, client.Permissions); err != nil {
		return nil, err
	}

	// Candidates are, in order, the requested scopes, or every scope the subject token carried.
	// An explicitly requested scope that any side cannot grant is refused: the client asked for it
	// and must learn it was denied. When scope is omitted, the result is the true intersection, so
	// a scope one side cannot grant is filtered out rather than refused; an empty intersection is
	// the one refusal below.
	candidates := oidc.SplitScope(input.Scope)
	explicitlyRequested := len(candidates) > 0
	if !explicitlyRequested {
		candidates = subjectScopes
	}

	granted := []string{}
	for _, scopeStr := range candidates {
		// Claim scopes and offline_access are not delegable resource permissions: the exchanged
		// token is a bearer access token for a downstream resource, never an ID token.
		if oidc.IsClaimScope(scopeStr) || oidc.IsOfflineAccessScope(scopeStr) {
			if explicitlyRequested {
				return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_scope",
					fmt.Sprintf("Id token scopes (such as '%v') are not supported in a token exchange. Use resource:permission scopes (e.g., backendA:read).", scopeStr),
					http.StatusBadRequest)
			}
			continue
		}

		resolution, err := permissions.ResolveScope(ctx, val.database, scopeStr)
		if err != nil {
			return nil, err
		}
		if resolution.Outcome != permissions.ScopeOK {
			if !explicitlyRequested {
				continue
			}
			switch resolution.Outcome {
			case permissions.ScopeResourceUnknown:
				return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_target",
					fmt.Sprintf("Invalid target: '%v'. Could not find a resource with identifier '%v'.", scopeStr, resolution.ResourceIdentifier),
					http.StatusBadRequest)
			case permissions.ScopeMalformed:
				return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_scope",
					fmt.Sprintf("Invalid scope format: '%v'. Scopes must adhere to the resource-identifier:permission-identifier format.", scopeStr),
					http.StatusBadRequest)
			case permissions.ScopePermissionUnknown:
				return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_scope",
					fmt.Sprintf("Scope '%v' is not recognized. The resource identified by '%v' doesn't grant the '%v' permission.",
						scopeStr, resolution.ResourceIdentifier, resolution.PermissionIdentifier),
					http.StatusBadRequest)
			}
		}

		// Source authorization: the subject token actually carried this scope.
		if !slices.Contains(subjectScopes, scopeStr) {
			if explicitlyRequested {
				return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_scope",
					fmt.Sprintf("Permission to access scope '%v' is not granted by the subject token.", scopeStr),
					http.StatusBadRequest)
			}
			continue
		}
		// The user still holds the permission, re-checked live as the refresh arm re-checks, so a
		// permission withdrawn since the subject token was minted is not delegated forward.
		userHas, err := val.permissionChecker.UserHasScopePermission(ctx, grant.SubjectUser.Id, scopeStr)
		if err != nil {
			return nil, err
		}
		if !userHas {
			if explicitlyRequested {
				return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_scope",
					fmt.Sprintf("The subject of the token no longer holds the '%v' permission.", scopeStr),
					http.StatusBadRequest)
			}
			continue
		}
		// The acting party's own token carried it, when an actor authenticated separately.
		if actorScopes != nil && !slices.Contains(actorScopes, scopeStr) {
			if explicitlyRequested {
				return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_scope",
					fmt.Sprintf("Permission to access scope '%v' is not granted to the actor.", scopeStr),
					http.StatusBadRequest)
			}
			continue
		}
		// Client allowance, compared by the resource-scoped permission id for the reason the
		// client credentials grant does (#104).
		if !clientHoldsPermission(client, resolution.Permission.Id) {
			if explicitlyRequested {
				return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_scope",
					fmt.Sprintf("Permission to access scope '%v' is not granted to the client.", scopeStr),
					http.StatusBadRequest)
			}
			continue
		}
		// The current resource policy of the request: audience/resource, when named, bounds the
		// target to the intersection.
		if len(targetResources) > 0 {
			if _, ok := targetResources[resolution.ResourceIdentifier]; !ok {
				if explicitlyRequested {
					return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_target",
						fmt.Sprintf("The scope '%v' targets resource '%v', which the request's audience or resource does not name.",
							scopeStr, resolution.ResourceIdentifier),
						http.StatusBadRequest)
				}
				continue
			}
		}
		if !slices.Contains(granted, scopeStr) {
			granted = append(granted, scopeStr)
		}
	}

	if len(granted) == 0 {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_scope",
			"The intersection of the subject token's authorization, the actor's permissions, the client's permissions and the resource policy granted no scope, so no access token can be issued.",
			http.StatusBadRequest)
	}

	grant.Scope = strings.Join(granted, " ")
	audiences := []string{}
	for _, scopeStr := range granted {
		parts := strings.SplitN(scopeStr, ":", 2)
		if !slices.Contains(audiences, parts[0]) {
			audiences = append(audiences, parts[0])
		}
	}
	grant.Audiences = audiences
	return grant, nil
}

// ActorSubjectOrClient returns the immediate acting party the act claim names: the actor token's
// subject when one was presented, otherwise the authenticated client that requested the exchange.
func (g *TokenExchangeGrant) ActorSubjectOrClient(client *record.Client) string {
	if g.ActorSubject != "" {
		return g.ActorSubject
	}
	return client.ClientIdentifier
}

// validateExchangeSubject validates the subject token and fills the grant's user and inherited
// authorization context. It returns the subject token's scope list and any act chain it carried.
func (val *TokenValidator) validateExchangeSubject(ctx context.Context, settings *record.Settings,
	input *ValidateTokenRequestInput, grant *TokenExchangeGrant) ([]string, map[string]any, error) {

	parsed, err := val.tokenParser.DecodeAndValidateTokenString(ctx, input.SubjectToken, true)
	if err != nil {
		return nil, nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			tokenExchangeInvalidTokenMsg, http.StatusBadRequest)
	}

	switch input.SubjectTokenType {
	case oidc.TokenTypeAccessURN:
		return val.validateSubjectAccessToken(ctx, settings, parsed, grant)
	case oidc.TokenTypeRefreshURN:
		return val.validateSubjectRefreshToken(ctx, settings, parsed, grant)
	default:
		return nil, nil, oauth.NewErrorDetailWithHTTPStatus("invalid_request",
			tokenExchangeSubjectTokenTypeUnsupported, http.StatusBadRequest)
	}
}

func (val *TokenValidator) validateSubjectAccessToken(ctx context.Context, settings *record.Settings,
	token *oauth.JwtToken, grant *TokenExchangeGrant) ([]string, map[string]any, error) {

	if token.StringClaim("iss") != settings.Issuer {
		return nil, nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant", tokenExchangeInvalidTokenMsg, http.StatusBadRequest)
	}
	if token.StringClaim("typ") != issuance.TokenTypeBearer.String() {
		return nil, nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant", tokenExchangeInvalidTokenMsg, http.StatusBadRequest)
	}
	jti := token.StringClaim("jti")
	sub := token.StringClaim("sub")
	if jti == "" || sub == "" {
		return nil, nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant", tokenExchangeInvalidTokenMsg, http.StatusBadRequest)
	}
	// The subject of an exchange this server performs must be a user: the use case is a service
	// acting on a user's behalf, and the inherited auth_time/session claims are what make the
	// issued token a user token the session guard can revoke.
	if _, hasAuthTime := token.Claims["auth_time"]; !hasAuthTime {
		return nil, nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			"The subject token does not represent a user and cannot be exchanged on a user's behalf.",
			http.StatusBadRequest)
	}
	user, err := val.database.GetUserBySubject(ctx, nil, sub)
	if err != nil {
		return nil, nil, err
	}
	if user == nil || !user.Enabled {
		return nil, nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant", tokenExchangeInvalidTokenMsg, http.StatusBadRequest)
	}

	scopes := oidc.SplitScope(token.StringClaim("scope"))
	chain, chainOK := actorChain(token.Claims["act"])
	if token.Claims["act"] != nil && !chainOK {
		return nil, nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant", tokenExchangeInvalidTokenMsg, http.StatusBadRequest)
	}
	if len(chain) > 0 {
		// A subject token carrying an act claim was itself issued by an exchange: its lineage row
		// must exist, name this user, and its requesting client must still be enabled. This walks
		// only the recorded chain; its depth is bounded again at issuance and at presentation.
		if err := val.verifyExchangeAncestry(ctx, jti, user.Id); err != nil {
			return nil, nil, err
		}
	}

	generation, genOK := exchangeTokenGeneration(token)
	if !genOK {
		return nil, nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant", tokenExchangeInvalidTokenMsg, http.StatusBadRequest)
	}

	acrLevel := record.AcrLevel(token.StringClaim("acr"))
	grant.SubjectUser = user
	grant.SubjectJti = jti
	grant.SessionIdentifier = token.StringClaim("sid")
	grant.AuthStateGeneration = generation
	grant.AuthenticatedAt = token.TimeClaim("auth_time")
	grant.AcrLevel = acrLevel
	grant.AuthMethods = tokenStringArrayClaim(token, "amr")
	return scopes, chain, nil
}

func (val *TokenValidator) validateSubjectRefreshToken(ctx context.Context, settings *record.Settings,
	parsed *oauth.JwtToken, grant *TokenExchangeGrant) ([]string, map[string]any, error) {

	jti := parsed.StringClaim("jti")
	if jti == "" {
		return nil, nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant", tokenExchangeInvalidTokenMsg, http.StatusBadRequest)
	}
	refreshToken, err := val.database.GetRefreshTokenByJti(ctx, nil, jti)
	if err != nil {
		return nil, nil, err
	}
	if refreshToken == nil {
		return nil, nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant", tokenExchangeInvalidTokenMsg, http.StatusBadRequest)
	}

	isROPC := !refreshToken.CodeId.Valid
	var (
		tokenScope      string
		tokenUserId     int64
		tokenUser       *record.User
		sourceCode      *record.Code
		sessionId       string
		authenticatedAt time.Time
		acr             record.AcrLevel
		authMethods     []string
	)
	if isROPC {
		if loadErr := val.database.RefreshTokenLoadUser(ctx, nil, refreshToken); loadErr != nil {
			return nil, nil, loadErr
		}
		if loadErr := val.database.RefreshTokenLoadClient(ctx, nil, refreshToken); loadErr != nil {
			return nil, nil, loadErr
		}
		tokenUserId = refreshToken.UserId.Int64
		tokenScope = refreshToken.Scope
		tokenUser = &refreshToken.User
		sessionId = ""
		if !refreshToken.AuthenticatedAt.Valid {
			return nil, nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant", tokenExchangeInvalidTokenMsg, http.StatusBadRequest)
		}
		authenticatedAt = refreshToken.AuthenticatedAt.Time
		acr = record.AcrLevel1
		authMethods = []string{oidc.AuthMethodPassword.String()}
	} else {
		if loadErr := val.database.RefreshTokenLoadCode(ctx, nil, refreshToken); loadErr != nil {
			return nil, nil, loadErr
		}
		if loadErr := val.database.CodeLoadUser(ctx, nil, &refreshToken.Code); loadErr != nil {
			return nil, nil, loadErr
		}
		tokenUserId = refreshToken.Code.UserId
		tokenScope = refreshToken.Code.Scope
		tokenUser = &refreshToken.Code.User
		sourceCode = &refreshToken.Code
		sessionId = refreshToken.Code.SessionIdentifier
		authenticatedAt = refreshToken.Code.AuthenticatedAt
		acr = refreshToken.Code.AcrLevel
		authMethods = strings.Fields(refreshToken.Code.AuthMethods)
	}

	if !tokenUser.Enabled {
		return nil, nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant", tokenExchangeInvalidTokenMsg, http.StatusBadRequest)
	}
	if refreshToken.AuthStateGeneration != tokenUser.AuthStateGeneration {
		return nil, nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant", tokenExchangeInvalidTokenMsg, http.StatusBadRequest)
	}
	if refreshToken.Revoked {
		return nil, nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant", tokenExchangeInvalidTokenMsg, http.StatusBadRequest)
	}
	familyRevoked, err := val.database.IsRefreshTokenFamilyRevoked(ctx, nil, refreshToken.FirstRefreshTokenJti)
	if err != nil {
		return nil, nil, err
	}
	if familyRevoked {
		return nil, nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant", tokenExchangeInvalidTokenMsg, http.StatusBadRequest)
	}
	if !isROPC && refreshToken.Code.Revoked {
		return nil, nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant", tokenExchangeInvalidTokenMsg, http.StatusBadRequest)
	}

	// The live session or the offline max-lifetime, the same boundary the refresh arm enforces.
	switch parsed.StringClaim("typ") {
	case issuance.TokenTypeRefresh.String():
		userSession, err := val.database.GetUserSessionBySessionIdentifier(ctx, nil, refreshToken.SessionIdentifier)
		if err != nil {
			return nil, nil, err
		}
		if userSession == nil || userSession.UserId != tokenUserId ||
			!userSession.IsValid(time.Now().UTC(), settings.UserSessionIdleTimeoutInSeconds,
				settings.UserSessionMaxLifetimeInSeconds, nil) {
			return nil, nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant", tokenExchangeInvalidTokenMsg, http.StatusBadRequest)
		}
	case issuance.TokenTypeOffline.String():
		maxLifetime := parsed.TimeClaim("offline_access_max_lifetime")
		if maxLifetime.IsZero() || time.Now().UTC().After(maxLifetime) {
			return nil, nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant", tokenExchangeInvalidTokenMsg, http.StatusBadRequest)
		}
	default:
		return nil, nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant", tokenExchangeInvalidTokenMsg, http.StatusBadRequest)
	}

	grant.SubjectUser = tokenUser
	grant.SubjectJti = jti
	grant.SubjectRefreshToken = refreshToken
	grant.SourceCode = sourceCode
	grant.SessionIdentifier = sessionId
	grant.AuthStateGeneration = refreshToken.AuthStateGeneration
	grant.AuthenticatedAt = authenticatedAt
	grant.AcrLevel = acr
	grant.AuthMethods = authMethods
	return oidc.SplitScope(tokenScope), map[string]any{}, nil
}

// validateExchangeActor validates the optional actor_token and resolves it to a client when its
// subject names one. It returns the actor token's scope list, or nil when no actor was presented.
func (val *TokenValidator) validateExchangeActor(ctx context.Context, settings *record.Settings,
	grant *TokenExchangeGrant) ([]string, error) {

	if grant.ActorTokenString == "" {
		return nil, nil
	}
	parsed, err := val.tokenParser.DecodeAndValidateTokenString(ctx, grant.ActorTokenString, true)
	if err != nil {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant", tokenExchangeInvalidActorMsg, http.StatusBadRequest)
	}
	// The actor must be a live bearer token from the same supported issuer. Exchange across trust
	// domains needs a federated subject policy this server does not define, so a foreign or
	// malformed actor is refused.
	if parsed.StringClaim("iss") != settings.Issuer || parsed.StringClaim("typ") != issuance.TokenTypeBearer.String() ||
		parsed.StringClaim("jti") == "" || parsed.StringClaim("sub") == "" {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant", tokenExchangeInvalidActorMsg, http.StatusBadRequest)
	}
	grant.ActorJti = parsed.StringClaim("jti")
	grant.ActorSubject = parsed.StringClaim("sub")

	actorClient, err := val.database.GetClientByClientIdentifier(ctx, nil, grant.ActorSubject)
	if err != nil {
		return nil, err
	}
	if actorClient != nil {
		if !actorClient.Enabled {
			return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant", tokenExchangeInvalidActorMsg, http.StatusBadRequest)
		}
		grant.ActorClientId = actorClient.Id
	}
	return oidc.SplitScope(parsed.StringClaim("scope")), nil
}

// verifyExchangeAncestry walks the recorded lineage of an already-exchanged subject token. The
// row for the token presented must exist, name the same subject user and have an enabled
// requesting client. An ancestor whose own subject was an unexchanged token ends the walk: its
// jti has no exchange row by construction. The walk is bounded by the maximum signed chain.
func (val *TokenValidator) verifyExchangeAncestry(ctx context.Context, jti string, subjectUserId int64) error {
	currentJti := jti
	first := true
	for range oidc.MaxActorChainDepth + 1 {
		row, err := val.database.GetTokenExchangeByIssuedJti(ctx, nil, currentJti)
		if err != nil {
			return err
		}
		if row == nil {
			if first {
				return oauth.NewErrorDetailWithHTTPStatus("invalid_grant", tokenExchangeInvalidTokenMsg, http.StatusBadRequest)
			}
			return nil
		}
		first = false
		if !row.SubjectUserId.Valid || row.SubjectUserId.Int64 != subjectUserId {
			return oauth.NewErrorDetailWithHTTPStatus("invalid_grant", tokenExchangeInvalidTokenMsg, http.StatusBadRequest)
		}
		ancestorClient, err := val.database.GetClientById(ctx, nil, row.ClientId)
		if err != nil {
			return err
		}
		if ancestorClient == nil || !ancestorClient.Enabled {
			return oauth.NewErrorDetailWithHTTPStatus("invalid_grant", tokenExchangeInvalidTokenMsg, http.StatusBadRequest)
		}
		if row.ActorTokenJti == "" && row.SubjectTokenType != oidc.TokenTypeRefreshURN {
			// An access token subject with no actor token was the first exchange: its subject was
			// the original grant and the walk ends here.
			return nil
		}
		currentJti = row.SubjectTokenJti
	}
	return nil
}

func clientHoldsPermission(client *record.Client, permissionId int64) bool {
	for _, perm := range client.Permissions {
		if perm.Id == permissionId {
			return true
		}
	}
	return false
}

// actorChain reads an act claim as a nested {"sub": ..., "act": ...} structure, returning the
// chain from the outermost actor inward. A malformed claim reports false.
func actorChain(raw any) (map[string]any, bool) {
	if raw == nil {
		return nil, true
	}
	m, ok := raw.(map[string]any)
	if !ok || m["sub"] == nil {
		return nil, false
	}
	return m, true
}

// actorChainDepth counts the nested act objects in an act claim: act: {"sub": "a"} is 1,
// act: {"sub": "b", "act": {"sub": "a"}} is 2.
func actorChainDepth(act map[string]any) int {
	depth := 0
	for current := act; current != nil; {
		depth++
		inner, ok := current["act"].(map[string]any)
		if !ok {
			return depth
		}
		current = inner
	}
	return depth
}

// buildActClaim nests the immediate actor over the subject token's existing chain, RFC 8693
// section 4.4.
func buildActClaim(immediateActor string, subjectChain map[string]any) map[string]any {
	act := map[string]any{"sub": immediateActor}
	if len(subjectChain) > 0 {
		act["act"] = subjectChain
	}
	return act
}

// exchangeTokenGeneration reads a subject token's auth_state_generation with the same raw-map
// presence rule the bearer session guard uses: absent is generation 0, malformed is a refusal.
func exchangeTokenGeneration(token *oauth.JwtToken) (int64, bool) {
	if _, present := token.Claims["auth_state_generation"]; !present {
		return 0, true
	}
	return token.IntClaim("auth_state_generation")
}

func tokenStringArrayClaim(token *oauth.JwtToken, name string) []string {
	raw, ok := token.Claims[name].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
