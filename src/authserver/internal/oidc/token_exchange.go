package oidc

// OAuth 2.0 Token Exchange (RFC 8693) vocabulary. The grant type value the token endpoint's
// grant_type parameter carries, the token type URNs the subject_token_type, actor_token_type and
// requested_token_type parameters spell, and the depth of the acting-party chain this server will
// sign. They travel on the wire verbatim, like the grant type values in grant_type.go.

const (
	// GrantTypeTokenExchange is RFC 8693 section 2.1's grant_type value.
	GrantTypeTokenExchange GrantType = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // G101: a protocol URN, not a credential

	// TokenTypeAccessURN is the URN naming an OAuth 2.0 access token. It is the only token type
	// this server issues from an exchange, and one of the two types it accepts as a subject token.
	TokenTypeAccessURN = "urn:ietf:params:oauth:token-type:access_token" //nolint:gosec // G101: a protocol URN, not a credential
	// TokenTypeRefreshURN names an OAuth 2.0 refresh token, accepted as a subject token: its row
	// carries the source grant (code, session, user) an exchange is recorded as descending from.
	TokenTypeRefreshURN = "urn:ietf:params:oauth:token-type:refresh_token" //nolint:gosec // G101: a protocol URN, not a credential

	// MaxActorChainDepth bounds how many acting parties an issued token's "act" claim may nest,
	// RFC 8693 section 4.4. A direct delegation, act: {"sub": "actor"}, is depth 1; the actor may
	// itself be acting for one earlier party, depth 2. A request that would nest more is refused
	// rather than minting a chain nobody can audit.
	MaxActorChainDepth = 2
)

// TokenExchangeTokenTypesSupported is the token type list the discovery document publishes for
// token exchange: the URNs an exchanged token is issued in and may be presented in. It returns a
// fresh slice for the reason GrantTypesSupported does.
func TokenExchangeTokenTypesSupported() []string {
	return []string{TokenTypeAccessURN, TokenTypeRefreshURN}
}
