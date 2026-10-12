package record

import (
	"database/sql"
)

// TokenExchange is the durable record of one OAuth 2.0 Token Exchange (RFC 8693): the identity the
// exchange ran under and the lineage the issued access token descends from.
//
// The row is written in the same transaction as the decision to mint, and it is the idempotency
// record too: RequestHash identifies one logical exchange, so an uncertain response, a retried
// submission or a concurrent identical exchange returns the stored token rather than minting a
// second, conflicting lineage.
//
// It is also the revocation lineage the bearer session guard walks: the issued token's jti finds
// the row, the row finds the client that requested it and, for a refresh-token subject, the source
// code and refresh token, so a disabled client, a terminated session, an advanced authentication
// generation or a revoked source grant invalidates every token descended here.
type TokenExchange struct {
	Id        int64        `db:"id" fieldtag:"pk"`
	CreatedAt sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt sql.NullTime `db:"updated_at"`

	// ExchangeJti is the jti of the access token this exchange issued, its unique handle.
	ExchangeJti string `db:"exchange_jti"`
	// RequestHash is the SHA-256 of the canonical exchange request (client, subject token, actor
	// token, audience/resource, scope, requested token type). It makes one logical exchange return
	// one result, whatever submission uncertainty occurred.
	RequestHash string `db:"request_hash"`

	// ClientId is the confidential, authenticated client that requested the exchange.
	ClientId int64 `db:"client_id"`

	// SubjectUserId is the user the subject token was minted for, when the subject named one. An
	// exchange this server performs always represents a user.
	SubjectUserId sql.NullInt64 `db:"subject_user_id"`
	// SubjectTokenJti and SubjectTokenType identify and name the presented subject token.
	SubjectTokenJti  string `db:"subject_token_jti"`
	SubjectTokenType string `db:"subject_token_type"`

	// ActorTokenJti and ActorClientId identify the presented actor token and, when its subject
	// named a client, that client. Empty actor jti means no actor token was presented.
	ActorTokenJti string       `db:"actor_token_jti"`
	ActorClientId sql.NullInt64 `db:"actor_client_id"`

	// The source grant the issued token descends from, when the subject was a refresh token: its
	// row and, through it, the authorization code whose revoked mark and session terminate the
	// lineage. Both NULL for an access-token subject, whose session and jti identify the grant.
	SourceRefreshTokenId sql.NullInt64 `db:"source_refresh_token_id"`
	SourceCodeId         sql.NullInt64 `db:"source_code_id"`
	// SessionIdentifier is the subject token's browser session, empty for a sessionless grant.
	SessionIdentifier string `db:"session_identifier"`

	// Scope and Audience are exactly what the issued token carries: the intersection of the
	// subject's authorization, the actor's permissions, the client's permissions and the resource
	// policy, restricted to the requested target. Audience is space-joined, one resource per value.
	Scope    string `db:"scope"`
	Audience string `db:"audience"`

	// IssuedTokenEncrypted is the signed access token exactly as it was answered, encrypted at
	// rest with the data cipher, so an idempotent retry can return the same token and not mint a
	// second lineage.
	IssuedTokenEncrypted []byte `db:"issued_token_encrypted"`

	// ExpiresAt is the issued token's exp; an idempotent replay arriving afterwards cannot revive
	// it.
	ExpiresAt sql.NullTime `db:"expires_at"`
}
