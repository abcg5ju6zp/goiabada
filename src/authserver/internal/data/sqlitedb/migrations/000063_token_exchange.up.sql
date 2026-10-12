-- RFC 8693 OAuth 2.0 Token Exchange: the per-client capability gate and the exchange lineage
-- table.
--
-- A backend service calling a downstream API on a user's behalf presents the user's token (or a
-- refresh token) as subject_token to the token endpoint, optionally authenticates the acting
-- party with an actor_token, and receives one down-scoped access token whose audience and scopes
-- are the intersection of the subject's authorization, the actor's permissions, the client's
-- permissions and the resource policy. token_exchanges is the durable record of who exchanged
-- what for whom, and of the grant, session and client the issued token descends from.
--
-- It carries three responsibilities at once, each visible in its columns:
--
-- (1) Lineage. client_id is the authenticated confidential client that requested the exchange;
-- subject_user_id, subject_token_jti and subject_token_type name the presented grant;
-- source_refresh_token_id and source_code_id pin the source grant when the subject was a refresh
-- token; session_identifier carries the source browser session when there was one. The bearer
-- session guard walks this row, so a disabled client, a terminated session, an advanced
-- authentication generation or a revoked code or refresh token invalidates every token descended
-- here. No foreign keys are declared, as in 000054: the guard fails closed on a missing parent,
-- and a user, client or code deletion must not block an exchange record's cleanup.
--
-- (2) Idempotency. request_hash is the SHA-256 of the canonical request (client, subject token,
-- actor token, audience, resource, scope, requested token type) and is unique. An uncertain
-- response, a retried submission or two concurrent identical exchanges find the row the first
-- committed and return the SAME stored token (issued_token_encrypted, decrypted with the data
-- cipher), so one logical exchange mints one token and builds one lineage, never two conflicting
-- ones. exchange_jti, the issued token's jti, is the reverse handle and is unique too.
--
-- (3) Audit. scope and audience are exactly the intersection the issued token carries, so the row
-- answers what was delegated to whom without decoding the stored token; expires_at bounds replays.
--
-- The clients column is the gate: token_exchange_enabled is false for every existing client, and
-- a client is permitted only once an operator switches a confidential client on. The down
-- migration drops the table and the column together.
ALTER TABLE clients ADD COLUMN token_exchange_enabled numeric NOT NULL DEFAULT 0;

CREATE TABLE token_exchanges (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME,
    updated_at DATETIME,
    exchange_jti TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    client_id INTEGER NOT NULL,
    subject_user_id INTEGER,
    subject_token_jti TEXT NOT NULL,
    subject_token_type TEXT NOT NULL,
    actor_token_jti TEXT NOT NULL,
    actor_client_id INTEGER,
    source_refresh_token_id INTEGER,
    source_code_id INTEGER,
    session_identifier TEXT NOT NULL,
    scope TEXT NOT NULL,
    audience TEXT NOT NULL,
    issued_token_encrypted BLOB,
    expires_at DATETIME
);

CREATE UNIQUE INDEX idx_token_exchanges_exchange_jti ON token_exchanges(exchange_jti);
CREATE UNIQUE INDEX idx_token_exchanges_request_hash ON token_exchanges(request_hash);
