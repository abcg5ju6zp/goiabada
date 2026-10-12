-- RFC 8693 OAuth 2.0 Token Exchange. See the sqlite migration of the same number for what the
-- table and the clients column mean and for the six questions.
--
-- The per-client capability gate. Every existing client starts unable to exchange; an operator
-- switches a confidential client on. No backfill: the admin console's client does not act for
-- other parties.
ALTER TABLE clients ADD COLUMN token_exchange_enabled boolean NOT NULL DEFAULT false;

-- PostgreSQL compares strings byte-wise, so no string column needs a collation pin.
CREATE TABLE token_exchanges (
    id BIGSERIAL PRIMARY KEY,
    created_at timestamp(6) without time zone,
    updated_at timestamp(6) without time zone,
    exchange_jti character varying(64) NOT NULL,
    request_hash character varying(64) NOT NULL,
    client_id bigint NOT NULL,
    subject_user_id bigint,
    subject_token_jti character varying(64) NOT NULL,
    subject_token_type character varying(128) NOT NULL,
    actor_token_jti character varying(64) NOT NULL,
    actor_client_id bigint,
    source_refresh_token_id bigint,
    source_code_id bigint,
    session_identifier character varying(64) NOT NULL,
    scope character varying(2048) NOT NULL,
    audience character varying(2048) NOT NULL,
    issued_token_encrypted bytea,
    expires_at timestamp(6) without time zone
);

CREATE UNIQUE INDEX idx_token_exchanges_exchange_jti ON token_exchanges(exchange_jti);
CREATE UNIQUE INDEX idx_token_exchanges_request_hash ON token_exchanges(request_hash);
