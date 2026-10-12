-- OAuth 2.0 Device Authorization Grant (RFC 8628). See the sqlite migration of the same number
-- for what the clients switch and the device_codes rows mean.
ALTER TABLE clients ADD COLUMN device_authorization_grant_enabled boolean NOT NULL DEFAULT false;

CREATE TABLE device_codes (
    id BIGSERIAL PRIMARY KEY,
    created_at timestamp(6) without time zone,
    updated_at timestamp(6) without time zone,
    expires_at timestamp(6) without time zone NOT NULL,
    device_code_hash character varying(64) NOT NULL,
    user_code_hash character varying(64) NOT NULL,
    client_id BIGINT NOT NULL,
    scope character varying(512) NOT NULL,
    status character varying(16) NOT NULL,
    consumed boolean NOT NULL DEFAULT false,
    interval_seconds INTEGER NOT NULL,
    last_polled_at timestamp(6) without time zone,
    user_id BIGINT,
    consented_scope character varying(512) NOT NULL DEFAULT '',
    session_identifier character varying(64) NOT NULL DEFAULT '',
    authenticated_at timestamp(6) without time zone,
    acr_level character varying(128) NOT NULL DEFAULT '',
    auth_methods character varying(64) NOT NULL DEFAULT '',
    auth_state_generation BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT fk_device_codes_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE,
    CONSTRAINT fk_device_codes_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX idx_device_codes_device_code_hash ON device_codes(device_code_hash);
CREATE UNIQUE INDEX idx_device_codes_user_code_hash ON device_codes(user_code_hash);
CREATE INDEX idx_device_codes_expires_at ON device_codes(expires_at);

-- Which grant issued a refresh token, for the refresh redemption's per-grant switch. See the
-- sqlite migration: existing code-less rows are ROPC's.
ALTER TABLE refresh_tokens ADD COLUMN grant_origin character varying(32) NOT NULL DEFAULT 'authorization_code';
UPDATE refresh_tokens SET grant_origin = 'ropc' WHERE code_id IS NULL;
