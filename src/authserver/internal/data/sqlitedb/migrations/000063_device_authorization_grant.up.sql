-- OAuth 2.0 Device Authorization Grant (RFC 8628).
--
-- clients.device_authorization_grant_enabled is the per-client switch the device authorization
-- endpoint and the device_code token grant check. Every existing client starts with it off: the
-- grant is opt-in, and an unknown client's answer is unchanged.
ALTER TABLE clients ADD COLUMN device_authorization_grant_enabled numeric NOT NULL DEFAULT 0;

-- device_codes is one device authorization from POST /auth/device until its single consumption:
--
--   * device_code_hash/user_code_hash hold only the SHA-256 digests of the two secrets. The
--     device_code is high entropy and presented by the polling device; the user_code is the
--     shorter, grouped code a person retypes at the verification page.
--   * status moves pending -> approved or pending -> denied once, by a compare-and-set in the
--     writer, so a concurrent confirmation and poll cannot disagree. consumed marks the one
--     terminal delivery (tokens, or access_denied); a second terminal poll is invalid_grant.
--   * the approval columns are zero while pending and are filled by the same statement that
--     approves, so tokens match the user, client, scope and session that were confirmed.
--   * expires_at is the active-expiry predicate every read carries; the background worker only
--     deletes rows past it and so can never remove an active authorization.
CREATE TABLE device_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME,
    updated_at DATETIME,
    expires_at DATETIME NOT NULL,
    device_code_hash TEXT NOT NULL,
    user_code_hash TEXT NOT NULL,
    client_id INTEGER NOT NULL,
    scope TEXT NOT NULL,
    status TEXT NOT NULL,
    consumed numeric NOT NULL DEFAULT 0,
    interval_seconds INTEGER NOT NULL,
    last_polled_at DATETIME,
    user_id INTEGER,
    consented_scope TEXT NOT NULL DEFAULT '',
    session_identifier TEXT NOT NULL DEFAULT '',
    authenticated_at DATETIME,
    acr_level TEXT NOT NULL DEFAULT '',
    auth_methods TEXT NOT NULL DEFAULT '',
    auth_state_generation INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT fk_device_codes_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE,
    CONSTRAINT fk_device_codes_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX idx_device_codes_device_code_hash ON device_codes(device_code_hash);
CREATE UNIQUE INDEX idx_device_codes_user_code_hash ON device_codes(user_code_hash);
CREATE INDEX idx_device_codes_expires_at ON device_codes(expires_at);

-- A refresh token records which grant issued it, so the refresh redemption gates on that
-- grant's own switch. Until now code_id IS NULL unambiguously meant the ROPC grant, which is why
-- the gate could infer the origin from code_id; a device grant issues code-less tokens too and
-- is governed by its own client switch. Existing code-less rows are ROPC's; everything else
-- descended from an authorization code.
ALTER TABLE refresh_tokens ADD COLUMN grant_origin TEXT NOT NULL DEFAULT 'authorization_code';
UPDATE refresh_tokens SET grant_origin = 'ropc' WHERE code_id IS NULL;
