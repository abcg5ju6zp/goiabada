-- OAuth 2.0 Device Authorization Grant (RFC 8628). See the sqlite migration of the same number
-- for what the clients switch and the device_codes rows mean. Every string column is pinned to
-- the case-sensitive collation per column, as every string column is.
--
-- The clients default constraint is NAMED so the down migration can drop it by name before the
-- column, for the reason 000029 gives.
ALTER TABLE [clients] ADD [device_authorization_grant_enabled] BIT NOT NULL
    CONSTRAINT [df_clients_device_authorization_grant_enabled] DEFAULT 0;

CREATE TABLE [device_codes] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] DATETIME2(6) NULL,
    [updated_at] DATETIME2(6) NULL,
    [expires_at] DATETIME2(6) NOT NULL,
    [device_code_hash] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [user_code_hash] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [client_id] BIGINT NOT NULL,
    [scope] NVARCHAR(512) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [status] NVARCHAR(16) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [consumed] BIT NOT NULL CONSTRAINT [df_device_codes_consumed] DEFAULT 0,
    [interval_seconds] INT NOT NULL,
    [last_polled_at] DATETIME2(6) NULL,
    [user_id] BIGINT NULL,
    [consented_scope] NVARCHAR(512) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL CONSTRAINT [df_device_codes_consented_scope] DEFAULT '',
    [session_identifier] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL CONSTRAINT [df_device_codes_session_identifier] DEFAULT '',
    [authenticated_at] DATETIME2(6) NULL,
    [acr_level] NVARCHAR(128) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL CONSTRAINT [df_device_codes_acr_level] DEFAULT '',
    [auth_methods] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL CONSTRAINT [df_device_codes_auth_methods] DEFAULT '',
    [auth_state_generation] BIGINT NOT NULL CONSTRAINT [df_device_codes_auth_state_generation] DEFAULT 0,
    CONSTRAINT [fk_device_codes_client] FOREIGN KEY ([client_id]) REFERENCES [clients] ([id]) ON DELETE CASCADE,
    CONSTRAINT [fk_device_codes_user] FOREIGN KEY ([user_id]) REFERENCES [users] ([id]) ON DELETE CASCADE
);
CREATE UNIQUE INDEX [idx_device_codes_device_code_hash] ON [device_codes]([device_code_hash]);
CREATE UNIQUE INDEX [idx_device_codes_user_code_hash] ON [device_codes]([user_code_hash]);
CREATE INDEX [idx_device_codes_expires_at] ON [device_codes]([expires_at]);

-- Which grant issued a refresh token, for the refresh redemption's per-grant switch. See the
-- sqlite migration: existing code-less rows are ROPC's. Named default, as the clients column is.
ALTER TABLE [refresh_tokens] ADD [grant_origin] NVARCHAR(16)
    COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL
    CONSTRAINT [df_refresh_tokens_grant_origin] DEFAULT 'authorization_code';

EXEC('UPDATE [refresh_tokens] SET [grant_origin] = ''ropc'' WHERE [code_id] IS NULL');
