-- RFC 8693 OAuth 2.0 Token Exchange. See the sqlite migration of the same number for what the
-- table and the clients column mean and for the six questions.
--
-- The per-client capability gate. Every existing client starts unable to exchange; an operator
-- switches a confidential client on. No backfill. The default constraint is named so the down
-- migration can drop it by name first, for the reason 000029 gives.
ALTER TABLE [clients] ADD [token_exchange_enabled] BIT NOT NULL
    CONSTRAINT [df_clients_token_exchange_enabled] DEFAULT 0;

-- Every string column is pinned to the case-sensitive collation per column (#283), so the two
-- unique keys compare a jti and a hash byte for byte.
CREATE TABLE [token_exchanges] (
    [id] BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
    [created_at] DATETIME2(6),
    [updated_at] DATETIME2(6),
    [exchange_jti] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [request_hash] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [client_id] BIGINT NOT NULL,
    [subject_user_id] BIGINT,
    [subject_token_jti] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [subject_token_type] NVARCHAR(128) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [actor_token_jti] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [actor_client_id] BIGINT,
    [source_refresh_token_id] BIGINT,
    [source_code_id] BIGINT,
    [session_identifier] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [scope] NVARCHAR(2048) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [audience] NVARCHAR(2048) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [issued_token_encrypted] VARBINARY(MAX),
    [expires_at] DATETIME2(6)
);

CREATE UNIQUE INDEX [idx_token_exchanges_exchange_jti] ON [token_exchanges]([exchange_jti]);
CREATE UNIQUE INDEX [idx_token_exchanges_request_hash] ON [token_exchanges]([request_hash]);
