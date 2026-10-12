-- RFC 9396 rich authorization requests. See the sqlite migration of the same number
-- for what the column holds and why existing rows land on the empty form.
--
-- The default constraint is NAMED deliberately: SQL Server refuses to drop a column
-- while a default constraint depends on it, so the down migration drops it by name
-- first (see 000024 for the established pattern). The column is pinned to the
-- case-sensitive collation per column like every string column here.
ALTER TABLE [codes] ADD [authorization_details] NVARCHAR(MAX)
    COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL
    CONSTRAINT [df_codes_authorization_details] DEFAULT ('[]');
