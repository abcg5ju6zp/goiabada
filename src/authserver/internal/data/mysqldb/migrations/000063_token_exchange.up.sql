-- RFC 8693 OAuth 2.0 Token Exchange. See the sqlite migration of the same number for what the
-- table and the clients column mean and for the six questions.
--
-- The per-client capability gate. Every existing client starts unable to exchange; an operator
-- switches a confidential client on. No backfill.
ALTER TABLE `clients` ADD COLUMN `token_exchange_enabled` tinyint(1) NOT NULL DEFAULT 0;

-- Every string column is pinned to the case- and accent-sensitive collation every table here
-- carries (#283): the two unique keys compare a jti and a hash byte for byte.
CREATE TABLE `token_exchanges` (
    `id` bigint unsigned NOT NULL AUTO_INCREMENT,
    `created_at` datetime(6),
    `updated_at` datetime(6),
    `exchange_jti` varchar(64) NOT NULL,
    `request_hash` varchar(64) NOT NULL,
    `client_id` bigint unsigned NOT NULL,
    `subject_user_id` bigint unsigned,
    `subject_token_jti` varchar(64) NOT NULL,
    `subject_token_type` varchar(128) NOT NULL,
    `actor_token_jti` varchar(64) NOT NULL DEFAULT '',
    `actor_client_id` bigint unsigned,
    `source_refresh_token_id` bigint unsigned,
    `source_code_id` bigint unsigned,
    `session_identifier` varchar(64) NOT NULL DEFAULT '',
    `scope` varchar(2048) NOT NULL,
    `audience` varchar(2048) NOT NULL,
    `issued_token_encrypted` longblob,
    `expires_at` datetime(6),
    PRIMARY KEY (`id`),
    UNIQUE KEY `idx_token_exchanges_exchange_jti` (`exchange_jti`),
    UNIQUE KEY `idx_token_exchanges_request_hash` (`request_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;
