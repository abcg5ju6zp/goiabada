-- OAuth 2.0 Device Authorization Grant (RFC 8628). See the sqlite migration of the same number
-- for what the clients switch and the device_codes rows mean. The table is pinned to the
-- case- and accent-sensitive collation every table here carries, so the unique indexes over the
-- two code digests mean what they say.
ALTER TABLE `clients` ADD COLUMN `device_authorization_grant_enabled` tinyint(1) NOT NULL DEFAULT 0;

CREATE TABLE `device_codes` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `created_at` datetime(6) DEFAULT NULL,
    `updated_at` datetime(6) DEFAULT NULL,
    `expires_at` datetime(6) NOT NULL,
    `device_code_hash` varchar(64) NOT NULL,
    `user_code_hash` varchar(64) NOT NULL,
    `client_id` BIGINT UNSIGNED NOT NULL,
    `scope` varchar(512) NOT NULL,
    `status` varchar(16) NOT NULL,
    `consumed` tinyint(1) NOT NULL DEFAULT 0,
    `interval_seconds` INT NOT NULL,
    `last_polled_at` datetime(6) DEFAULT NULL,
    `user_id` BIGINT UNSIGNED NULL,
    `consented_scope` varchar(512) NOT NULL DEFAULT '',
    `session_identifier` varchar(64) NOT NULL DEFAULT '',
    `authenticated_at` datetime(6) DEFAULT NULL,
    `acr_level` varchar(128) NOT NULL DEFAULT '',
    `auth_methods` varchar(64) NOT NULL DEFAULT '',
    `auth_state_generation` BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`id`),
    UNIQUE KEY `idx_device_codes_device_code_hash` (`device_code_hash`),
    UNIQUE KEY `idx_device_codes_user_code_hash` (`user_code_hash`),
    KEY `idx_device_codes_expires_at` (`expires_at`),
    CONSTRAINT `fk_device_codes_client` FOREIGN KEY (`client_id`) REFERENCES `clients` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_device_codes_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;

-- Which grant issued a refresh token, for the refresh redemption's per-grant switch. See the
-- sqlite migration: existing code-less rows are ROPC's.
ALTER TABLE `refresh_tokens` ADD COLUMN `grant_origin` varchar(32) NOT NULL DEFAULT 'authorization_code';
UPDATE `refresh_tokens` SET `grant_origin` = 'ropc' WHERE `code_id` IS NULL;
