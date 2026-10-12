-- Migration 000063 down: drop the token exchange lineage table and the clients capability
-- column. Every recorded exchange and every allowance goes with them.
DROP TABLE `token_exchanges`;
ALTER TABLE `clients` DROP COLUMN `token_exchange_enabled`;
