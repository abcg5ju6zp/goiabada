-- Migration 000063 down: drop the token exchange lineage table and the clients capability
-- column. Every recorded exchange and every allowance goes with them; the previous release reads
-- no such column and refuses no client for it.
DROP TABLE token_exchanges;
ALTER TABLE clients DROP COLUMN token_exchange_enabled;
