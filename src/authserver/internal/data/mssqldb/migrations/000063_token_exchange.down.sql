-- Migration 000063 down: drop the token exchange lineage table and the clients capability
-- column. Every recorded exchange and every allowance goes with them. Constraint before column,
-- for the reason the up migration gives.
DROP TABLE [token_exchanges];
ALTER TABLE [clients] DROP CONSTRAINT [df_clients_token_exchange_enabled];
ALTER TABLE [clients] DROP COLUMN [token_exchange_enabled];
