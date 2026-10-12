-- Migration 000063 down: remove the device authorization grant. Every outstanding device
-- authorization goes with the table, and every client's switch with the column.
ALTER TABLE refresh_tokens DROP COLUMN grant_origin;
DROP TABLE device_codes;
ALTER TABLE clients DROP COLUMN device_authorization_grant_enabled;
