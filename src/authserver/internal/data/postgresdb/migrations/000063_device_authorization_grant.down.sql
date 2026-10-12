-- Migration 000063 down: remove the device authorization grant.
ALTER TABLE refresh_tokens DROP COLUMN grant_origin;
DROP TABLE device_codes;
ALTER TABLE clients DROP COLUMN device_authorization_grant_enabled;
