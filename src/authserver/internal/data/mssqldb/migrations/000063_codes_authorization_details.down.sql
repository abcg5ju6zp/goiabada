-- Constraint before column: see the up migration for why.
ALTER TABLE [codes] DROP CONSTRAINT [df_codes_authorization_details];
ALTER TABLE [codes] DROP COLUMN [authorization_details];
