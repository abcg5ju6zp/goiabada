-- RFC 9396 rich authorization requests (#rich-authorization).
--
-- codes.authorization_details stores the immutable, canonical JSON snapshot of the
-- authorization_details set the user saw and ticked at the consent screen. The token
-- endpoint re-validates it against current resources, client license and user grants
-- and copies it into the access token's authorization_details claim.
--
-- "[]" is the empty form: every code writes the column, and existing rows (all expired,
-- single-use codes) land on a scope-only grant without a backfill.
ALTER TABLE codes ADD COLUMN authorization_details TEXT NOT NULL DEFAULT '[]';
