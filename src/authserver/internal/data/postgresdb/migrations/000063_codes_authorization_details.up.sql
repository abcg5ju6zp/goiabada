-- RFC 9396 rich authorization requests. See the sqlite migration of the same number
-- for what the column holds and why existing rows land on the empty form. PostgreSQL
-- compares strings byte-wise, so a TEXT column needs no collation pin.
ALTER TABLE codes ADD COLUMN authorization_details TEXT NOT NULL DEFAULT '[]';
