-- RFC 9396 rich authorization requests. See the sqlite migration of the same number
-- for what the column holds and why existing rows land on the empty form.
--
-- LONGTEXT, like authorize_requests.request_form and audit_logs.details: a canonical
-- detail set is unbounded in practice and must not share a length ceiling. The default
-- is an expression ('[]') because MySQL refuses a literal default on a LONGTEXT column;
-- the column is pinned to the case-sensitive collation every table here carries.
ALTER TABLE `codes`
    ADD COLUMN `authorization_details` LONGTEXT COLLATE utf8mb4_0900_as_cs NOT NULL DEFAULT ('[]');
