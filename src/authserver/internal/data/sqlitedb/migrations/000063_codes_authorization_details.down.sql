-- Reverses migration 000063: codes stop carrying the authorization_details snapshot.
-- Outstanding codes are at most sixty seconds old and one-time, so nothing in flight is
-- lost beyond the detail set.
ALTER TABLE codes DROP COLUMN authorization_details;
