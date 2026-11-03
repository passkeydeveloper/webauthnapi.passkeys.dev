-- Credentials are scoped to the RP ID each caller passes in. Rows from before this are only ever
-- a day old, so they get an empty RP ID that no caller can use and the hourly cleanup removes
ALTER TABLE credentials ADD COLUMN rp_id TEXT NOT NULL DEFAULT '';

DROP INDEX credentials_username;
CREATE INDEX credentials_rp_id_username ON credentials (rp_id, username);
