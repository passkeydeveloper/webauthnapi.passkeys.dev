-- Credentials now expire a day after registration, or 30 days after their latest authentication.
-- Existing rows keep the day-after-last-use expiry they had before.
ALTER TABLE credentials ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0;
UPDATE credentials SET expires_at = updated_at + 86400000;

DROP INDEX credentials_updated_at;
CREATE INDEX credentials_expires_at ON credentials (expires_at);
