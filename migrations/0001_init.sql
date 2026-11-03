CREATE TABLE credentials (
  id TEXT PRIMARY KEY,
  rp_id TEXT NOT NULL,
  username TEXT NOT NULL,
  public_key TEXT NOT NULL,
  sign_count INTEGER NOT NULL,
  is_discoverable INTEGER,
  device_type TEXT NOT NULL,
  backed_up INTEGER NOT NULL,
  transports TEXT,
  aaguid TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX credentials_rp_id_username ON credentials (rp_id, username);
CREATE INDEX credentials_expires_at ON credentials (expires_at);
