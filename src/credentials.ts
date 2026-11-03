const DAY_MS = 24 * 60 * 60 * 1000;

/** How long a credential is kept after registration if it's never used to authenticate */
const REGISTERED_CREDENTIAL_LIFETIME_MS = DAY_MS;

/** How long a credential is kept after each authentication it's used for */
const USED_CREDENTIAL_LIFETIME_MS = 30 * DAY_MS;

export interface StoredCredential {
  id: string;
  rpId: string;
  username: string;
  publicKey: string;
  signCount: number;
  isDiscoverable: boolean | null;
  deviceType: 'singleDevice' | 'multiDevice';
  backedUp: boolean;
  transports: string[] | null;
  aaguid: string;
}

interface Row {
  id: string;
  rp_id: string;
  username: string;
  public_key: string;
  sign_count: number;
  is_discoverable: number | null;
  device_type: 'singleDevice' | 'multiDevice';
  backed_up: number;
  transports: string | null;
  aaguid: string;
}

function fromRow(row: Row): StoredCredential {
  return {
    id: row.id,
    rpId: row.rp_id,
    username: row.username,
    publicKey: row.public_key,
    signCount: row.sign_count,
    isDiscoverable: row.is_discoverable === null ? null : row.is_discoverable === 1,
    deviceType: row.device_type,
    backedUp: row.backed_up === 1,
    transports: row.transports ? JSON.parse(row.transports) : null,
    aaguid: row.aaguid,
  };
}

export async function storeCredential(db: D1Database, cred: StoredCredential): Promise<void> {
  const now = Date.now();
  await db
    .prepare(
      `INSERT INTO credentials (id, rp_id, username, public_key, sign_count, is_discoverable, device_type,
         backed_up, transports, aaguid, created_at, updated_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      cred.id,
      cred.rpId,
      cred.username,
      cred.publicKey,
      cred.signCount,
      cred.isDiscoverable === null ? null : Number(cred.isDiscoverable),
      cred.deviceType,
      Number(cred.backedUp),
      cred.transports ? JSON.stringify(cred.transports) : null,
      cred.aaguid,
      now,
      now,
      now + REGISTERED_CREDENTIAL_LIFETIME_MS,
    )
    .run();
}

export async function getCredentialById(db: D1Database, rpId: string, id: string): Promise<StoredCredential | null> {
  const row = await db.prepare('SELECT * FROM credentials WHERE rp_id = ? AND id = ?').bind(rpId, id).first<Row>();
  return row ? fromRow(row) : null;
}

export async function getCredentialsByUsername(
  db: D1Database,
  rpId: string,
  username: string,
): Promise<StoredCredential[]> {
  const { results } = await db
    .prepare('SELECT * FROM credentials WHERE rp_id = ? AND username = ? ORDER BY created_at')
    .bind(rpId, username)
    .all<Row>();
  return results.map(fromRow);
}

/** Record a successful authentication, which also extends how long the credential is kept */
export async function updateSignCount(db: D1Database, id: string, signCount: number): Promise<void> {
  const now = Date.now();
  await db
    .prepare('UPDATE credentials SET sign_count = ?, updated_at = ?, expires_at = ? WHERE id = ?')
    .bind(signCount, now, now + USED_CREDENTIAL_LIFETIME_MS, id)
    .run();
}

export async function deleteCredential(db: D1Database, rpId: string, id: string, username: string): Promise<boolean> {
  const result = await db
    .prepare('DELETE FROM credentials WHERE rp_id = ? AND id = ? AND username = ?')
    .bind(rpId, id, username)
    .run();
  return result.meta.changes > 0;
}

export async function deleteExpiredCredentials(db: D1Database): Promise<void> {
  await db.prepare('DELETE FROM credentials WHERE expires_at < ?').bind(Date.now()).run();
}
