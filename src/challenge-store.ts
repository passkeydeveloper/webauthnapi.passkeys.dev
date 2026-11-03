import { DurableObject } from 'cloudflare:workers';

/**
 * Single-use challenge storage. One object instance per key (RP ID, the caller's session ID and,
 * for registration, the username), so `take` is atomic and a challenge can never be replayed.
 */
export class ChallengeStore extends DurableObject {
  async put(options: unknown, ttlMs: number): Promise<void> {
    const expiresAt = Date.now() + ttlMs;
    await this.ctx.storage.put({ options, expiresAt });
    await this.ctx.storage.setAlarm(expiresAt);
  }

  /**
   * Expiry is checked here as well as by the alarm, since alarms can run late or be retried and
   * a challenge shouldn't be usable past its TTL
   */
  async take(): Promise<unknown> {
    const stored = await this.ctx.storage.get<unknown>(['options', 'expiresAt']);
    await this.ctx.storage.deleteAll();
    await this.ctx.storage.deleteAlarm();

    const expiresAt = stored.get('expiresAt') as number | undefined;
    return expiresAt !== undefined && expiresAt > Date.now() ? stored.get('options') : undefined;
  }

  async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }
}
