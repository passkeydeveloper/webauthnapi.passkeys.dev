import type { ChallengeStore } from './challenge-store';

export interface Env {
  DB: D1Database;
  CHALLENGES: DurableObjectNamespace<ChallengeStore>;
}
