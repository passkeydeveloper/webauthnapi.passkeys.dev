import { WorkerEntrypoint } from 'cloudflare:workers';
import type { ZodError } from 'zod';
import { getProviderName } from './aaguids';
import { supportedAlgorithms, type Algorithm } from './algorithms';
import { ChallengeStore } from './challenge-store';
import {
  MAX_CREDENTIALS_PER_USERNAME,
  countCredentialsByUsername,
  deleteCredential,
  deleteExpiredCredentials,
  getCredentialById,
  getCredentialsByUsername,
  storeCredential,
  updateSignCount,
  type StoredCredential,
} from './credentials';
import type { Env } from './env';
import { describePublicKey, type PublicKeyInfo } from './public-key';
import {
  authenticationOptionsRequest,
  authenticationVerificationRequest,
  credentialRequest,
  credentialsRequest,
  registrationOptionsRequest,
  registrationVerificationRequest,
  type CreateAuthenticationOptionsInput,
  type CreateRegistrationOptionsInput,
  type DeleteCredentialInput,
  type GetCredentialsInput,
  type VerifyAuthenticationResponseInput,
  type VerifyRegistrationResponseInput,
} from './schemas';
import {
  CHALLENGE_TTL_MS,
  UnsupportedAlgorithmError,
  buildAuthenticationOptions,
  buildRegistrationOptions,
  verifyAuthentication,
  verifyRegistration,
  type AuthenticationOptionsJSON,
  type RegistrationOptionsJSON,
  type StoredAuthenticationOptions,
  type StoredRegistrationOptions,
} from './webauthn';

export { ChallengeStore };

export type * from './schemas';
export type { AuthenticationOptionsJSON, RegistrationOptionsJSON };

/** An expected failure, such as invalid input or a response that doesn't verify */
export interface Failure {
  ok: false;
  error: string;
  /** Validation messages keyed by the path of the offending input field */
  fieldErrors?: Record<string, string[]>;
}

export type Result<T> = { ok: true; value: T } | Failure;

export interface CredentialDetails extends Omit<StoredCredential, 'publicKey'> {
  providerName: string | null;
  publicKey: PublicKeyInfo;
}

function invalid(error: ZodError): Failure {
  const fieldErrors: Record<string, string[]> = {};
  for (const issue of error.issues) {
    const key = issue.path.join('.') || 'request';
    (fieldErrors[key] ??= []).push(issue.message);
  }
  return { ok: false, error: 'Invalid request', fieldErrors };
}

/**
 * A response that didn't verify. Only WebAuthn verification errors are reported this way; anything
 * else (e.g. a database error) is thrown so the caller and the Worker's logs see a real exception.
 */
function failed(err: unknown): Failure {
  return { ok: false, error: (err as Error).message };
}

const tooManyCredentials: Failure = {
  ok: false,
  error: `That username already has the maximum of ${MAX_CREDENTIALS_PER_USERNAME} credentials`,
};

/**
 * The WebAuthn API, called by other Workers through an RPC service binding. It has no public
 * routes, so the binding is the access control.
 *
 * Every method takes the caller's relying party ID, and credentials are kept separately per RP ID.
 * Callers own their users' sessions: each ceremony takes the caller's session ID so its challenge
 * can only be completed by the browser that started it, and a successful authentication returns
 * the username for the caller to log in however it sees fit.
 */
export default class WebAuthnApi extends WorkerEntrypoint<Env> {
  /** The algorithms this runtime can verify (ML-DSA isn't supported by Workers yet) */
  async getRuntimeCapabilities(): Promise<{ algorithms: Algorithm[] }> {
    return { algorithms: await supportedAlgorithms() };
  }

  async createRegistrationOptions(input: CreateRegistrationOptionsInput): Promise<Result<RegistrationOptionsJSON>> {
    const parsed = registrationOptionsRequest.safeParse(input);
    if (!parsed.success) return invalid(parsed.error);
    const req = parsed.data;

    const existing = await getCredentialsByUsername(this.env.DB, req.rpId, req.username);
    if (existing.length >= MAX_CREDENTIALS_PER_USERNAME) {
      return tooManyCredentials;
    }

    let built;
    try {
      built = await buildRegistrationOptions(req, existing);
    } catch (err) {
      if (err instanceof UnsupportedAlgorithmError) {
        return { ok: false, error: 'Invalid request', fieldErrors: { algorithms: [err.message] } };
      }
      throw err;
    }

    await this.#challenges(`reg:${req.rpId}:${req.sessionId}:${req.username}`).put(built.stored, CHALLENGE_TTL_MS);

    return { ok: true, value: built.options };
  }

  async verifyRegistrationResponse(input: VerifyRegistrationResponseInput): Promise<Result<{ credentialId: string }>> {
    const parsed = registrationVerificationRequest.safeParse(input);
    if (!parsed.success) return invalid(parsed.error);
    const req = parsed.data;

    const stored = await this.#challenges(`reg:${req.rpId}:${req.sessionId}:${req.username}`).take() as StoredRegistrationOptions | undefined;
    if (!stored) {
      return { ok: false, error: `no options for user ${req.username}` };
    }

    let credential: StoredCredential;
    try {
      credential = await verifyRegistration(req, req.response as never, req.username, stored);
    } catch (err) {
      return failed(err);
    }

    // Checked again since several registrations for the same username can be in flight at once
    if ((await countCredentialsByUsername(this.env.DB, req.rpId, req.username)) >= MAX_CREDENTIALS_PER_USERNAME) {
      return tooManyCredentials;
    }
    if (!(await storeCredential(this.env.DB, credential))) {
      return { ok: false, error: 'Credential already registered' };
    }

    return { ok: true, value: { credentialId: credential.id } };
  }

  /** Omit `username` for conditional UI */
  async createAuthenticationOptions(input: CreateAuthenticationOptionsInput): Promise<Result<AuthenticationOptionsJSON>> {
    const parsed = authenticationOptionsRequest.safeParse(input);
    if (!parsed.success) return invalid(parsed.error);
    const req = parsed.data;

    let existing: StoredCredential[] = [];
    if (req.username) {
      existing = await getCredentialsByUsername(this.env.DB, req.rpId, req.username);
      if (existing.length === 0) {
        return { ok: false, error: 'That username has no registered credentials' };
      }
    }

    const { options, stored } = await buildAuthenticationOptions(req, existing);

    await this.#challenges(`auth:${req.rpId}:${req.sessionId}`).put(stored, CHALLENGE_TTL_MS);

    return { ok: true, value: options };
  }

  async verifyAuthenticationResponse(
    input: VerifyAuthenticationResponseInput,
  ): Promise<Result<{ username: string; credentialId: string }>> {
    const parsed = authenticationVerificationRequest.safeParse(input);
    if (!parsed.success) return invalid(parsed.error);
    const req = parsed.data;

    const stored = await this.#challenges(`auth:${req.rpId}:${req.sessionId}`).take() as StoredAuthenticationOptions | undefined;
    if (!stored) {
      return { ok: false, error: 'no options for this session' };
    }

    const credential = await getCredentialById(this.env.DB, req.rpId, req.response.id);
    if (!credential) {
      return { ok: false, error: 'Unrecognized credential ID' };
    }
    if (req.username && credential.username !== req.username) {
      return { ok: false, error: 'Credential does not belong to user' };
    }

    let newCounter: number;
    try {
      newCounter = await verifyAuthentication(req, req.response as never, credential, stored);
    } catch (err) {
      return failed(err);
    }
    await updateSignCount(this.env.DB, credential.id, newCounter);

    return { ok: true, value: { username: credential.username, credentialId: credential.id } };
  }

  /** A user's credentials, with provider name and public key details */
  async getCredentials(input: GetCredentialsInput): Promise<Result<CredentialDetails[]>> {
    const parsed = credentialsRequest.safeParse(input);
    if (!parsed.success) return invalid(parsed.error);

    const credentials = await getCredentialsByUsername(this.env.DB, parsed.data.rpId, parsed.data.username);
    return {
      ok: true,
      value: credentials.map(({ publicKey, ...cred }) => ({
        ...cred,
        providerName: getProviderName(cred.aaguid, cred.deviceType),
        publicKey: describePublicKey(publicKey),
      })),
    };
  }

  async deleteCredential(input: DeleteCredentialInput): Promise<Result<{ deleted: true }>> {
    const parsed = credentialRequest.safeParse(input);
    if (!parsed.success) return invalid(parsed.error);

    const deleted = await deleteCredential(this.env.DB, parsed.data.rpId, parsed.data.id, parsed.data.username);
    if (!deleted) {
      return { ok: false, error: 'Unrecognized credential ID' };
    }
    return { ok: true, value: { deleted: true } };
  }

  async scheduled(): Promise<void> {
    await deleteExpiredCredentials(this.env.DB);
  }

  #challenges(key: string) {
    return this.env.CHALLENGES.getByName(key);
  }
}
