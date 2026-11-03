import { WorkerEntrypoint } from 'cloudflare:workers';
import type { ZodError } from 'zod';
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/server';
import { getProviderName } from './aaguids';
import { supportedAlgorithms, type Algorithm } from './algorithms';
import { ChallengeStore } from './challenge-store';
import {
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
  type AuthenticationOptionsInput,
  type AuthenticationVerificationInput,
  type CredentialInput,
  type CredentialsInput,
  type RegistrationOptionsInput,
  type RegistrationVerificationInput,
} from './schemas';
import {
  CHALLENGE_TTL_MS,
  UnsupportedAlgorithmError,
  buildAuthenticationOptions,
  buildRegistrationOptions,
  verifyAuthentication,
  verifyRegistration,
  type StoredAuthenticationOptions,
  type StoredRegistrationOptions,
} from './webauthn';

export { ChallengeStore };

const CREDENTIAL_LIFETIME_MS = 24 * 60 * 60 * 1000;
export type * from './schemas';

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

function failed(err: unknown): Failure {
  return { ok: false, error: (err as Error).message };
}

/**
 * The WebAuthn API, called by other Workers through an RPC service binding. It has no public
 * routes, so the binding is the access control.
 *
 * Callers own their users' sessions: each ceremony takes the caller's session ID so its challenge
 * can only be completed by the browser that started it, and a successful authentication returns
 * the username for the caller to log in however it sees fit.
 */
export default class WebAuthnApi extends WorkerEntrypoint<Env> {
  /** The algorithms this runtime can verify (ML-DSA isn't supported by Workers yet) */
  async capabilities(): Promise<{ algorithms: Algorithm[] }> {
    return { algorithms: await supportedAlgorithms() };
  }

  async registrationOptions(input: RegistrationOptionsInput): Promise<Result<PublicKeyCredentialCreationOptionsJSON>> {
    const parsed = registrationOptionsRequest.safeParse(input);
    if (!parsed.success) return invalid(parsed.error);
    const req = parsed.data;

    const existing = await getCredentialsByUsername(this.env.DB, req.username);

    let built;
    try {
      built = await buildRegistrationOptions(this.env, req, existing);
    } catch (err) {
      if (err instanceof UnsupportedAlgorithmError) {
        return { ok: false, error: 'Invalid request', fieldErrors: { algorithms: [err.message] } };
      }
      throw err;
    }

    await this.#challenges(`reg:${req.sessionId}:${req.username}`).put(built.stored, CHALLENGE_TTL_MS);

    return { ok: true, value: built.options };
  }

  async registrationVerification(input: RegistrationVerificationInput): Promise<Result<{ credentialId: string }>> {
    const parsed = registrationVerificationRequest.safeParse(input);
    if (!parsed.success) return invalid(parsed.error);
    const req = parsed.data;

    const stored = await this.#challenges(`reg:${req.sessionId}:${req.username}`).take() as StoredRegistrationOptions | undefined;
    if (!stored) {
      return { ok: false, error: `no options for user ${req.username}` };
    }

    try {
      const credential = await verifyRegistration(this.env, req.response as never, req.username, stored);
      await storeCredential(this.env.DB, credential);
      return { ok: true, value: { credentialId: credential.id } };
    } catch (err) {
      return failed(err);
    }
  }

  /** Omit `username` for conditional UI */
  async authenticationOptions(input: AuthenticationOptionsInput): Promise<Result<PublicKeyCredentialRequestOptionsJSON>> {
    const parsed = authenticationOptionsRequest.safeParse(input);
    if (!parsed.success) return invalid(parsed.error);
    const req = parsed.data;

    let existing: StoredCredential[] = [];
    if (req.username) {
      existing = await getCredentialsByUsername(this.env.DB, req.username);
      if (existing.length === 0) {
        return { ok: false, error: 'That username has no registered credentials' };
      }
    }

    const { options, stored } = await buildAuthenticationOptions(this.env, req, existing);

    await this.#challenges(`auth:${req.sessionId}`).put(stored, CHALLENGE_TTL_MS);

    return { ok: true, value: options };
  }

  async authenticationVerification(
    input: AuthenticationVerificationInput,
  ): Promise<Result<{ username: string; credentialId: string }>> {
    const parsed = authenticationVerificationRequest.safeParse(input);
    if (!parsed.success) return invalid(parsed.error);
    const req = parsed.data;

    const stored = await this.#challenges(`auth:${req.sessionId}`).take() as StoredAuthenticationOptions | undefined;
    if (!stored) {
      return { ok: false, error: 'no options for this session' };
    }

    try {
      const credential = await getCredentialById(this.env.DB, req.response.id);
      if (!credential) {
        throw new Error('Unrecognized credential ID');
      }
      if (req.username && credential.username !== req.username) {
        throw new Error('Credential does not belong to user');
      }

      const newCounter = await verifyAuthentication(this.env, req.response as never, credential, stored);
      await updateSignCount(this.env.DB, credential.id, newCounter);

      return { ok: true, value: { username: credential.username, credentialId: credential.id } };
    } catch (err) {
      return failed(err);
    }
  }

  /** A user's credentials, with provider name and public key details */
  async credentials(input: CredentialsInput): Promise<Result<CredentialDetails[]>> {
    const parsed = credentialsRequest.safeParse(input);
    if (!parsed.success) return invalid(parsed.error);

    const credentials = await getCredentialsByUsername(this.env.DB, parsed.data.username);
    return {
      ok: true,
      value: credentials.map(({ publicKey, ...cred }) => ({
        ...cred,
        providerName: getProviderName(cred.aaguid, cred.deviceType),
        publicKey: describePublicKey(publicKey),
      })),
    };
  }

  async deleteCredential(input: CredentialInput): Promise<Result<{ deleted: true }>> {
    const parsed = credentialRequest.safeParse(input);
    if (!parsed.success) return invalid(parsed.error);

    const deleted = await deleteCredential(this.env.DB, parsed.data.id, parsed.data.username);
    if (!deleted) {
      return { ok: false, error: 'Unrecognized credential ID' };
    }
    return { ok: true, value: { deleted: true } };
  }

  async scheduled(): Promise<void> {
    await deleteExpiredCredentials(this.env.DB, CREDENTIAL_LIFETIME_MS);
  }

  #challenges(key: string) {
    return this.env.CHALLENGES.getByName(key);
  }
}
