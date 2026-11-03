import { z } from 'zod';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import { ALGORITHMS } from './algorithms';

const userVerification = z.enum(['discouraged', 'preferred', 'required']);
const hints = z.array(z.enum(['security-key', 'client-device', 'hybrid'])).default([]);
const username = z.string().min(1).max(64);

/**
 * The caller's ID for the browser session running a ceremony. Restricted to URL-safe characters
 * (UUIDs, base64url) so it can't run into the `:` separators in challenge store keys.
 */
const sessionId = z.string().regex(/^[\w-]{1,128}$/, 'Must be 1-128 letters, digits, `_` or `-`');

/** A domain, which also keeps it free of the `:` separators in challenge store keys */
const rpId = z.string().regex(/^[a-z0-9-]+(\.[a-z0-9-]+)*$/i, 'Must be a domain, without protocol').max(253);
const rpName = z.string().min(1).max(64);

/** Origins the ceremony may be completed from, compared exactly against the client data's origin */
const expectedOrigins = z
  .array(z.url().refine((url) => new URL(url).origin === url, 'Must be an origin, without a path or trailing slash'))
  .min(1);

export const registrationOptionsRequest = z.object({
  rpId,
  rpName,
  sessionId,
  username,
  userVerification: userVerification,
  attestation: z.enum(['none', 'direct']),
  attachment: z.enum(['all', 'cross_platform', 'platform']),
  algorithms: z.array(z.enum(ALGORITHMS)).default([]),
  discoverableCredential: userVerification,
  hints,
});

export const registrationVerificationRequest = z.object({
  rpId,
  expectedOrigins,
  sessionId,
  username,
  response: z.looseObject({ id: z.string() }),
});

export const authenticationOptionsRequest = z.object({
  rpId,
  sessionId,
  username: username.optional(),
  userVerification: userVerification,
  hints,
});

export const authenticationVerificationRequest = z.object({
  rpId,
  expectedOrigins,
  sessionId,
  username: username.optional(),
  response: z.looseObject({ id: z.string() }),
});

export const credentialsRequest = z.object({ rpId, username });

export const credentialRequest = z.object({ rpId, username, id: z.string().min(1) });

export type RegistrationOptionsRequest = z.infer<typeof registrationOptionsRequest>;
export type AuthenticationOptionsRequest = z.infer<typeof authenticationOptionsRequest>;

// What callers pass over RPC. Responses are typed as what the browser produces, though they're
// still validated here since they come straight from untrusted clients.
export type RegistrationOptionsInput = z.input<typeof registrationOptionsRequest>;
export type RegistrationVerificationInput = Omit<z.input<typeof registrationVerificationRequest>, 'response'> & {
  response: RegistrationResponseJSON;
};
export type AuthenticationOptionsInput = z.input<typeof authenticationOptionsRequest>;
export type AuthenticationVerificationInput = Omit<z.input<typeof authenticationVerificationRequest>, 'response'> & {
  response: AuthenticationResponseJSON;
};
export type CredentialsInput = z.input<typeof credentialsRequest>;
export type CredentialInput = z.input<typeof credentialRequest>;
