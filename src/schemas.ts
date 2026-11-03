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

export const registrationOptionsRequest = z.object({
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
  sessionId,
  username,
  response: z.looseObject({ id: z.string() }),
});

export const authenticationOptionsRequest = z.object({
  sessionId,
  username: username.optional(),
  userVerification: userVerification,
  hints,
});

export const authenticationVerificationRequest = z.object({
  sessionId,
  username: username.optional(),
  response: z.looseObject({ id: z.string() }),
});

export const credentialsRequest = z.object({ username });

export const credentialRequest = z.object({ username, id: z.string().min(1) });

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
