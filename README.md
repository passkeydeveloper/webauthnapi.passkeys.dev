# passkeys.dev WebAuthn API

A WebAuthn registration and authentication service for tools hosted on passkeys.dev. It is a [Cloudflare Worker](https://developers.cloudflare.com/workers/) built with [@simplewebauthn/server](https://simplewebauthn.dev), using D1 for credentials and a Durable Object for single-use challenges.

The Worker has no public routes. Other Workers on the same account call it over [RPC](https://developers.cloudflare.com/workers/runtime-apis/rpc/) through a [service binding](https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/), so the binding itself is the access control.

## Development

Requires Node.js 24+ (a [mise](https://mise.jdx.dev) config is included).

```bash
npm install
npx wrangler d1 migrations apply DB --local     # first run only
npm run dev
```

```bash
npm test             # Vitest, run inside the Workers runtime
npm run typecheck
```

While `npm run dev` is running, a calling Worker's own `wrangler dev` connects its service binding to this one through Wrangler's local dev registry.

## Calling the API

Add a binding in the calling Worker's Wrangler config:

```jsonc
"services": [{ "binding": "WEBAUTHN", "service": "webauthnapi-passkeys-dev" }]
```

Then call methods on it, typed as `Service<WebAuthnApi>` with the default export of `src/index.ts`:

```ts
const result = await env.WEBAUTHN.createAuthenticationOptions({ rpId: 'tools.passkeys.dev', sessionId, userVerification: 'preferred' });
if (!result.ok) return Response.json(result, { status: 400 });
return Response.json(result.value);
```

Each caller passes its relying party configuration to the methods that need it: `rpId` to all of them, `rpName` to `createRegistrationOptions`, and `expectedOrigins` (exact origins such as `https://tools.passkeys.dev`, which ceremonies may be completed from) to the two verification methods. Credentials are stored per RP ID, so callers with different RP IDs never see each other's credentials.

The calling Worker owns its users' sessions. Every ceremony method takes the caller's `sessionId` (1–128 letters, digits, `_` or `-`, e.g. a UUID), which ties the challenge to the browser that started the ceremony. A successful `verifyAuthenticationResponse` returns `{ username, credentialId }` for the caller to log the user in with.

Expected failures, such as invalid input or a response that doesn't verify, are returned as `{ ok: false, error, fieldErrors? }` rather than thrown. Successes are `{ ok: true, value }`.

| Method | Description |
| --- | --- |
| `getRuntimeCapabilities()` | `{ algorithms }` the runtime can verify (ML-DSA isn't supported by Workers yet) |
| `createRegistrationOptions({ rpId, rpName, sessionId, username, ... })` | Generate registration options |
| `verifyRegistrationResponse({ rpId, expectedOrigins, sessionId, username, response })` | Verify a registration response and store the credential |
| `createAuthenticationOptions({ rpId, sessionId, username?, ... })` | Generate authentication options (omit `username` for conditional UI) |
| `verifyAuthenticationResponse({ rpId, expectedOrigins, sessionId, username?, response })` | Verify an authentication response |
| `getCredentials({ rpId, username })` | A user's credentials, with provider name and public key details |
| `deleteCredential({ rpId, username, id })` | Delete one of a user's credentials |

## Deploying

The `d1_databases` entry in `wrangler.jsonc` has a placeholder `database_id`; create a database with `wrangler d1 create` before deploying. Credentials are deleted 24 hours after registration if they're never used, or 30 days after the last authentication they were used for, by an hourly cron trigger.
