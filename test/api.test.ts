import { env } from 'cloudflare:test';
import { exports } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import type WebAuthnApi from '../src/index';
import type { AuthenticationOptionsInput, RegistrationOptionsInput, Result } from '../src/index';
import { VirtualAuthenticator } from './virtual-authenticator';

const registrationRequest: Omit<RegistrationOptionsInput, 'sessionId'> = {
  username: 'alice',
  userVerification: 'preferred',
  attestation: 'none',
  attachment: 'all',
  algorithms: ['es256'],
  discoverableCredential: 'preferred',
  hints: [],
};

const authenticationRequest: Omit<AuthenticationOptionsInput, 'sessionId'> = { userVerification: 'preferred', hints: [] };

const api = exports.default as unknown as Service<WebAuthnApi>;

/** Values from a successful result, failing the test otherwise */
function ok<T>(result: Result<T>): T {
  if (!result.ok) throw new Error(`Expected success, got ${JSON.stringify(result)}`);
  return result.value;
}

async function register(sessionId: string, authenticator: VirtualAuthenticator, overrides = {}, registrationOptions = {}) {
  const options = ok(await api.registrationOptions({ sessionId, ...registrationRequest, ...overrides }));
  const response = await authenticator.register(options, registrationOptions);
  return api.registrationVerification({ sessionId, username: 'alice', response });
}

beforeEach(async () => {
  await env.DB.exec('DELETE FROM credentials');
});

describe('registration', () => {
  it('generates options honoring the request', async () => {
    const options = ok(await api.registrationOptions({
      sessionId: 's1',
      ...registrationRequest,
      algorithms: ['rs256', 'es256'],
      attachment: 'platform',
      hints: ['hybrid'],
      discoverableCredential: 'required',
    }));

    expect(options.pubKeyCredParams.map((p) => p.alg)).toEqual([-257, -7]);
    expect(options.authenticatorSelection).toMatchObject({
      authenticatorAttachment: 'platform',
      residentKey: 'required',
    });
    expect(options.hints).toEqual(['hybrid']);
    expect(options.extensions).toEqual({ credProps: true });
  });

  it('sends an empty pubKeyCredParams when no algorithms are selected', async () => {
    const options = ok(await api.registrationOptions({ sessionId: 's1', ...registrationRequest, algorithms: [] }));
    expect(options.pubKeyCredParams).toEqual([]);
  });

  it('rejects invalid requests and algorithms the runtime cannot verify', async () => {
    const invalid = await api.registrationOptions({ sessionId: 's1', ...registrationRequest, username: '' });
    expect(invalid).toMatchObject({ ok: false, fieldErrors: { username: expect.any(Array) } });

    const pqc = await api.registrationOptions({ sessionId: 's1', ...registrationRequest, algorithms: ['mldsa44'] });
    expect(pqc).toMatchObject({ ok: false, fieldErrors: { algorithms: expect.any(Array) } });
  });

  it('rejects session IDs that could collide in challenge store keys', async () => {
    const result = await api.registrationOptions({ sessionId: 'a:b', ...registrationRequest });
    expect(result).toMatchObject({ ok: false, fieldErrors: { sessionId: expect.any(Array) } });
  });

  it('registers a credential and excludes it from later registrations', async () => {
    const result = await register('s1', new VirtualAuthenticator());
    expect(result).toMatchObject({ ok: true, value: { credentialId: expect.any(String) } });

    const options = ok(await api.registrationOptions({ sessionId: 's1', ...registrationRequest }));
    expect(options.excludeCredentials).toHaveLength(1);
  });

  it('only accepts a challenge once', async () => {
    const options = ok(await api.registrationOptions({ sessionId: 's1', ...registrationRequest }));
    const response = await new VirtualAuthenticator().register(options);

    const first = await api.registrationVerification({ sessionId: 's1', username: 'alice', response });
    const replay = await api.registrationVerification({ sessionId: 's1', username: 'alice', response });
    expect(first.ok).toBe(true);
    expect(replay.ok).toBe(false);
  });

  it('rejects a wrong origin', async () => {
    const options = ok(await api.registrationOptions({ sessionId: 's1', ...registrationRequest }));
    const response = await new VirtualAuthenticator('example.com', 'https://evil.example').register(options);
    const result = await api.registrationVerification({ sessionId: 's1', username: 'alice', response });
    expect(result.ok).toBe(false);
  });
});

describe('authentication', () => {
  it('logs in with a registered credential and updates the sign count', async () => {
    const authenticator = new VirtualAuthenticator();
    const { credentialId } = ok(await register('s1', authenticator));

    const options = ok(await api.authenticationOptions({ sessionId: 's1', ...authenticationRequest, username: 'alice' }));
    expect(options.allowCredentials).toHaveLength(1);

    const response = await authenticator.authenticate(options);
    const result = await api.authenticationVerification({ sessionId: 's1', username: 'alice', response });
    expect(result).toEqual({ ok: true, value: { username: 'alice', credentialId } });

    const [credential] = ok(await api.credentials({ username: 'alice' }));
    expect(credential).toMatchObject({ signCount: 1, isDiscoverable: true });
  });

  it('supports username-less (conditional UI) authentication', async () => {
    const authenticator = new VirtualAuthenticator();
    await register('s1', authenticator);

    const options = ok(await api.authenticationOptions({ sessionId: 's1', ...authenticationRequest }));
    expect(options.allowCredentials).toEqual([]);

    const response = await authenticator.authenticate(options);
    const result = await api.authenticationVerification({ sessionId: 's1', response });
    expect(result).toMatchObject({ ok: true, value: { username: 'alice' } });
  });

  it('rejects unknown usernames and mismatched users', async () => {
    const unknown = await api.authenticationOptions({ sessionId: 's1', ...authenticationRequest, username: 'nobody' });
    expect(unknown.ok).toBe(false);

    const authenticator = new VirtualAuthenticator();
    await register('s1', authenticator);
    const options = ok(await api.authenticationOptions({ sessionId: 's1', ...authenticationRequest }));
    const response = await authenticator.authenticate(options);
    const result = await api.authenticationVerification({ sessionId: 's1', username: 'bob', response });
    expect(result).toMatchObject({ ok: false, error: 'Credential does not belong to user' });
  });

  it('does not let a different session consume the challenge', async () => {
    const authenticator = new VirtualAuthenticator();
    await register('s1', authenticator);

    const options = ok(await api.authenticationOptions({ sessionId: 's1', ...authenticationRequest }));
    const response = await authenticator.authenticate(options);
    const result = await api.authenticationVerification({ sessionId: 's2', response });
    expect(result.ok).toBe(false);
  });
});

describe('credentials', () => {
  it('only deletes credentials belonging to the given user', async () => {
    const { credentialId } = ok(await register('s1', new VirtualAuthenticator()));

    expect(await api.deleteCredential({ username: 'bob', id: credentialId })).toMatchObject({ ok: false });
    expect(await api.deleteCredential({ username: 'alice', id: credentialId })).toEqual({ ok: true, value: { deleted: true } });
    expect(ok(await api.credentials({ username: 'alice' }))).toEqual([]);
  });
});

describe('credential details', () => {
  async function credentialFrom(authenticator: VirtualAuthenticator, registrationOptions = {}) {
    ok(await register('s1', authenticator, {}, registrationOptions));
    return ok(await api.credentials({ username: 'alice' }))[0];
  }

  it('describes the public key', async () => {
    const credential = await credentialFrom(new VirtualAuthenticator());
    expect(credential.publicKey).toEqual({
      kty: { id: 2, name: 'EC2' },
      alg: { id: -7, name: 'ES256' },
    });
  });

  it('names synced credentials with an all-zero AAGUID as iCloud Keychain', async () => {
    const credential = await credentialFrom(new VirtualAuthenticator(), { synced: true });
    expect(credential).toMatchObject({ deviceType: 'multiDevice', backedUp: true, providerName: 'iCloud Keychain' });
  });

  it('has no provider name for unrecognized device-bound credentials', async () => {
    const credential = await credentialFrom(new VirtualAuthenticator());
    expect(credential).toMatchObject({ deviceType: 'singleDevice', providerName: null });
  });
});

describe('origins', () => {
  it('accepts ceremonies from any expected origin', async () => {
    const options = ok(await api.registrationOptions({ sessionId: 's1', ...registrationRequest }));
    const response = await new VirtualAuthenticator('example.com', 'https://other.example').register(options);
    const result = await api.registrationVerification({ sessionId: 's1', username: 'alice', response });
    expect(result.ok).toBe(true);
  });
});
