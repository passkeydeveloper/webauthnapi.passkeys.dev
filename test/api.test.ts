import { runInDurableObject } from 'cloudflare:test';
import { env, exports } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { MAX_CREDENTIALS_PER_USERNAME, deleteExpiredCredentials, storeCredential } from '../src/credentials';
import type { CreateAuthenticationOptionsInput, CreateRegistrationOptionsInput, Result } from '../src/index';
import { VirtualAuthenticator } from './virtual-authenticator';

/** The relying party for verification calls; `https://other.example` checks multiple origins */
const rp = { rpId: 'example.com', expectedOrigins: ['https://example.com', 'https://other.example'] };

const registrationRequest: Omit<CreateRegistrationOptionsInput, 'sessionId'> = {
  rpId: 'example.com',
  rpName: 'Example',
  username: 'alice',
  userVerification: 'preferred',
  attestation: 'none',
  attachment: 'all',
  algorithms: ['es256'],
  discoverableCredential: 'preferred',
  hints: [],
};

const authenticationRequest: Omit<CreateAuthenticationOptionsInput, 'sessionId'> = {
  rpId: 'example.com',
  userVerification: 'preferred',
  hints: [],
};

const api = exports.default;

/** Values from a successful result, failing the test otherwise */
function ok<T>(result: Result<T>): T {
  if (!result.ok) throw new Error(`Expected success, got ${JSON.stringify(result)}`);
  return result.value;
}

async function register(sessionId: string, authenticator: VirtualAuthenticator, overrides = {}, registrationOptions = {}) {
  const options = ok(await api.createRegistrationOptions({ sessionId, ...registrationRequest, ...overrides }));
  const response = await authenticator.register(options, registrationOptions);
  return api.verifyRegistrationResponse({ ...rp, sessionId, username: 'alice', response });
}

beforeEach(async () => {
  await env.DB.exec('DELETE FROM credentials');
});

describe('registration', () => {
  it('generates options honoring the request', async () => {
    const options = ok(await api.createRegistrationOptions({
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
    const options = ok(await api.createRegistrationOptions({ sessionId: 's1', ...registrationRequest, algorithms: [] }));
    expect(options.pubKeyCredParams).toEqual([]);
  });

  it('rejects invalid requests and algorithms the runtime cannot verify', async () => {
    const invalid = await api.createRegistrationOptions({ sessionId: 's1', ...registrationRequest, username: '' });
    expect(invalid).toMatchObject({ ok: false, fieldErrors: { username: expect.any(Array) } });

    const pqc = await api.createRegistrationOptions({ sessionId: 's1', ...registrationRequest, algorithms: ['mldsa44'] });
    expect(pqc).toMatchObject({ ok: false, fieldErrors: { algorithms: expect.any(Array) } });
  });

  it('rejects session IDs that could collide in challenge store keys', async () => {
    const result = await api.createRegistrationOptions({ sessionId: 'a:b', ...registrationRequest });
    expect(result).toMatchObject({ ok: false, fieldErrors: { sessionId: expect.any(Array) } });
  });

  it('registers a credential and excludes it from later registrations', async () => {
    const result = await register('s1', new VirtualAuthenticator());
    expect(result).toMatchObject({ ok: true, value: { credentialId: expect.any(String) } });

    const options = ok(await api.createRegistrationOptions({ sessionId: 's1', ...registrationRequest }));
    expect(options.excludeCredentials).toHaveLength(1);
  });

  it('only accepts a challenge once', async () => {
    const options = ok(await api.createRegistrationOptions({ sessionId: 's1', ...registrationRequest }));
    const response = await new VirtualAuthenticator().register(options);

    const first = await api.verifyRegistrationResponse({ ...rp, sessionId: 's1', username: 'alice', response });
    const replay = await api.verifyRegistrationResponse({ ...rp, sessionId: 's1', username: 'alice', response });
    expect(first.ok).toBe(true);
    expect(replay.ok).toBe(false);
  });

  it('rejects a wrong origin', async () => {
    const options = ok(await api.createRegistrationOptions({ sessionId: 's1', ...registrationRequest }));
    const response = await new VirtualAuthenticator('example.com', 'https://evil.example').register(options);
    const result = await api.verifyRegistrationResponse({ ...rp, sessionId: 's1', username: 'alice', response });
    expect(result.ok).toBe(false);
  });
});

describe('authentication', () => {
  it('logs in with a registered credential and updates the sign count', async () => {
    const authenticator = new VirtualAuthenticator();
    const { credentialId } = ok(await register('s1', authenticator));

    const options = ok(await api.createAuthenticationOptions({ sessionId: 's1', ...authenticationRequest, username: 'alice' }));
    expect(options.allowCredentials).toHaveLength(1);

    const response = await authenticator.authenticate(options);
    const result = await api.verifyAuthenticationResponse({ ...rp, sessionId: 's1', username: 'alice', response });
    expect(result).toEqual({ ok: true, value: { username: 'alice', credentialId } });

    const [credential] = ok(await api.getCredentials({ rpId: 'example.com', username: 'alice' }));
    expect(credential).toMatchObject({ signCount: 1, isDiscoverable: true });
  });

  it('supports username-less (conditional UI) authentication', async () => {
    const authenticator = new VirtualAuthenticator();
    await register('s1', authenticator);

    const options = ok(await api.createAuthenticationOptions({ sessionId: 's1', ...authenticationRequest }));
    expect(options.allowCredentials).toEqual([]);

    const response = await authenticator.authenticate(options);
    const result = await api.verifyAuthenticationResponse({ ...rp, sessionId: 's1', response });
    expect(result).toMatchObject({ ok: true, value: { username: 'alice' } });
  });

  it('rejects unknown usernames and mismatched users', async () => {
    const unknown = await api.createAuthenticationOptions({ sessionId: 's1', ...authenticationRequest, username: 'nobody' });
    expect(unknown.ok).toBe(false);

    const authenticator = new VirtualAuthenticator();
    await register('s1', authenticator);
    const options = ok(await api.createAuthenticationOptions({ sessionId: 's1', ...authenticationRequest }));
    const response = await authenticator.authenticate(options);
    const result = await api.verifyAuthenticationResponse({ ...rp, sessionId: 's1', username: 'bob', response });
    expect(result).toMatchObject({ ok: false, error: 'Credential does not belong to user' });
  });

  it('does not let a different session consume the challenge', async () => {
    const authenticator = new VirtualAuthenticator();
    await register('s1', authenticator);

    const options = ok(await api.createAuthenticationOptions({ sessionId: 's1', ...authenticationRequest }));
    const response = await authenticator.authenticate(options);
    const result = await api.verifyAuthenticationResponse({ ...rp, sessionId: 's2', response });
    expect(result.ok).toBe(false);
  });
});

describe('credentials', () => {
  it('only deletes credentials belonging to the given user', async () => {
    const { credentialId } = ok(await register('s1', new VirtualAuthenticator()));

    expect(await api.deleteCredential({ rpId: 'example.com', username: 'bob', id: credentialId })).toMatchObject({ ok: false });
    expect(await api.deleteCredential({ rpId: 'example.com', username: 'alice', id: credentialId })).toEqual({ ok: true, value: { deleted: true } });
    expect(ok(await api.getCredentials({ rpId: 'example.com', username: 'alice' }))).toEqual([]);
  });
});

describe('credential details', () => {
  async function credentialFrom(authenticator: VirtualAuthenticator, registrationOptions = {}) {
    ok(await register('s1', authenticator, {}, registrationOptions));
    return ok(await api.getCredentials({ rpId: 'example.com', username: 'alice' }))[0];
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
    const options = ok(await api.createRegistrationOptions({ sessionId: 's1', ...registrationRequest }));
    const response = await new VirtualAuthenticator('example.com', 'https://other.example').register(options);
    const result = await api.verifyRegistrationResponse({ ...rp, sessionId: 's1', username: 'alice', response });
    expect(result.ok).toBe(true);
  });
});

describe('relying parties', () => {
  it('rejects RP IDs and expected origins that are not a domain and origins', async () => {
    const options = await api.createRegistrationOptions({ sessionId: 's1', ...registrationRequest, rpId: 'https://example.com' });
    expect(options).toMatchObject({ ok: false, fieldErrors: { rpId: expect.any(Array) } });

    const verification = await api.verifyRegistrationResponse({
      ...rp,
      expectedOrigins: ['https://example.com/'],
      sessionId: 's1',
      username: 'alice',
      response: {} as never,
    });
    expect(verification).toMatchObject({ ok: false, fieldErrors: { 'expectedOrigins.0': expect.any(Array) } });
  });

  it('keeps credentials separate per RP ID', async () => {
    const { credentialId } = ok(await register('s1', new VirtualAuthenticator()));
    const other = { rpId: 'other.example', username: 'alice' };

    expect(ok(await api.getCredentials(other))).toEqual([]);
    expect(await api.createAuthenticationOptions({ sessionId: 's1', ...authenticationRequest, ...other })).toMatchObject({ ok: false });
    expect(await api.deleteCredential({ ...other, id: credentialId })).toMatchObject({ ok: false });
    expect(ok(await api.getCredentials({ rpId: 'example.com', username: 'alice' }))).toHaveLength(1);
  });
});

describe('credential expiry', () => {
  const DAY_MS = 24 * 60 * 60 * 1000;

  async function expiresAt(id: string) {
    return (await env.DB.prepare('SELECT expires_at FROM credentials WHERE id = ?').bind(id).first<number>('expires_at'))!;
  }

  it('keeps unused credentials for a day, and used ones for 30 days after each authentication', async () => {
    const authenticator = new VirtualAuthenticator();
    const { credentialId } = ok(await register('s1', authenticator));
    expect(await expiresAt(credentialId)).toBeCloseTo(Date.now() + DAY_MS, -4);

    const options = ok(await api.createAuthenticationOptions({ sessionId: 's1', ...authenticationRequest }));
    const response = await authenticator.authenticate(options);
    ok(await api.verifyAuthenticationResponse({ ...rp, sessionId: 's1', response }));
    expect(await expiresAt(credentialId)).toBeCloseTo(Date.now() + 30 * DAY_MS, -4);
  });

  it('deletes only expired credentials', async () => {
    const { credentialId: expired } = ok(await register('s1', new VirtualAuthenticator()));
    const { credentialId: current } = ok(await register('s1', new VirtualAuthenticator()));
    await env.DB.prepare('UPDATE credentials SET expires_at = ? WHERE id = ?').bind(Date.now() - 1, expired).run();

    await deleteExpiredCredentials(env.DB);

    const remaining = ok(await api.getCredentials({ rpId: 'example.com', username: 'alice' }));
    expect(remaining.map((cred) => cred.id)).toEqual([current]);
  });
});

describe('registration limits and checks', () => {
  /** Store placeholder credentials for alice directly, to reach the per-username limit quickly */
  async function storePlaceholders(from: number, to: number) {
    for (let i = from; i < to; i++) {
      await storeCredential(env.DB, {
        id: `placeholder-${i}`,
        rpId: 'example.com',
        username: 'alice',
        publicKey: '',
        signCount: 0,
        isDiscoverable: null,
        deviceType: 'singleDevice',
        backedUp: false,
        transports: null,
        aaguid: '00000000-0000-0000-0000-000000000000',
      });
    }
  }

  const tooMany = { ok: false, error: `That username already has the maximum of ${MAX_CREDENTIALS_PER_USERNAME} credentials` };

  it('refuses registration options once a username has the maximum number of credentials', async () => {
    await storePlaceholders(0, MAX_CREDENTIALS_PER_USERNAME);
    expect(await api.createRegistrationOptions({ sessionId: 's1', ...registrationRequest })).toEqual(tooMany);
  });

  it('refuses to store a credential that would go over the maximum', async () => {
    await storePlaceholders(0, MAX_CREDENTIALS_PER_USERNAME - 1);
    const options = ok(await api.createRegistrationOptions({ sessionId: 's1', ...registrationRequest }));
    await storePlaceholders(MAX_CREDENTIALS_PER_USERNAME - 1, MAX_CREDENTIALS_PER_USERNAME);

    const response = await new VirtualAuthenticator().register(options);
    expect(await api.verifyRegistrationResponse({ ...rp, sessionId: 's1', username: 'alice', response })).toEqual(tooMany);
  });

  it('reports a credential ID that is already registered', async () => {
    const authenticator = new VirtualAuthenticator();
    ok(await register('s1', authenticator));
    expect(await register('s1', authenticator)).toEqual({ ok: false, error: 'Credential already registered' });
  });
});

describe('challenge store', () => {
  it('does not hand out a challenge past its TTL, even if the alarm has not run yet', async () => {
    const store = env.CHALLENGES.getByName('expiry-test');
    await store.put({ challenge: 'abc' }, 60_000);
    await runInDurableObject(store, (_, state) => state.storage.put('expiresAt', Date.now() - 1));

    expect(await store.take()).toBeUndefined();
  });
});
