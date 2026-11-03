import { exports } from 'cloudflare:workers';
import { expect, it } from 'vitest';
import type WebAuthnApi from '../src/index';

it('lists only algorithms the runtime supports', async () => {
  const { algorithms } = await (exports.default as unknown as Service<WebAuthnApi>).getRuntimeCapabilities();

  expect(algorithms).toEqual(expect.arrayContaining(['es256', 'rs256', 'ed25519']));
  // Workers has no ML-DSA in WebCrypto yet; this fails (and should be revisited) once it does
  expect(algorithms).not.toContain('mldsa44');
});
