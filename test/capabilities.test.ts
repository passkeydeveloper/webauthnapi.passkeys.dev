import { exports } from 'cloudflare:workers';
import { expect, it } from 'vitest';

it('lists only algorithms the runtime supports', async () => {
  const { algorithms } = await exports.default.getRuntimeCapabilities();

  expect(algorithms).toEqual(expect.arrayContaining(['es256', 'rs256', 'ed25519']));
  // Workers has no ML-DSA in WebCrypto yet; this fails (and should be revisited) once it does
  expect(algorithms).not.toContain('mldsa44');
});
