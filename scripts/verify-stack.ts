import assert from 'node:assert/strict';
import { createAttestationChain } from '../test/helpers/crypto-fixtures.js';

const base = new URL(process.env.STACK_BASE_URL ?? 'http://127.0.0.1:3000');
if (base.username || base.password || !['http:', 'https:'].includes(base.protocol)) throw new Error('Invalid stack URL');
const platforms = (process.env.STACK_TEST_PLATFORMS ?? 'android,ios').split(',');
if (!platforms.length || platforms.some(p => p !== 'android' && p !== 'ios')) throw new Error('Invalid stack platforms');
const request = (path: string, init?: RequestInit) => fetch(new URL(path, base), {
  ...init, redirect: 'error', signal: AbortSignal.timeout(10_000)
});
for (const [path, expected] of [['/health', 'UP'], ['/ready', 'READY']]) {
  const response = await request(path);
  assert.equal(response.status, 200);
  assert.equal((await response.json() as { status: string }).status, expected);
}
for (const platform of new Set(platforms)) {
  const response = await request('/api/auth/challenge', { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ platform }) });
  assert.equal(response.status, 200, `Provider ${platform} must be enabled for this smoke test`);
  const issued = await response.json() as { challenge: string; expiresAt: number };
  assert.match(issued.challenge, /^[a-f0-9]{64}$/);
  assert.ok(issued.expiresAt > Date.now());
  if (platform === 'android') {
    const fixture = await createAttestationChain({ challengeHex: issued.challenge,
      packageName: 'com.example.secure', now: Date.now() });
    const forged = await request('/api/auth/register-device', { method: 'POST',
      headers: { 'content-type': 'application/json', 'x-test-mode': 'true' },
      body: JSON.stringify({ challenge: issued.challenge, certificateChain: fixture.chain }) });
    assert.equal(forged.status, 403);
    assert.equal((await forged.json() as { error: string }).error, 'UNTRUSTED_ROOT_CA');
  }
}
const unauthenticated = await request('/api/tarot/read', { method: 'POST', body: '{}' });
assert.equal(unauthenticated.status, 401);
console.log(JSON.stringify({ scope: 'runtime-stack-smoke', result: 'PASS', health: 200, ready: 200,
  enabledPlatformsChecked: platforms, protectedRequestWithoutProof: 401,
  ...(platforms.includes('android') ? { syntheticRootRejected: 403, testHeaderCannotBypassTrust: true } : {}),
  hardwareAttestationVerified: false }));
