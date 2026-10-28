import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { computeDeviceId } from '../src/core/device-id.js';
import { RedisSecurityStore } from '../src/store/redis.js';

const phase = process.argv[2];
const runId = process.env.PERSISTENCE_TEST_ID ?? '';
const url = process.env.REDIS_TEST_URL;
if (!['seed', 'verify'].includes(phase) || !/^[a-f0-9-]{36}$/.test(runId) || !url) {
  throw new Error('Run this storage-only proof through npm run test:docker');
}
const store = new RedisSecurityStore({ url, keyPrefix: `compose-proof:${runId}:` });
const marker = createHash('sha256').update(runId).digest('hex');
const challenge = createHash('sha256').update('challenge:' + runId).digest('hex');
const expectedKeyHash = process.env.PERSISTENCE_EXPECTED_KEY_SHA256;
if (phase === 'verify' && !/^[a-f0-9]{64}$/.test(expectedKeyHash ?? '')) {
  throw new Error('Expected public key hash from seed process is required');
}
try {
  assert.equal(await store.ping(), true);
  if (phase === 'seed') {
    const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey;
    const publicKeyPem = key.export({ format: 'pem', type: 'spki' }).toString();
    const record = {
      deviceId: marker, platform: 'ios' as const, publicKeyPem,
      keyId: computeDeviceId('ios', publicKeyPem), lastSequence: '0', signCount: 0,
      registeredAt: Date.now(), metadata: { isolatedStorageTest: true, runId }
    };
    assert.equal(await store.createDeviceNX(record), true);
    assert.equal((await store.commitSequence(marker, publicKeyPem, '9007199254740993', 1)).ok, true);
    await store.saveChallenge(challenge, 'ios', 60);
    console.log(JSON.stringify({ phase, scope: 'redis-storage-only', durableWriteAcknowledged: true,
      publicKeySha256: createHash('sha256').update(publicKeyPem).digest('hex') }));
  } else {
    const restored = await store.getDevice(marker);
    assert.ok(restored, 'Redis must retain the same device after service restart');
    assert.equal(restored.lastSequence, '9007199254740993');
    assert.equal(restored.signCount, 1);
    assert.equal(restored.metadata.runId, runId);
    assert.equal(createHash('sha256').update(restored.publicKeyPem).digest('hex'), expectedKeyHash);
    assert.equal((await store.commitSequence(marker, restored.publicKeyPem, '9007199254740993', 2)).reason, 'REPLAY');
    assert.equal((await store.commitSequence(marker, restored.publicKeyPem, '9007199254740994', 1)).reason, 'COUNTER_ROLLBACK');
    assert.equal((await store.commitSequence(marker, restored.publicKeyPem, '9007199254740994', 2)).ok, true);
    assert.equal(await store.createDeviceNX({ ...restored, lastSequence: '0', signCount: 0 }), false);
    assert.deepEqual(await store.consumeChallenge(challenge), { platform: 'ios' });
    assert.equal(await store.consumeChallenge(challenge), null);
    console.log(JSON.stringify({ phase, scope: 'redis-storage-only', sequenceBeyond2pow53Survived: true,
      iosCounterSurvived: true, replayRejected: true, nextSequenceAccepted: true,
      samePublicKeySurvived: true, registrationCannotReset: true,
      pendingChallengeSurvived: true, challengeSingleUse: true }));
  }
} finally {
  await store.close();
}
