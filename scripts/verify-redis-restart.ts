import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID, generateKeyPairSync, createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { RedisSecurityStore } from '../src/store/redis.js';

const exec = promisify(execFile);
const docker = async (...args: string[]) => (await exec('docker', args, { timeout: 30_000, maxBuffer: 64 * 1024 })).stdout.trim();
const name = 'node-secure-restart-' + randomUUID().slice(0, 8);
let container: string | undefined;
let store: RedisSecurityStore | undefined;
try {
  container = await docker('run', '--rm', '-d', '--name', name, '-p', '127.0.0.1::6379', 'redis:8-alpine',
    'redis-server', '--appendonly', 'yes', '--appendfsync', 'always', '--maxmemory-policy', 'noeviction');
  if (!/^[a-f0-9]{64}$/.test(container)) throw new Error('Unexpected Docker container identifier');
  const connect = async () => {
    const binding = await docker('port', container!, '6379/tcp');
    if (!/^127\.0\.0\.1:\d+$/.test(binding)) throw new Error('Unexpected isolated Redis port');
    const candidate = new RedisSecurityStore({ url: 'redis://' + binding, keyPrefix: 'restart-proof:' });
    for (let i = 0; i < 20; i++) {
      if (await candidate.ping()) return candidate;
      await delay(100);
    }
    await candidate.close();
    throw new Error('Isolated Redis did not become ready');
  };
  store = await connect();
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey;
  const publicKeyPem = key.export({ format: 'pem', type: 'spki' }).toString();
  const deviceId = createHash('sha256').update(publicKeyPem).digest('hex');
  const record = { deviceId, platform: 'ios' as const, publicKeyPem, keyId: deviceId,
    lastSequence: '0', signCount: 0, registeredAt: Date.now(), metadata: { isolatedStorageTest: true } };
  assert.equal(await store.createDeviceNX(record), true);
  assert.equal((await store.commitSequence(deviceId, publicKeyPem, '9007199254740993', 1)).ok, true);
  await store.close();
  store = undefined;
  await docker('restart', container);
  store = await connect();
  const restored = await store.getDevice(deviceId);
  assert.equal(restored?.lastSequence, '9007199254740993');
  assert.equal(restored?.signCount, 1);
  assert.equal(restored?.publicKeyPem, publicKeyPem);
  assert.equal((await store.commitSequence(deviceId, publicKeyPem, '9007199254740993', 2)).reason, 'REPLAY');
  assert.equal((await store.commitSequence(deviceId, publicKeyPem, '9007199254740994', 1)).reason, 'COUNTER_ROLLBACK');
  assert.equal((await store.commitSequence(deviceId, publicKeyPem, '9007199254740994', 2)).ok, true);
  assert.equal(await store.createDeviceNX(record), false);
  console.log(JSON.stringify({ redisContainerActuallyRestarted: true, aof: true, sequenceBeyond2pow53Survived: true,
    iosCounterSurvived: true, replayRejected: true, nextSequenceAccepted: true, registrationCannotReset: true }));
} finally {
  await store?.close();
  if (container && /^[a-f0-9]{64}$/.test(container)) await docker('rm', '-f', container);
}
