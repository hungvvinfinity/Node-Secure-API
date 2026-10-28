import { createClient } from 'redis';
import { randomUUID, generateKeyPairSync, sign } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { AndroidSecurityProvider } from '../src/platform/android.js';
import { GOOGLE_HARDWARE_ATTESTATION_ROOTS } from '../src/platform/android-roots.js';
import { PublicKeyCache, defaultPublicKeyCache } from '../src/platform/key-cache.js';
import { SecurityService } from '../src/core/security-service.js';
import { computeDeviceId } from '../src/core/device-id.js';
import { buildCanonicalBuffer } from '../src/core/canonical.js';
import { createServer } from '../src/http/server.js';
import { RedisSecurityStore } from '../src/store/redis.js';
import { CachingSecurityStore } from '../src/store/cached.js';
import type { DeviceRecord } from '../src/contracts.js';

const url = process.env.BENCHMARK_REDIS_URL;
if (!url) throw new Error('Set BENCHMARK_REDIS_URL to an isolated test Redis');
const count = Number(process.env.BENCHMARK_REQUESTS ?? 1024);
const deviceCount = Number(process.env.BENCHMARK_DEVICES ?? 16);
if (!Number.isInteger(count) || count < 32 || count > 100_000 ||
    !Number.isInteger(deviceCount) || deviceCount < 1 || deviceCount > 256) throw new Error('Invalid benchmark size');
const prefix = `benchmark:${randomUUID()}:`;
const devices = Array.from({ length: deviceCount }, () => {
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const pem = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const deviceId = computeDeviceId('android', pem);
  return { keys, deviceId, sequence: 0n, record: { deviceId, platform: 'android', publicKeyPem: pem,
    lastSequence: '0', metadata: {}, registeredAt: Date.now() } as DeviceRecord };
});
const seeded = new RedisSecurityStore({ url, keyPrefix: prefix });
await Promise.all(devices.map(d => seeded.createDeviceNX(d.record)));
await seeded.close();
const body = Buffer.from('{"benchmark":true}');
const provider = new AndroidSecurityProvider({ trustAnchors: [...GOOGLE_HARDWARE_ATTESTATION_ROOTS],
  expectedPackageName: 'com.example.benchmark', expectedSignerDigests: ['ab'.repeat(32)],
  revocationSource: { getRevokedSerials: async () => { throw new Error('Registration is outside this benchmark'); } } });

const results: Record<string, unknown>[] = [];
try {
  for (const cached of [false, true]) {
    const durable = new RedisSecurityStore({ url, keyPrefix: prefix });
    let reads = 0;
    let commits = 0;
    const get = durable.getDevice.bind(durable);
    const commit = durable.commitSequence.bind(durable);
    durable.getDevice = (...args) => { reads++; return get(...args); };
    durable.commitSequence = (...args) => { commits++; return commit(...args); };
    const store = cached ? new CachingSecurityStore(durable) : durable;
    const server = createServer({ store, securityService: new SecurityService({ store, providers: [provider] }) });
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('No listening address');
    const endpoint = `http://127.0.0.1:${address.port}/api/tarot/read`;
    const request = async (device: typeof devices[number]): Promise<number> => {
      const start = performance.now();
      const timestamp = String(Date.now());
      const sequence = String(++device.sequence);
      const signature = sign('sha256', buildCanonicalBuffer(timestamp, sequence, 'POST', '/api/tarot/read', body),
        device.keys.privateKey).toString('base64');
      const response = await fetch(endpoint, { method: 'POST', body, headers: {
        'X-Device-Id': device.deviceId, 'X-Timestamp': timestamp, 'X-Sequence': sequence, 'X-Signature': signature
      } });
      await response.arrayBuffer();
      if (response.status !== 200) throw new Error(`Benchmark request rejected: ${response.status}`);
      return performance.now() - start;
    };
    try {
      // One serial stream per device preserves the protocol's strict arrival order.
      await Promise.all(devices.map(async device => { for (let i = 0; i < 4; i++) await request(device); }));
      reads = commits = 0;
      const latencies: number[] = [];
      const started = performance.now();
      await Promise.all(devices.map(async (device, index) => {
        for (let i = index; i < count; i += deviceCount) latencies.push(await request(device));
      }));
      const duration = performance.now() - started;
      latencies.sort((a, b) => a - b);
      results.push({ mode: cached ? 'identity-cache' : 'redis-read-every-request', requests: latencies.length,
        requestsPerSecond: Math.round(count * 1000 / duration), p50ms: +latencies[Math.floor(count * .5)].toFixed(2),
        p95ms: +latencies[Math.floor(count * .95)].toFixed(2), redisReads: reads, atomicCommits: commits });
    } finally {
      await new Promise<void>(resolve => server.close(() => resolve()));
      await store.close();
    }
  }
  // Separate the PEM parsing cost from HTTP and Redis overhead.
  const pem = devices[0].record.publicKeyPem;
  const canonical = Buffer.from('benchmark-key-object');
  const signature = sign('sha256', canonical, devices[0].keys.privateKey);
  const { verify } = await import('node:crypto');
  const keyCache = new PublicKeyCache();
  for (const useCache of [false, true]) {
    const start = performance.now();
    for (let i = 0; i < 10_000; i++) {
      if (!verify('sha256', canonical, useCache ? keyCache.getP256Key(pem) : pem, signature)) throw new Error('Verification failed');
    }
    results.push({ mode: useCache ? 'keyobject-microbenchmark' : 'pem-microbenchmark', iterations: 10_000,
      totalMs: +(performance.now() - start).toFixed(2) });
  }
  console.log(JSON.stringify({ note: 'Synthetic seeded keys; local software sender + HTTP + ECDSA + Redis. No attestation/hardware/business workload.',
    node: process.version, deviceCount, keyCache: defaultPublicKeyCache.stats, results }, null, 2));
} finally {
  const cleanup = createClient({ url, socket: { reconnectStrategy: false, connectTimeout: 1000 }, commandOptions: { timeout: 1000 } });
  cleanup.on('error', () => {});
  try { await cleanup.connect(); await cleanup.del(devices.map(d => `${prefix}device:${d.deviceId}`)); }
  finally { cleanup.destroy(); }
}
