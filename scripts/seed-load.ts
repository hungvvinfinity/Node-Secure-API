import { generateKeyPairSync } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { computeDeviceId } from '../src/core/device-id.js';
import { RedisSecurityStore } from '../src/store/redis.js';
import type { DeviceRecord } from '../src/contracts.js';

export interface SeededDeviceFixture {
  deviceId: string;
  privateKeyPkcs8: string;
}

/**
 * Seeds synthetic EC P-256 test devices into Redis for k6 capacity benchmarks.
 * Invariants:
 * - Requires explicit REDIS_TEST_URL with redis: or rediss: protocol.
 * - Requires REDIS_KEY_PREFIX to start with 'loadtest:'.
 * - Bounds LOAD_DEVICES between 1 and 1024 (default 512).
 * - Writes fixture array [{ deviceId, privateKeyPkcs8 }] with mode 0o600.
 * - Suppresses fixture path and private keys from stdout.
 * - Disposes Redis store in finally block.
 */
export async function seedLoadDevices(): Promise<SeededDeviceFixture[]> {
  const redisUrl = process.env.REDIS_TEST_URL?.trim();
  if (!redisUrl) {
    throw new Error('REDIS_TEST_URL is required');
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(redisUrl);
  } catch {
    throw new Error('Invalid REDIS_TEST_URL');
  }

  if (parsedUrl.protocol !== 'redis:' && parsedUrl.protocol !== 'rediss:') {
    throw new Error('REDIS_TEST_URL must use redis: or rediss: protocol');
  }

  const keyPrefix = process.env.REDIS_KEY_PREFIX?.trim() || 'loadtest:';
  if (!keyPrefix.startsWith('loadtest:')) {
    throw new Error('REDIS_KEY_PREFIX must start with loadtest:');
  }

  const rawLoadDevices = process.env.LOAD_DEVICES?.trim();
  let loadDevices = 512;
  if (rawLoadDevices) {
    if (!/^(0|[1-9]\d*)$/.test(rawLoadDevices)) {
      throw new Error('LOAD_DEVICES must be a canonical integer');
    }
    loadDevices = Number(rawLoadDevices);
  }

  if (!Number.isSafeInteger(loadDevices) || loadDevices < 1 || loadDevices > 1024) {
    throw new Error('LOAD_DEVICES out of range (1..1024)');
  }

  const outputPath = process.env.FIXTURES_OUTPUT_PATH?.trim() || '/fixtures/devices.json';
  const outputDir = path.dirname(outputPath);
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  const store = new RedisSecurityStore({
    url: redisUrl,
    keyPrefix
  });

  try {
    const isReady = await store.ping();
    if (!isReady) {
      throw new Error('Redis ping failed: store is not reachable');
    }

    const fixtures: SeededDeviceFixture[] = [];
    const now = Date.now();

    for (let i = 0; i < loadDevices; i++) {
      const keyPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const publicKeyPem = keyPair.publicKey.export({ format: 'pem', type: 'spki' }).toString();
      const privateKeyPkcs8 = keyPair.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');
      const deviceId = computeDeviceId('android', publicKeyPem);

      const record: DeviceRecord = {
        deviceId,
        platform: 'android',
        publicKeyPem,
        lastSequence: '0',
        registeredAt: now,
        metadata: { benchmark: true }
      };

      const created = await store.createDeviceNX(record);
      if (!created) {
        throw new Error('Collision or failed device creation in Redis');
      }

      fixtures.push({
        deviceId,
        privateKeyPkcs8
      });
    }

    // Write fixture JSON with mode 0o600
    fs.writeFileSync(outputPath, JSON.stringify(fixtures, null, 2), { mode: 0o600 });

    // Output generic success metric without leaking path or credentials
    console.log(`[seed-load] Seeded ${fixtures.length} benchmark devices into Redis.`);

    return fixtures;
  } finally {
    await store.close();
  }
}

// Direct execution entrypoint
const isMain =
  import.meta.url === `file://${process.argv[1]}` ||
  process.argv[1]?.endsWith('seed-load.ts') ||
  process.argv[1]?.endsWith('seed-load.js');

if (isMain) {
  seedLoadDevices().catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[seed-load] Error: ${message}`);
    process.exit(1);
  });
}
