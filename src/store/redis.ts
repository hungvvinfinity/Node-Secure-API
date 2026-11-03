import { createClient, type RedisClientType } from 'redis';
import { type DeviceRecord, type Platform, SecurityError } from '../contracts.js';
import type { CommitResult, SecurityStore } from './types.js';
import { validSequence, validSignCount, validateDeviceRecord } from './validation.js';

export interface RedisSecurityStoreOptions {
  client?: RedisClientType;
  url?: string;
  keyPrefix?: string;
  connectTimeoutMs?: number;
  commandTimeoutMs?: number;
  now?: () => number;
}

const CONSUME_CHALLENGE_LUA = `
local val = redis.call('GET', KEYS[1])
if val then
    redis.call('DEL', KEYS[1])
    return val
else
    return nil
end
`;

const CREATE_DEVICE_NX_LUA = `
local key = KEYS[1]
if redis.call('EXISTS', key) == 1 then
    local exp = redis.call('HGET', key, 'expiresAt')
    local nowMs = tonumber(ARGV[13] or '0')
    if exp and exp ~= '' and nowMs > 0 and tonumber(exp) and nowMs >= tonumber(exp) then
        redis.call('DEL', key)
    else
        return 0
    end
end
redis.call('HSET', key,
    'deviceId', ARGV[1],
    'platform', ARGV[2],
    'publicKeyPem', ARGV[3],
    'lastSequence', ARGV[4],
    'registeredAt', ARGV[5],
    'metadata', ARGV[6],
    'keyId', ARGV[7] or '',
    'signCount', ARGV[8] or '',
    'receipt', ARGV[9] or '',
    'tier', ARGV[10] or 'hardware',
    'expiresAt', ARGV[11] or ''
)
local ttl = tonumber(ARGV[12] or '')
if ttl and ttl > 0 then
    redis.call('EXPIRE', key, ttl)
end
return 1
`;

const COMMIT_SEQUENCE_LUA = `
local key = KEYS[1]
local expectedPubKey = ARGV[1]
local newSeq = ARGV[2]
local newSignCountStr = ARGV[3]
local nowMs = tonumber(ARGV[4] or '0')

local exists = redis.call('EXISTS', key)
if exists == 0 then
    return { -1, 'DEVICE_NOT_FOUND' }
end

local exp = redis.call('HGET', key, 'expiresAt')
if exp and exp ~= '' and nowMs > 0 and tonumber(exp) and nowMs >= tonumber(exp) then
    redis.call('DEL', key)
    return { -7, 'LEASE_EXPIRED' }
end

local pubKey = redis.call('HGET', key, 'publicKeyPem')
if pubKey ~= expectedPubKey then
    return { -2, 'KEY_MISMATCH' }
end

local function is_greater(a, b)
    if #a > #b then return true end
    if #a < #b then return false end
    return a > b
end

local function valid_sequence(s, zero_allowed)
    if not s then return false end
    if s == '0' then return zero_allowed end
    if not string.match(s, '^[1-9]%d*$') then return false end
    return #s < 19 or (#s == 19 and s <= '9223372036854775807')
end

local currentSeq = redis.call('HGET', key, 'lastSequence')
if not valid_sequence(currentSeq, true) then return {-4, 'CORRUPTED_SEQUENCE'} end
if not valid_sequence(newSeq, false) then return {-4, 'INVALID_SEQUENCE'} end

if not is_greater(newSeq, currentSeq) then
    return { 0, currentSeq }
end

local platform = redis.call('HGET', key, 'platform')
if platform ~= 'ios' and platform ~= 'android' then return {-4, 'CORRUPTED_PLATFORM'} end
if platform == 'ios' then
    if not newSignCountStr or newSignCountStr == '' then
        return { -6, 'MISSING_SIGN_COUNT' }
    end
    if not string.match(newSignCountStr, "^[1-9]%d*$") then
        return { -3, 'INVALID_SIGN_COUNT' }
    end
    local currentCountStr = redis.call('HGET', key, 'signCount')
    if not currentCountStr or not valid_sequence(currentCountStr, true) then
        return { -5, 'CORRUPTED_SIGN_COUNT' }
    end
    local currentCount = tonumber(currentCountStr)
    if currentCount > 4294967295 then return {-5, 'CORRUPTED_SIGN_COUNT'} end
    local newCount = tonumber(newSignCountStr)
    if not newCount or newCount <= currentCount or newCount > 4294967295 then
        return { -3, 'SIGN_COUNT_NOT_INCREMENTED' }
    end
    redis.call('HSET', key, 'signCount', newSignCountStr)
elseif newSignCountStr and newSignCountStr ~= '' then
    return {-4, 'UNEXPECTED_SIGN_COUNT'}
end

redis.call('HSET', key, 'lastSequence', newSeq)
return { 1, newSeq }
`;

export class RedisSecurityStore implements SecurityStore {
  private client: RedisClientType;
  private connecting?: Promise<RedisClientType>;
  private closed = false;
  private readonly ownsClient: boolean;
  private readonly prefix: string;
  private readonly url: string;
  private readonly connectTimeoutMs: number;
  private readonly commandTimeoutMs: number;
  private readonly now: () => number;

  constructor(options: RedisSecurityStoreOptions = {}) {
    this.prefix = options.keyPrefix ?? 'sec:';
    this.url = options.url ?? process.env.REDIS_URL ?? 'redis://127.0.0.1:6379';
    this.connectTimeoutMs = options.connectTimeoutMs ?? 1000;
    this.commandTimeoutMs = options.commandTimeoutMs ?? 1000;
    this.now = options.now ?? (() => Date.now());
    for (const value of [this.connectTimeoutMs, this.commandTimeoutMs]) {
      if (!Number.isInteger(value) || value < 1 || value > 60000) throw new Error('Invalid Redis timeout');
    }
    this.ownsClient = !options.client;
    this.client = options.client ?? this.initOwnedClient();
  }

  private initOwnedClient(): RedisClientType {
    const client = createClient({
      url: this.url, disableOfflineQueue: true, commandsQueueMaxLength: 4096,
      commandOptions: { timeout: this.commandTimeoutMs },
      socket: { connectTimeout: this.connectTimeoutMs, reconnectStrategy: false }
    }) as RedisClientType;
    client.on('error', () => { /* Each operation reports a sanitized STORE_ERROR. */ });
    return client;
  }

  private discard(client: RedisClientType): void {
    if (this.ownsClient) {
      try { client.destroy(); } catch { /* Already closed. */ }
    }
  }

  private async deadline<T>(operation: Promise<T>, milliseconds: number, client: RedisClientType): Promise<T> {
    let timer: NodeJS.Timeout | undefined;
    try {
      return await Promise.race([operation, new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          this.discard(client);
          reject(new SecurityError('STORE_ERROR', 503));
        }, milliseconds);
      })]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  private async ensureConnected(): Promise<RedisClientType> {
    if (this.closed) throw new SecurityError('STORE_ERROR', 503);
    if (this.client.isReady) return this.client;
    if (this.connecting) return this.connecting;
    if (this.client.isOpen) throw new SecurityError('STORE_ERROR', 503);
    if (this.ownsClient) this.client = this.initOwnedClient();
    const client = this.client;
    // Share a single handshake among all concurrent callers. isOpen does not mean isReady.
    const attempt = Promise.resolve().then(async () => {
      try {
        await this.deadline(client.connect(), this.connectTimeoutMs, client);
        if (this.closed || !client.isReady) throw new SecurityError('STORE_ERROR', 503);
        return client;
      } catch {
        this.discard(client);
        throw new SecurityError('STORE_ERROR', 503);
      }
    });
    this.connecting = attempt;
    try { return await attempt; }
    finally { if (this.connecting === attempt) this.connecting = undefined; }
  }

  private async command<T>(operation: (client: RedisClientType) => Promise<T>): Promise<T> {
    const client = await this.ensureConnected();
    try { return await this.deadline(operation(client), this.commandTimeoutMs, client); }
    catch {
      // Always discard this operation's client, never a newer replacement connection.
      this.discard(client);
      throw new SecurityError('STORE_ERROR', 503);
    }
  }

  private challengeKey(challenge: string): string { return this.prefix + 'challenge:' + challenge; }
  private deviceKey(deviceId: string): string { return this.prefix + 'device:' + deviceId; }

  async saveChallenge(challenge: string, platform: Platform, ttlSeconds: number, salt?: string): Promise<void> {
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > 3600 ||
        (platform !== 'android' && platform !== 'ios')) throw new SecurityError('INVALID_CHALLENGE', 400);
    const value = salt ? JSON.stringify({ platform, salt }) : platform;
    await this.command(c => c.set(this.challengeKey(challenge), value, { EX: ttlSeconds }));
  }

  async consumeChallenge(challenge: string): Promise<{ platform: Platform; salt?: string } | null> {
    const result = await this.command(c => c.eval(CONSUME_CHALLENGE_LUA, { keys: [this.challengeKey(challenge)], arguments: [] }));
    if (result === null) return null;
    if (result === 'android' || result === 'ios') return { platform: result };
    if (typeof result === 'string') {
      try {
        const parsed = JSON.parse(result);
        if (parsed.platform === 'android' || parsed.platform === 'ios') {
          return { platform: parsed.platform, salt: parsed.salt };
        }
      } catch {
        const parts = result.split(':');
        if (parts[0] === 'android' || parts[0] === 'ios') {
          return { platform: parts[0] as Platform, salt: parts[1] };
        }
      }
    }
    throw new SecurityError('CORRUPTED_CHALLENGE', 500);
  }

  async createDeviceNX(device: DeviceRecord): Promise<boolean> {
    validateDeviceRecord(device);
    // Keep the durable fraud receipt available to a risk worker without sending it
    // through Redis and parsing its base64 on every protected API request.
    const { receipt, ...requestMetadata } = device.metadata;
    if (receipt !== undefined && typeof receipt !== 'string') throw new SecurityError('CORRUPTED_DEVICE_RECORD', 500);
    const ttlSeconds = device.expiresAt ? Math.max(1, Math.ceil((device.expiresAt - this.now()) / 1000)) : 0;
    const result = await this.command(c => c.eval(CREATE_DEVICE_NX_LUA, {
      keys: [this.deviceKey(device.deviceId)],
      arguments: [
        device.deviceId,
        device.platform,
        device.publicKeyPem,
        device.lastSequence,
        String(device.registeredAt),
        JSON.stringify(requestMetadata),
        device.keyId ?? '',
        device.signCount === undefined ? '' : String(device.signCount),
        receipt ?? '',
        device.tier ?? 'hardware',
        device.expiresAt === undefined ? '' : String(device.expiresAt),
        ttlSeconds > 0 ? String(ttlSeconds) : '',
        String(this.now())
      ]
    }));
    return result === 1;
  }

  async getDevice(deviceId: string): Promise<DeviceRecord | null> {
    const fields = ['deviceId', 'platform', 'publicKeyPem', 'lastSequence', 'registeredAt', 'metadata', 'keyId', 'signCount', 'tier', 'expiresAt'];
    const values = await this.command(c => c.hmGet(this.deviceKey(deviceId), fields));
    if (values.every(value => value === null)) return null;
    const data: Record<string, string> = Object.fromEntries(fields.map((field, i) => [field, values[i] ?? '']));

    // Check lease expiry
    if (data.expiresAt && data.expiresAt !== '') {
      const expMs = Number(data.expiresAt);
      if (Number.isSafeInteger(expMs) && this.now() >= expMs) {
        await this.command(c => c.del(this.deviceKey(deviceId)));
        return null;
      }
    }

    let metadata: Record<string, unknown>;
    try { metadata = JSON.parse(data.metadata); }
    catch { throw new SecurityError('CORRUPTED_DEVICE_RECORD', 500); }
    const device: DeviceRecord = {
      deviceId: data.deviceId,
      platform: data.platform as Platform,
      publicKeyPem: data.publicKeyPem,
      lastSequence: data.lastSequence,
      registeredAt: Number(data.registeredAt),
      metadata,
      keyId: data.keyId || undefined,
      signCount: data.signCount === '' || data.signCount === undefined ? undefined : Number(data.signCount),
      tier: (data.tier as any) || 'hardware',
      expiresAt: data.expiresAt ? Number(data.expiresAt) : undefined
    };
    if (device.deviceId !== deviceId || (data.signCount && !validSequence(data.signCount, true))) {
      throw new SecurityError('CORRUPTED_DEVICE_RECORD', 500);
    }
    validateDeviceRecord(device);
    return device;
  }

  async commitSequence(deviceId: string, expectedPublicKeyPem: string, newSequence: string, newSignCount?: number): Promise<CommitResult> {
    if (!validSequence(newSequence)) throw new SecurityError('INVALID_SEQUENCE', 400);
    if (newSignCount !== undefined && !validSignCount(newSignCount, false)) {
      return { ok: false, reason: 'COUNTER_ROLLBACK' };
    }
    const raw = await this.command(c => c.eval(COMMIT_SEQUENCE_LUA, {
      keys: [this.deviceKey(deviceId)],
      arguments: [expectedPublicKeyPem, newSequence, newSignCount === undefined ? '' : String(newSignCount), String(this.now())]
    }));
    if (!Array.isArray(raw) || typeof raw[0] !== 'number') throw new SecurityError('STORE_ERROR', 503);
    const [status, sequence] = raw;
    switch (status) {
      case 1: return { ok: true };
      case 0: return { ok: false, reason: 'REPLAY', currentSequence: String(sequence) };
      case -1: return { ok: false, reason: 'NOT_FOUND' };
      case -2: return { ok: false, reason: 'KEY_MISMATCH' };
      case -3: return { ok: false, reason: 'COUNTER_ROLLBACK' };
      case -4: case -5: return { ok: false, reason: 'CORRUPTED_RECORD' };
      case -6: return { ok: false, reason: 'MISSING_SIGN_COUNT' };
      case -7: return { ok: false, reason: 'LEASE_EXPIRED' };
      default: throw new SecurityError('STORE_ERROR', 503);
    }
  }

  async ping(): Promise<boolean> {
    try { return await this.command(c => c.ping()) === 'PONG'; } catch { return false; }
  }

  async close(): Promise<void> {
    this.closed = true;
    this.discard(this.client);
  }
}
