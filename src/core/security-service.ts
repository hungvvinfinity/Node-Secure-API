import crypto from 'node:crypto';
import {
  type DeviceRecord,
  type DeviceSecurityProvider,
  type Platform,
  type RegistrationInput,
  type PowInfo,
  SecurityError
} from '../contracts.js';
import type { SecurityStore } from '../store/types.js';
import { buildCanonicalBuffer } from './canonical.js';
import { computeDeviceId } from './device-id.js';
import { generatePowChallenge } from './pow.js';
import { RateLimiter } from './rate-limiter.js';

export interface SecurityServiceOptions {
  store: SecurityStore;
  providers?: DeviceSecurityProvider[];
  maxClockSkewMs?: number;
  challengeTtlSeconds?: number;
  now?: () => number;
  powDifficultyBits?: number;
  rateLimiter?: RateLimiter;
  softwareRateLimitRpm?: number;
  ipRateLimitRpm?: number;
  ipRegistrationLimitPerHour?: number;
}

export interface IssueChallengeResult {
  challenge: string;
  expiresAt: number;
  serverTime: number;
  platform: Platform;
  pow?: PowInfo;
  powInfo?: PowInfo;
}

export interface RegisterDeviceResult {
  deviceId: string;
  device: DeviceRecord;
}

export interface AuthenticateRequestParams {
  deviceId: string;
  timestamp: string;
  sequence: string;
  signature?: string;
  assertion?: string;
  method: string;
  requestTarget: string;
  rawBody: Buffer;
}

export interface AuthContext {
  device: DeviceRecord;
  rawBody: Buffer;
  timestamp: string;
  sequence: string;
  signCount?: number;
}

const MAX_INT64 = 9223372036854775807n;
const UINT32_MAX = 4294967295;

export class SecurityService {
  private readonly store: SecurityStore;
  private readonly providers = new Map<Platform, DeviceSecurityProvider>();
  private readonly maxClockSkewMs: number;
  private readonly challengeTtlSeconds: number;
  private readonly now: () => number;
  private readonly powDifficultyBits: number;
  private readonly rateLimiter: RateLimiter;

  constructor(options: SecurityServiceOptions) {
    if (options.challengeTtlSeconds !== undefined) {
      if (!Number.isFinite(options.challengeTtlSeconds) || options.challengeTtlSeconds <= 0) {
        throw new Error('challengeTtlSeconds must be a positive number');
      }
    }
    if (options.maxClockSkewMs !== undefined) {
      if (!Number.isFinite(options.maxClockSkewMs) || options.maxClockSkewMs <= 0) {
        throw new Error('maxClockSkewMs must be a positive number');
      }
    }

    this.store = options.store;
    this.maxClockSkewMs = options.maxClockSkewMs ?? 15000;
    this.challengeTtlSeconds = options.challengeTtlSeconds ?? 60;
    this.now = options.now ?? (() => Date.now());
    this.powDifficultyBits = options.powDifficultyBits ?? 18;
    this.rateLimiter = options.rateLimiter ?? new RateLimiter({
      softwareRateLimitRpm: options.softwareRateLimitRpm ?? 6,
      ipRateLimitRpm: options.ipRateLimitRpm ?? 20,
      ipRegistrationLimitPerHour: options.ipRegistrationLimitPerHour ?? 5,
      now: this.now
    });

    if (options.providers) {
      for (const provider of options.providers) {
        this.registerProvider(provider);
      }
    }
  }

  registerProvider(provider: DeviceSecurityProvider): void {
    this.providers.set(provider.platform, provider);
  }

  getProvider(platform: Platform): DeviceSecurityProvider {
    const provider = this.providers.get(platform);
    if (!provider) {
      throw new SecurityError('UNSUPPORTED_PLATFORM', 400);
    }
    return provider;
  }

  getRateLimiter(): RateLimiter {
    return this.rateLimiter;
  }

  releaseInFlight(deviceId: string): void {
    this.rateLimiter.releaseInFlight(deviceId);
  }

  /**
   * Generates a 32-byte cryptographic random hex challenge,
   * binds it to a target platform, attaches dynamic PoW parameters, and stores it with a 60s TTL.
   */
  async issueChallenge(platform: Platform = 'android'): Promise<IssueChallengeResult> {
    if (platform !== 'android' && platform !== 'ios') {
      throw new SecurityError('INVALID_PLATFORM', 400);
    }
    this.getProvider(platform);

    const challenge = crypto.randomBytes(32).toString('hex');
    const now = this.now();
    const expiresAt = now + this.challengeTtlSeconds * 1000;
    const pow = generatePowChallenge(this.powDifficultyBits);

    await this.store.saveChallenge(challenge, platform, this.challengeTtlSeconds, pow.salt);

    return {
      challenge,
      expiresAt,
      serverTime: now,
      platform,
      pow,
      powInfo: pow
    };
  }

  /**
   * Registers a hardware or software-protected device:
   * 1. Atomically consumes single-use challenge.
   * 2. Verifies cryptographic attestation / PoW solution via platform provider.
   * 3. Deterministically computes deviceId from platform and SPKI DER base64.
   * 4. Persists device record atomically with NX (no overwrite) and appropriate lease TTL.
   */
  async registerDevice(input: RegistrationInput): Promise<RegisterDeviceResult> {
    if (!input.challenge || typeof input.challenge !== 'string' || !/^[0-9a-fA-F]{64}$/.test(input.challenge)) {
      throw new SecurityError('INVALID_CHALLENGE', 400);
    }

    // Atomic consume guarantees single use and retrieves server-bound platform and PoW salt
    const challengeBinding = await this.store.consumeChallenge(input.challenge);
    if (!challengeBinding) {
      throw new SecurityError('INVALID_CHALLENGE', 401);
    }

    const provider = this.getProvider(challengeBinding.platform);

    // Attestation challenge is the exact UTF-8 bytes of the 64-char hex string
    const challengeContext = {
      challenge: Buffer.from(input.challenge, 'utf8'),
      salt: challengeBinding.salt
    };

    const verified = await provider.verifyRegistration(input, challengeContext);

    // Deterministic device ID prevents same-key aliasing
    const deviceId = computeDeviceId(challengeBinding.platform, verified.publicKeyPem);

    const deviceRecord: DeviceRecord = {
      deviceId,
      platform: challengeBinding.platform,
      publicKeyPem: verified.publicKeyPem,
      keyId: verified.keyId,
      signCount: verified.signCount,
      tier: verified.tier ?? 'hardware',
      expiresAt: verified.expiresAt,
      metadata: verified.metadata ?? {},
      lastSequence: '0',
      registeredAt: this.now()
    };

    const created = await this.store.createDeviceNX(deviceRecord);
    if (!created) {
      throw new SecurityError('DEVICE_ALREADY_REGISTERED', 409);
    }

    return {
      deviceId,
      device: deviceRecord
    };
  }

  /**
   * Authenticates an incoming business request:
   * 1. Validates strict timestamp (integer ms, max 15s clock skew).
   * 2. Validates strict sequence (canonical positive int64, no leading zeros).
   * 3. Looks up device record from persistent store.
   * 4. Verifies rolling device lease (software tier).
   * 5. Enforces single in-flight concurrency lock & rate limit for software tier.
   * 6. Assembles canonical byte buffer over raw body and raw request-target.
   * 7. Verifies cryptographic signature BEFORE advancing sequence.
   * 8. Validates iOS signCount requirements strictly.
   * 9. Atomically commits sequence advance and counter in store.
   */
  async authenticateRequest(params: AuthenticateRequestParams): Promise<AuthContext> {
    // 1. Strict timestamp check
    if (!/^[1-9]\d{0,15}$/.test(params.timestamp)) {
      throw new SecurityError('INVALID_TIMESTAMP', 400);
    }
    const timestampMs = Number(params.timestamp);
    const requestNow = this.now();
    if (!Number.isSafeInteger(timestampMs) || !Number.isSafeInteger(requestNow) ||
        Math.abs(requestNow - timestampMs) > this.maxClockSkewMs) {
      throw new SecurityError('EXPIRED_TIMESTAMP', 401);
    }

    // 2. Strict sequence check
    if (!/^[1-9]\d{0,18}$/.test(params.sequence)) {
      throw new SecurityError('INVALID_SEQUENCE', 400);
    }
    const sequenceBig = BigInt(params.sequence);
    if (sequenceBig <= 0n || sequenceBig > MAX_INT64) {
      throw new SecurityError('INVALID_SEQUENCE', 400);
    }

    // 3. Device lookup
    const device = await this.store.getDevice(params.deviceId);
    if (!device) {
      throw new SecurityError('DEVICE_NOT_REGISTERED', 401);
    }

    // 4. Rolling lease expiration check
    if (device.expiresAt !== undefined && this.now() >= device.expiresAt) {
      throw new SecurityError('DEVICE_LEASE_EXPIRED', 401);
    }

    // 5. Software Tier defenses: Rate limiting & Single in-flight concurrency lock
    const isSoftware = device.tier === 'software';
    if (isSoftware) {
      if (!this.rateLimiter.acquireInFlight(device.deviceId)) {
        throw new SecurityError('CONCURRENT_REQUEST_DISALLOWED', 429);
      }
      if (!this.rateLimiter.checkDeviceRateLimit(device.deviceId)) {
        this.rateLimiter.releaseInFlight(device.deviceId);
        throw new SecurityError('RATE_LIMIT_EXCEEDED', 429);
      }
    }

    // Helper to release in-flight lock if any subsequent authentication step fails
    const failWithCleanup = (err: unknown): never => {
      if (isSoftware) {
        this.rateLimiter.releaseInFlight(device.deviceId);
      }
      if (err instanceof SecurityError) throw err;
      throw new SecurityError('INVALID_SIGNATURE', 401);
    };

    // 6. Platform proof requirements
    if (device.platform === 'android' && !params.signature) {
      failWithCleanup(new SecurityError('MISSING_SIGNATURE', 401));
    }
    if (device.platform === 'ios' && !params.assertion) {
      failWithCleanup(new SecurityError('MISSING_ASSERTION', 401));
    }

    // 7. Assemble canonical UTF-8 buffer over wire-received target and raw body bytes
    const canonical = buildCanonicalBuffer(
      params.timestamp,
      params.sequence,
      params.method,
      params.requestTarget,
      params.rawBody
    );

    // 8. Verify signature BEFORE atomic sequence advance (prevents burning sequence on invalid signature)
    const provider = this.getProvider(device.platform);
    let verifyResult: { signCount?: number } = {};
    try {
      verifyResult = await provider.verifyRequest(device, {
        canonical,
        signature: params.signature || '',
        assertion: params.assertion
      });
    } catch (err) {
      failWithCleanup(err);
    }

    // 9. Validate iOS signCount requirement strictly before sequence commit
    if (device.platform === 'ios') {
      const newSignCount = verifyResult.signCount;
      if (newSignCount === undefined || newSignCount === null) {
        failWithCleanup(new SecurityError('MISSING_SIGN_COUNT', 401));
      } else if (!Number.isInteger(newSignCount) || newSignCount < 1 || newSignCount > UINT32_MAX) {
        failWithCleanup(new SecurityError('INVALID_SIGN_COUNT', 400));
      }
    }

    // 10. Atomic CAS commit in persistent store
    let commitResult: Awaited<ReturnType<SecurityStore['commitSequence']>> = { ok: false };
    try {
      commitResult = await this.store.commitSequence(
        device.deviceId,
        device.publicKeyPem,
        params.sequence,
        verifyResult.signCount
      );
    } catch (err) {
      failWithCleanup(err);
    }

    if (!commitResult.ok) {
      switch (commitResult.reason) {
        case 'REPLAY':
          failWithCleanup(new SecurityError('REPLAY_DETECTED', 401));
        case 'NOT_FOUND':
          failWithCleanup(new SecurityError('DEVICE_NOT_REGISTERED', 401));
        case 'KEY_MISMATCH':
          failWithCleanup(new SecurityError('INVALID_DEVICE_KEY', 401));
        case 'COUNTER_ROLLBACK':
          failWithCleanup(new SecurityError('COUNTER_ROLLBACK', 401));
        case 'MISSING_SIGN_COUNT':
          failWithCleanup(new SecurityError('MISSING_SIGN_COUNT', 401));
        case 'LEASE_EXPIRED':
          failWithCleanup(new SecurityError('DEVICE_LEASE_EXPIRED', 401));
        case 'CORRUPTED_RECORD':
          failWithCleanup(new SecurityError('CORRUPTED_DEVICE_RECORD', 500));
        default:
          failWithCleanup(new SecurityError('REPLAY_DETECTED', 401));
      }
    }

    device.lastSequence = params.sequence;
    if (verifyResult?.signCount !== undefined) {
      device.signCount = verifyResult.signCount;
    }

    return {
      device,
      rawBody: params.rawBody,
      timestamp: params.timestamp,
      sequence: params.sequence,
      signCount: verifyResult?.signCount
    };
  }
}
