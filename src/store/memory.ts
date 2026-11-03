import { type DeviceRecord, type Platform, SecurityError } from '../contracts.js';
import type { CommitResult, SecurityStore } from './types.js';
import { validSequence, validateDeviceRecord } from './validation.js';

interface ChallengeEntry {
  platform: Platform;
  expiresAt: number;
  salt?: string;
}

export interface MemorySecurityStoreOptions {
  now?: () => number;
}

const UINT32_MAX = 4294967295;

/**
 * In-memory security store designed for unit and integration testing.
 * NEVER use in production environments.
 */
export class MemorySecurityStore implements SecurityStore {
  private readonly challenges = new Map<string, ChallengeEntry>();
  private readonly devices = new Map<string, DeviceRecord>();
  private readonly consumedChallenges = new Map<string, number>();
  private readonly now: () => number;

  constructor(options: MemorySecurityStoreOptions = {}) {
    this.now = options.now ?? (() => Date.now());
  }

  async saveChallenge(challenge: string, platform: Platform, ttlSeconds: number, salt?: string): Promise<void> {
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > 3600 ||
        (platform !== 'android' && platform !== 'ios')) throw new SecurityError('INVALID_CHALLENGE', 400);
    const expiresAt = this.now() + ttlSeconds * 1000;
    this.challenges.set(challenge, { platform, expiresAt, salt });
  }

  async consumeChallenge(challenge: string): Promise<{ platform: Platform; salt?: string } | null> {
    const entry = this.challenges.get(challenge);
    if (!entry) {
      return null;
    }

    // Always delete challenge upon first access (single-use guarantee)
    this.challenges.delete(challenge);

    // Fail closed if challenge expired (uses >= as required)
    if (this.now() >= entry.expiresAt) {
      return null;
    }

    return { platform: entry.platform, salt: entry.salt };
  }

  async consumeStatelessChallenge(challenge: string, ttlSeconds: number): Promise<boolean> {
    const now=this.now();
    for(const [key,until] of this.consumedChallenges) if(until<=now) this.consumedChallenges.delete(key);
    if(this.consumedChallenges.has(challenge)) return false;
    this.consumedChallenges.set(challenge,now+ttlSeconds*1000); return true;
  }

  async createDeviceNX(device: DeviceRecord): Promise<boolean> {
    const existing = this.devices.get(device.deviceId);
    if (existing) {
      // If existing device lease has expired, purge and allow renewal
      if (existing.expiresAt !== undefined && this.now() >= existing.expiresAt) {
        this.devices.delete(device.deviceId);
      } else {
        return false;
      }
    }

    this.validateStoredDevice(device);
    this.devices.set(device.deviceId, structuredClone(device));
    return true;
  }

  async getDevice(deviceId: string): Promise<DeviceRecord | null> {
    const device = this.devices.get(deviceId);
    if (!device) {
      return null;
    }
    this.validateStoredDevice(device);

    // Enforce lease expiration: fail closed and purge expired lease
    if (device.expiresAt !== undefined && this.now() >= device.expiresAt) {
      this.devices.delete(deviceId);
      return null;
    }

    const result = structuredClone(device);
    delete result.metadata.receipt;
    return result;
  }

  async commitSequence(
    deviceId: string,
    expectedPublicKeyPem: string,
    newSequence: string,
    newSignCount?: number
  ): Promise<CommitResult> {
    if (!validSequence(newSequence)) throw new SecurityError('INVALID_SEQUENCE', 400);
    const device = this.devices.get(deviceId);
    if (!device) {
      return { ok: false, reason: 'NOT_FOUND' };
    }

    this.validateStoredDevice(device);

    // Fail closed on expired device lease
    if (device.expiresAt !== undefined && this.now() >= device.expiresAt) {
      this.devices.delete(deviceId);
      return { ok: false, reason: 'LEASE_EXPIRED' };
    }

    if (device.publicKeyPem !== expectedPublicKeyPem) {
      return { ok: false, reason: 'KEY_MISMATCH' };
    }

    // Require iOS signCount when platform is ios (fail closed before sequence advance)
    if (device.platform === 'ios') {
      if (newSignCount === undefined || newSignCount === null) {
        return { ok: false, reason: 'MISSING_SIGN_COUNT' };
      }
      if (!Number.isInteger(newSignCount) || newSignCount < 1 || newSignCount > UINT32_MAX) {
        return { ok: false, reason: 'COUNTER_ROLLBACK' };
      }
      const currentCount = device.signCount ?? 0;
      if (newSignCount <= currentCount) {
        return { ok: false, reason: 'COUNTER_ROLLBACK' };
      }
    }

    // Strict BigInt comparison for decimal monotonic sequence
    const currentSeqBig = BigInt(device.lastSequence || '0');
    const newSeqBig = BigInt(newSequence);

    if (newSeqBig <= currentSeqBig) {
      return { ok: false, reason: 'REPLAY', currentSequence: device.lastSequence };
    }

    // Apply updates atomically
    if (device.platform === 'ios' && newSignCount !== undefined) {
      device.signCount = newSignCount;
    }

    device.lastSequence = newSequence;
    return { ok: true };
  }

  async ping(): Promise<boolean> {
    return true;
  }

  async close(): Promise<void> {
    this.challenges.clear();
    this.consumedChallenges.clear();
    this.devices.clear();
  }

  private validateStoredDevice(device: DeviceRecord): void {
    validateDeviceRecord(device);
  }
}
