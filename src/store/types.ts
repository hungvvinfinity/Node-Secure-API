import type { DeviceRecord, Platform } from '../contracts.js';

export interface CommitResult {
  ok: boolean;
  reason?:
    | 'REPLAY'
    | 'NOT_FOUND'
    | 'KEY_MISMATCH'
    | 'COUNTER_ROLLBACK'
    | 'CORRUPTED_RECORD'
    | 'MISSING_SIGN_COUNT';
  currentSequence?: string;
}

export interface SecurityStore {
  saveChallenge(challenge: string, platform: Platform, ttlSeconds: number): Promise<void>;
  consumeChallenge(challenge: string): Promise<{ platform: Platform } | null>;
  createDeviceNX(device: DeviceRecord): Promise<boolean>;
  getDevice(deviceId: string): Promise<DeviceRecord | null>;
  commitSequence(
    deviceId: string,
    expectedPublicKeyPem: string,
    newSequence: string,
    newSignCount?: number
  ): Promise<CommitResult>;
  ping(): Promise<boolean>;
  close(): Promise<void>;
}
