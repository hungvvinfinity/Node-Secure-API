import type { DeviceRecord, Platform } from '../contracts.js';

export interface CommitResult {
  ok: boolean;
  reason?:
    | 'REPLAY'
    | 'NOT_FOUND'
    | 'KEY_MISMATCH'
    | 'COUNTER_ROLLBACK'
    | 'CORRUPTED_RECORD'
    | 'MISSING_SIGN_COUNT'
    | 'LEASE_EXPIRED';
  currentSequence?: string;
}

export interface SecurityStore {
  saveChallenge(challenge: string, platform: Platform, ttlSeconds: number, salt?: string): Promise<void>;
  consumeChallenge(challenge: string): Promise<{ platform: Platform; salt?: string } | null>;
  consumeStatelessChallenge?(challenge: string, ttlSeconds: number): Promise<boolean>;
  createDeviceNX(device: DeviceRecord): Promise<boolean>;
  getDevice(deviceId: string): Promise<DeviceRecord | null>;
  commitSequence(
    deviceId: string,
    expectedPublicKeyPem: string,
    newSequence: string,
    newSignCount?: number
  ): Promise<CommitResult>;
  isQuarantined?(timestampMs: number): boolean;
  ping(): Promise<boolean>;
  close(): Promise<void>;
}

export interface DurableDeviceStore {
  createDeviceNX(device: DeviceRecord): Promise<boolean>;
  getDevice(deviceId: string): Promise<DeviceRecord | null>;
  checkpointDevices(devices: Array<{ deviceId: string; lastSequence: string; signCount?: number }>): Promise<void>;
  ping(): Promise<boolean>;
  close(): Promise<void>;
}
