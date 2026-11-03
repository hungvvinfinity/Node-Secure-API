import { SecurityError, type DeviceRecord } from '../contracts.js';

const MAX_INT64 = '9223372036854775807';
export function validSequence(value: unknown, allowZero = false): value is string {
  return typeof value === 'string' && ((allowZero && value === '0') ||
    (/^[1-9]\d{0,18}$/.test(value) && (value.length < 19 || value <= MAX_INT64)));
}
export function validSignCount(value: unknown, allowZero = true): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= (allowZero ? 0 : 1) && value <= 0xffffffff;
}
export function validateDeviceRecord(device: DeviceRecord): void {
  if (!device || typeof device.deviceId !== 'string' || !device.deviceId ||
      (device.platform !== 'android' && device.platform !== 'ios') ||
      typeof device.publicKeyPem !== 'string' || !device.publicKeyPem ||
      !validSequence(device.lastSequence, true) ||
      (device.signCount !== undefined && !validSignCount(device.signCount)) ||
      (device.platform === 'ios' && (!validSignCount(device.signCount) || typeof device.keyId !== 'string' || !device.keyId)) ||
      !Number.isSafeInteger(device.registeredAt) || device.registeredAt <= 0 ||
      (device.tier !== undefined && device.tier !== 'hardware' && device.tier !== 'software') ||
      (device.expiresAt !== undefined && (!Number.isSafeInteger(device.expiresAt) || device.expiresAt <= 0)) ||
      (device.tier === 'software' && (!Number.isSafeInteger(device.expiresAt) || (device.expiresAt ?? 0) <= 0)) ||
      (device.platform === 'ios' && device.tier === 'software') ||
      !device.metadata || typeof device.metadata !== 'object' || Array.isArray(device.metadata)) {
    throw new SecurityError('CORRUPTED_DEVICE_RECORD', 500);
  }
}
