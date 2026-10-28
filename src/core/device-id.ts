import crypto from 'node:crypto';
import type { Platform } from '../contracts.js';

/**
 * Deterministically derives device ID from platform and SPKI DER base64.
 * SHA256(platform + ":" + spkiDerBase64)
 *
 * This prevents key aliasing and ensures single device identity per hardware key.
 */
export function computeDeviceId(platform: Platform, publicKeyPem: string): string {
  const keyObj = crypto.createPublicKey(publicKeyPem);
  const spkiDer = keyObj.export({ type: 'spki', format: 'der' });
  const spkiDerBase64 = spkiDer.toString('base64');
  return crypto.createHash('sha256').update(`${platform}:${spkiDerBase64}`).digest('hex');
}
