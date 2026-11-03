export type Platform = 'android' | 'ios';

export type DeviceTier = 'hardware' | 'software';

export interface PowInfo {
  salt: string;
  difficulty: number;
}

export interface ChallengeResponse {
  status: 'SUCCESS';
  challenge: string;
  expiresAt: number;
  pow?: PowInfo;
  powInfo?: PowInfo;
}

export interface RegistrationInput {
  challenge: string;
  certificateChain?: string[];
  attestationObject?: string;
  keyId?: string;
  publicKeyPem?: string;  // Cho thiết bị không hỗ trợ attestation chain
  powNonce?: string;      // Lời giải PoW
}

export interface VerifiedRegistration {
  publicKeyPem: string;
  keyId?: string;
  signCount?: number;
  tier?: DeviceTier;
  expiresAt?: number;
  metadata: Record<string, unknown>;
}

export interface DeviceRecord extends VerifiedRegistration {
  deviceId: string;
  platform: Platform;
  lastSequence: string;
  registeredAt: number;
  tier?: DeviceTier;
  expiresAt?: number;
}

export interface RequestProof {
  canonical: Buffer;
  signature?: string;
  assertion?: string;
}

/** Only platform cryptography differs; challenge/replay/HTTP policy stays shared. */
export interface DeviceSecurityProvider {
  readonly platform: Platform;
  verifyRegistration(
    input: RegistrationInput,
    context: { challenge: Buffer; salt?: string }
  ): Promise<VerifiedRegistration>;
  verifyRequest(device: DeviceRecord, proof: RequestProof): Promise<{ signCount?: number }>;
}

export { SecurityError, type SecurityErrorCode, isSecurityError } from './core/errors.js';
