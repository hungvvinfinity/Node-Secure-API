export type Platform = 'android' | 'ios';

export interface RegistrationInput {
  challenge: string;
  certificateChain?: string[];
  attestationObject?: string;
  keyId?: string;
}

export interface VerifiedRegistration {
  publicKeyPem: string;
  keyId?: string;
  signCount?: number;
  metadata: Record<string, unknown>;
}

export interface DeviceRecord extends VerifiedRegistration {
  deviceId: string;
  platform: Platform;
  lastSequence: string;
  registeredAt: number;
}

export interface RequestProof {
  canonical: Buffer;
  signature?: string;
  assertion?: string;
}

/** Only platform cryptography differs; challenge/replay/HTTP policy stays shared. */
export interface DeviceSecurityProvider {
  readonly platform: Platform;
  verifyRegistration(input: RegistrationInput, context: { challenge: Buffer }): Promise<VerifiedRegistration>;
  verifyRequest(device: DeviceRecord, proof: RequestProof): Promise<{ signCount?: number }>;
}

export class SecurityError extends Error {
  constructor(public readonly code: string, public readonly status: number = 403) {
    super(code);
    this.name = 'SecurityError';
  }
}
