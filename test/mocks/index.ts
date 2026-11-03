import crypto from 'node:crypto';
import type {
  DeviceRecord,
  DeviceSecurityProvider,
  RegistrationInput,
  RequestProof,
  VerifiedRegistration
} from '../../src/contracts.js';
import { SecurityError } from '../../src/core/errors.js';
import { MemorySecurityStore } from '../../src/store/memory.js';
import type { RevocationSource } from '../../src/platform/trust.js';

export { MemorySecurityStore };

/**
 * Standard Mock Android Provider for isolated tests.
 */
export class MockAndroidProvider implements DeviceSecurityProvider {
  public readonly platform = 'android' as const;

  public async verifyRegistration(
    input: RegistrationInput,
    context: { challenge: Buffer; salt?: string }
  ): Promise<VerifiedRegistration> {
    if (!input.certificateChain || input.certificateChain.length === 0) {
      throw new SecurityError('INVALID_CERTIFICATE_CHAIN', 400);
    }
    const leafDer = Buffer.from(input.certificateChain[0] ?? '', 'base64');
    const leafCert = new crypto.X509Certificate(leafDer);
    return {
      publicKeyPem: leafCert.publicKey.export({ type: 'spki', format: 'pem' }) as string,
      metadata: { challenge: context.challenge.toString('utf8') }
    };
  }

  public async verifyRequest(device: DeviceRecord, proof: RequestProof): Promise<{ signCount?: number }> {
    const isMatch = crypto.verify(
      'sha256',
      proof.canonical,
      device.publicKeyPem,
      Buffer.from(proof.signature || '', 'base64')
    );
    if (!isMatch) {
      throw new SecurityError('INVALID_SIGNATURE', 401);
    }
    return {};
  }
}

/**
 * Standard Mock iOS Provider for isolated tests.
 */
export class MockIOSProvider implements DeviceSecurityProvider {
  public readonly platform = 'ios' as const;

  public async verifyRegistration(
    input: RegistrationInput,
    _context: { challenge: Buffer; salt?: string }
  ): Promise<VerifiedRegistration> {
    if (!input.attestationObject) {
      throw new SecurityError('MISSING_ATTESTATION_OBJECT', 400);
    }
    return {
      publicKeyPem: input.publicKeyPem ?? '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0\n-----END PUBLIC KEY-----',
      metadata: { keyId: input.keyId }
    };
  }

  public async verifyRequest(_device: DeviceRecord, proof: RequestProof): Promise<{ signCount?: number }> {
    if (!proof.assertion) {
      throw new SecurityError('MISSING_ASSERTION', 401);
    }
    return { signCount: 1 };
  }
}

/**
 * Mock Revocation Source for offline revocation testing.
 */
export class MockRevocationSource implements RevocationSource {
  public serials = new Set<string>();

  public revoke(serialHex: string): void {
    this.serials.add(serialHex.toLowerCase());
  }

  public async getRevokedSerials(): Promise<Set<string>> {
    return this.serials;
  }
}
