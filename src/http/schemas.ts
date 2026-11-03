import { z } from 'zod';

/**
 * Challenge Request / Response Schemas
 */
export const ChallengeRequestSchema = z.object({
  platform: z.enum(['android', 'ios']).optional().default('android')
});
export type ChallengeRequest = z.infer<typeof ChallengeRequestSchema>;

export const PowInfoSchema = z.object({
  difficulty: z.number().int().positive(),
  salt: z.string().min(1)
});

export const ChallengeResponseSchema = z.object({
  status: z.literal('SUCCESS'),
  challenge: z.string().regex(/^[0-9a-fA-F]{64}$/),
  expiresAt: z.number().positive(),
  serverTime: z.number().positive(),
  pow: PowInfoSchema.optional(),
  powInfo: PowInfoSchema.optional()
});
export type ChallengeResponse = z.infer<typeof ChallengeResponseSchema>;

/**
 * Device Registration Schemas
 */
export const RegisterDeviceRequestSchema = z.object({
  challenge: z.string().regex(/^[0-9a-fA-F]{64}$/, 'Challenge must be a 64-character hex string'),
  certificateChain: z.array(z.string().min(1)).min(1, 'certificateChain must be a non-empty array of base64 strings').optional(),
  attestationObject: z.string().min(1, 'attestationObject must be a non-empty string').optional(),
  keyId: z.string().optional(),
  publicKeyPem: z.string().min(1, 'publicKeyPem must be a non-empty string').optional(),
  powNonce: z.string().min(1, 'powNonce must be a non-empty string').optional()
}).refine(
  data => data.certificateChain !== undefined || data.attestationObject !== undefined || data.publicKeyPem !== undefined,
  {
    message: 'Either certificateChain, attestationObject, or publicKeyPem is required',
    path: ['certificateChain']
  }
);
export type RegisterDeviceRequest = z.infer<typeof RegisterDeviceRequestSchema>;

export const RegisterDeviceResponseSchema = z.object({
  status: z.literal('SUCCESS'),
  deviceId: z.string().min(1),
  tier: z.enum(['hardware', 'software']),
  platform: z.enum(['android', 'ios'])
});
export type RegisterDeviceResponse = z.infer<typeof RegisterDeviceResponseSchema>;

/**
 * Security Headers Schema for Authenticated API Calls
 */
export const SecurityHeadersSchema = z.object({
  'x-device-id': z.string().min(1, 'Missing required header x-device-id'),
  'x-timestamp': z.string().regex(/^\d+$/, 'Invalid timestamp format in header x-timestamp'),
  'x-sequence': z.string().regex(/^\d+$/, 'Invalid sequence format in header x-sequence'),
  'x-signature': z.string().optional(),
  'x-assertion': z.string().optional()
});
export type SecurityHeaders = z.infer<typeof SecurityHeadersSchema>;
