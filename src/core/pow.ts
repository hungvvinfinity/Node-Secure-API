import crypto from 'node:crypto';

/**
 * Counts the number of consecutive leading zero bits in a binary buffer
 * starting from the most significant bit of byte 0.
 */
export function countLeadingZeroBits(buffer: Uint8Array): number {
  let zeros = 0;
  for (let i = 0; i < buffer.length; i++) {
    const byte = buffer[i];
    if (byte === 0) {
      zeros += 8;
    } else {
      zeros += Math.clz32(byte) - 24;
      break;
    }
  }
  return zeros;
}

/**
 * Verifies a Proof of Work solution:
 * SHA256(challenge + ":" + salt + ":" + nonce) must have at least `difficulty` leading zero bits.
 *
 * Performance guarantee: < 0.005ms per verification call.
 */
export function verifyProofOfWork(
  challenge: string,
  salt: string,
  nonce: string,
  difficulty: number
): boolean {
  if (typeof challenge !== 'string' || !challenge ||
      typeof salt !== 'string' || !salt ||
      typeof nonce !== 'string' || !nonce ||
      typeof difficulty !== 'number' || !Number.isInteger(difficulty) ||
      difficulty < 1 || difficulty > 256) {
    return false;
  }

  const input = `${challenge}:${salt}:${nonce}`;
  const hash = crypto.createHash('sha256').update(input, 'utf8').digest();
  return countLeadingZeroBits(hash) >= difficulty;
}

/**
 * Solves a Proof of Work puzzle by finding a nonce that satisfies the difficulty.
 * Used for testing and client reference implementation.
 */
export function solveProofOfWork(
  challenge: string,
  salt: string,
  difficulty: number,
  maxIterations = 50_000_000
): string {
  if (typeof challenge !== 'string' || !challenge ||
      typeof salt !== 'string' || !salt ||
      typeof difficulty !== 'number' || !Number.isInteger(difficulty) ||
      difficulty < 1 || difficulty > 256) {
    throw new Error('Invalid Proof of Work parameters for solver');
  }

  const prefix = `${challenge}:${salt}:`;
  let nonce = 0;

  while (nonce < maxIterations) {
    const nonceStr = nonce.toString();
    const hash = crypto.createHash('sha256').update(prefix + nonceStr, 'utf8').digest();
    if (countLeadingZeroBits(hash) >= difficulty) {
      return nonceStr;
    }
    nonce++;
  }

  throw new Error(`PoW solver exceeded maximum iterations (${maxIterations}) for difficulty ${difficulty}`);
}

/**
 * Generates dynamic PoW challenge parameters (random salt and configured difficulty).
 */
export function generatePowChallenge(difficulty = 18): { salt: string; difficulty: number } {
  const salt = crypto.randomBytes(16).toString('hex');
  return {
    salt,
    difficulty
  };
}
