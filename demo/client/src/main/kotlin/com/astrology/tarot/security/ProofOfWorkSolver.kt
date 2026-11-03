package com.astrology.tarot.security

import java.security.MessageDigest

/**
 * Proof of Work (PoW) Solver and Verifier for Tier 2 (Software Protected) devices.
 *
 * Implements the contract specified in docs/ANDROID_COMPATIBILITY_PLAN.md:
 * SHA256(challenge + ":" + salt + ":" + nonce) must have at least `difficulty` leading zero bits.
 */
object ProofOfWorkSolver {

    /**
     * Counts the number of consecutive leading zero bits in a binary buffer
     * starting from the most significant bit (MSB) of byte 0.
     */
    fun countLeadingZeroBits(bytes: ByteArray): Int {
        var zeros = 0
        for (b in bytes) {
            val unsignedByte = b.toInt() and 0xFF
            if (unsignedByte == 0) {
                zeros += 8
            } else {
                // Integer.numberOfLeadingZeros operates on a 32-bit int.
                // An unsigned 8-bit byte occupying the lowest 8 bits has (leadingZeros - 24) zero bits.
                zeros += Integer.numberOfLeadingZeros(unsignedByte) - 24
                break
            }
        }
        return zeros
    }

    /**
     * Verifies if a given nonce satisfies the Proof of Work difficulty.
     */
    fun verifyProofOfWork(
        challenge: String,
        salt: String,
        nonce: String,
        difficulty: Int
    ): Boolean {
        if (challenge.isEmpty() || salt.isEmpty() || nonce.isEmpty() || difficulty < 1 || difficulty > 256) {
            return false
        }
        val input = "$challenge:$salt:$nonce"
        val hash = MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.UTF_8))
        return countLeadingZeroBits(hash) >= difficulty
    }

    /**
     * Solves the Proof of Work puzzle by finding a nonce that satisfies the difficulty.
     * Uses incremental byte-level SHA-256 updates to maximize hash throughput.
     */
    fun solveProofOfWork(
        challenge: String,
        salt: String,
        difficulty: Int,
        maxIterations: Long = 50_000_000L
    ): String {
        require(challenge.isNotEmpty()) { "Challenge must not be empty" }
        require(salt.isNotEmpty()) { "Salt must not be empty" }
        require(difficulty in 1..256) { "Difficulty must be between 1 and 256" }

        val prefix = "$challenge:$salt:"
        val prefixBytes = prefix.toByteArray(Charsets.UTF_8)
        val md = MessageDigest.getInstance("SHA-256")
        var nonce = 0L

        while (nonce < maxIterations) {
            val nonceStr = nonce.toString()
            val nonceBytes = nonceStr.toByteArray(Charsets.UTF_8)

            md.reset()
            md.update(prefixBytes)
            md.update(nonceBytes)
            val hash = md.digest()

            if (countLeadingZeroBits(hash) >= difficulty) {
                return nonceStr
            }
            nonce++
        }

        throw IllegalStateException("PoW solver exceeded maximum iterations ($maxIterations) for difficulty $difficulty")
    }
}
