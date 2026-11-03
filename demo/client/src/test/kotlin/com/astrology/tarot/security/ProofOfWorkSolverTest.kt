package com.astrology.tarot.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

class ProofOfWorkSolverTest {

    @Test
    fun testCountLeadingZeroBits() {
        // 0 zero bits: MSB is 1
        assertEquals(0, ProofOfWorkSolver.countLeadingZeroBits(byteArrayOf(0x80.toByte())))
        assertEquals(0, ProofOfWorkSolver.countLeadingZeroBits(byteArrayOf(0xFF.toByte())))

        // 1 to 7 zero bits
        assertEquals(1, ProofOfWorkSolver.countLeadingZeroBits(byteArrayOf(0x40.toByte())))
        assertEquals(2, ProofOfWorkSolver.countLeadingZeroBits(byteArrayOf(0x20.toByte())))
        assertEquals(3, ProofOfWorkSolver.countLeadingZeroBits(byteArrayOf(0x10.toByte())))
        assertEquals(4, ProofOfWorkSolver.countLeadingZeroBits(byteArrayOf(0x08.toByte())))
        assertEquals(5, ProofOfWorkSolver.countLeadingZeroBits(byteArrayOf(0x04.toByte())))
        assertEquals(6, ProofOfWorkSolver.countLeadingZeroBits(byteArrayOf(0x02.toByte())))
        assertEquals(7, ProofOfWorkSolver.countLeadingZeroBits(byteArrayOf(0x01.toByte())))

        // 8 zero bits: byte 0 is 0x00, byte 1 MSB is 1
        assertEquals(8, ProofOfWorkSolver.countLeadingZeroBits(byteArrayOf(0x00, 0x80.toByte())))

        // 16 zero bits: 2 zero bytes, byte 2 MSB is 1
        assertEquals(16, ProofOfWorkSolver.countLeadingZeroBits(byteArrayOf(0x00, 0x00, 0x80.toByte())))

        // 18 zero bits: 2 zero bytes, byte 2 has 2 zero bits (0x20 = 0010 0000)
        assertEquals(18, ProofOfWorkSolver.countLeadingZeroBits(byteArrayOf(0x00, 0x00, 0x20.toByte())))

        // Empty buffer
        assertEquals(0, ProofOfWorkSolver.countLeadingZeroBits(ByteArray(0)))
    }

    @Test
    fun testSolveAndVerifyProofOfWork() {
        val challenge = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        val salt = "fedcba9876543210fedcba9876543210"

        for (difficulty in listOf(8, 12, 14)) {
            val nonce = ProofOfWorkSolver.solveProofOfWork(challenge, salt, difficulty)
            assertTrue("Nonce must not be empty", nonce.isNotEmpty())

            val isValid = ProofOfWorkSolver.verifyProofOfWork(challenge, salt, nonce, difficulty)
            assertTrue("PoW solution for difficulty $difficulty must verify", isValid)
        }
    }

    @Test
    fun testVerifyRejectionOnTampering() {
        val challenge = "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"
        val salt = "abcdef0123456789abcdef0123456789"
        val difficulty = 10

        val validNonce = ProofOfWorkSolver.solveProofOfWork(challenge, salt, difficulty)
        assertTrue(ProofOfWorkSolver.verifyProofOfWork(challenge, salt, validNonce, difficulty))

        // Tampered nonce
        assertFalse(ProofOfWorkSolver.verifyProofOfWork(challenge, salt, validNonce + "99", difficulty))

        // Tampered salt
        assertFalse(ProofOfWorkSolver.verifyProofOfWork(challenge, "wrong_salt", validNonce, difficulty))

        // Tampered challenge
        assertFalse(ProofOfWorkSolver.verifyProofOfWork("wrong_challenge", salt, validNonce, difficulty))
    }
}
