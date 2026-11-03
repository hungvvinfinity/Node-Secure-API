package com.astrology.tarot.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class AtomicSequenceGeneratorTest {

    @Before
    fun setUp() {
        AtomicSequenceGenerator.configure(null as android.content.SharedPreferences?)
        AtomicSequenceGenerator.reset(0L)
    }

    @Test
    fun testStrictlyIncreasingSequence() {
        assertEquals(0L, AtomicSequenceGenerator.currentSequence())
        assertEquals(1L, AtomicSequenceGenerator.nextSequence())
        assertEquals(2L, AtomicSequenceGenerator.nextSequence())
        assertEquals(3L, AtomicSequenceGenerator.nextSequence())
        assertEquals(3L, AtomicSequenceGenerator.currentSequence())
    }

    @Test
    fun testReset() {
        AtomicSequenceGenerator.nextSequence() // 1
        AtomicSequenceGenerator.nextSequence() // 2
        assertEquals(2L, AtomicSequenceGenerator.currentSequence())

        AtomicSequenceGenerator.reset(0L)
        assertEquals(0L, AtomicSequenceGenerator.currentSequence())
        assertEquals(1L, AtomicSequenceGenerator.nextSequence())

        AtomicSequenceGenerator.reset(100L)
        assertEquals(100L, AtomicSequenceGenerator.currentSequence())
        assertEquals(101L, AtomicSequenceGenerator.nextSequence())
    }

    @Test
    fun testNoLeadingZerosInString() {
        AtomicSequenceGenerator.reset(0L)
        val seq1 = AtomicSequenceGenerator.nextSequenceString()
        assertEquals("1", seq1)
        assertFalse(seq1.startsWith("0"))

        AtomicSequenceGenerator.reset(9L)
        val seq10 = AtomicSequenceGenerator.nextSequenceString()
        assertEquals("10", seq10)
        assertFalse(seq10.startsWith("0"))
    }

    @Test
    fun testMultithreadConcurrency() {
        val threadCount = 16
        val iterationsPerThread = 100
        val totalExpected = threadCount * iterationsPerThread

        AtomicSequenceGenerator.reset(0L)

        val executor = Executors.newFixedThreadPool(threadCount)
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(threadCount)
        val generatedNumbers = ConcurrentHashMap.newKeySet<Long>()

        for (i in 0 until threadCount) {
            executor.submit {
                try {
                    startLatch.await() // Ensure all threads start simultaneously
                    repeat(iterationsPerThread) {
                        val seq = AtomicSequenceGenerator.nextSequence()
                        val added = generatedNumbers.add(seq)
                        assertTrue("Duplicate sequence detected: $seq", added)
                    }
                } finally {
                    doneLatch.countDown()
                }
            }
        }

        // Trigger simultaneous start
        startLatch.countDown()
        val finished = doneLatch.await(10, TimeUnit.SECONDS)
        executor.shutdown()

        assertTrue("All threads must finish within timeout", finished)
        assertEquals("Must generate exactly $totalExpected unique sequences", totalExpected, generatedNumbers.size)

        // Verify that the set contains exactly numbers from 1 to totalExpected without gaps
        val min = generatedNumbers.minOrNull() ?: 0L
        val max = generatedNumbers.maxOrNull() ?: 0L
        assertEquals(1L, min)
        assertEquals(totalExpected.toLong(), max)
    }
}
