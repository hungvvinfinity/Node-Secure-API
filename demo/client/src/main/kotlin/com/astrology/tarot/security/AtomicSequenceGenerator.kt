package com.astrology.tarot.security

import android.content.Context
import android.content.SharedPreferences
import java.util.concurrent.atomic.AtomicLong

/**
 * Thread-safe 64-bit sequence counter.
 *
 * Requirements:
 * - Strictly increasing positive int64 starting from 1 (up to Long.MAX_VALUE).
 * - Canonical decimal format without leading zeros or exponential notations.
 * - Persistent across app restarts: value is committed to disk before use so process
 *   death cannot reuse a sequence.
 * - Reset to 0 when re-attesting/re-registering with the backend.
 * - Thread-safe under high concurrency.
 */
object AtomicSequenceGenerator {
    private const val PREFS_NAME = "security_demo_prefs"
    private const val KEY_SEQUENCE = "sequence"

    private val counter = AtomicLong(0)
    private var preferences: SharedPreferences? = null

    @Synchronized
    fun configure(context: Context) {
        if (preferences == null) {
            preferences = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val savedSeq = preferences!!.getLong(KEY_SEQUENCE, 0L)
            initialize(savedSeq)
        }
    }

    /**
     * Overload for testing or direct preference injection.
     */
    @Synchronized
    fun configure(prefs: SharedPreferences?) {
        preferences = prefs
        if (prefs != null) {
            val savedSeq = prefs.getLong(KEY_SEQUENCE, 0L)
            initialize(savedSeq)
        }
    }

    @Synchronized
    fun initialize(lastSavedSeq: Long) {
        require(lastSavedSeq >= 0L) { "Initial sequence must be non-negative" }
        counter.set(maxOf(counter.get(), lastSavedSeq))
    }

    @Synchronized
    fun currentSequence(): Long {
        return counter.get()
    }

    /**
     * Resets the sequence counter to a given base (default 0).
     * The next sequence produced will be base + 1 (e.g. 1).
     */
    @Synchronized
    fun reset(newSeq: Long = 0L) {
        require(newSeq >= 0L) { "Reset sequence must be non-negative" }
        preferences?.let { prefs ->
            check(prefs.edit().putLong(KEY_SEQUENCE, newSeq).commit()) { "Failed to persist sequence reset" }
        }
        counter.set(newSeq)
    }

    /**
     * Generates the next sequence number (strictly increasing, starting from 1).
     * Atomically commits to SharedPreferences before returning to prevent sequence reuse on crash.
     */
    @Synchronized
    fun nextSequence(): Long {
        check(counter.get() < Long.MAX_VALUE) { "Sequence number exhausted (reached Long.MAX_VALUE)" }
        val next = counter.incrementAndGet()
        preferences?.let { prefs ->
            check(prefs.edit().putLong(KEY_SEQUENCE, next).commit()) { "Failed to persist sequence counter" }
        }
        return next
    }

    /**
     * Returns the next sequence formatted as a canonical decimal string without leading zeros.
     */
    @Synchronized
    fun nextSequenceString(): String {
        return nextSequence().toString()
    }
}
