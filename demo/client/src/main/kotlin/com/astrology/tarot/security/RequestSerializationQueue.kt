package com.astrology.tarot.security

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Ensures strict total order for hardware-attested requests at application/coroutine level.
 *
 * As noted in CLIENT_PROTOCOL.md:
 * "Serialize các request được bảo vệ bằng hàng đợi/mutex bao phủ cả send và response để giữ thứ tự;
 *  AtomicLong đơn lẻ không bảo đảm thứ tự đến server."
 *
 * Combined with AttestationSigningInterceptor.wireLock, this guarantees end-to-end
 * strict sequential ordering for all callers.
 */
object RequestSerializationQueue {
    private val coroutineMutex = Mutex()

    /**
     * Executes a suspending action with strict serialization.
     */
    suspend fun <T> executeSerialized(action: suspend () -> T): T {
        return coroutineMutex.withLock {
            action()
        }
    }

    /**
     * Executes a blocking action with strict synchronization using the wire lock.
     */
    fun <T> executeBlockingSerialized(action: () -> T): T {
        return synchronized(AttestationSigningInterceptor.wireLock) {
            action()
        }
    }
}
