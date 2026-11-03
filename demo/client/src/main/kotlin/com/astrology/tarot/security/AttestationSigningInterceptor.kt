package com.astrology.tarot.security

import okhttp3.Interceptor
import okhttp3.Response
import okio.Buffer
import java.security.MessageDigest

/**
 * OkHttp Interceptor that generates cryptographic attestation headers for protected endpoints.
 *
 * Canonical specification (CLIENT_PROTOCOL.md & src/core/canonical.ts):
 *   timestamp:sequence:METHOD:request-target:bodySha256Hex
 *
 * - timestamp: milliseconds as received in header (decimal string)
 * - sequence: canonical decimal positive int64 without leading zeros
 * - METHOD: uppercase HTTP method (POST, GET, etc.)
 * - request-target: raw encodedPath + encodedQuery as received on the wire
 * - bodySha256Hex: lowercase hex digest of raw body bytes (empty body uses SHA256 of empty byte array)
 *
 * Signature:
 * - SHA256withECDSA on canonical UTF-8 bytes using hardware private key in AndroidKeyStore.
 * - DER sequence (r, s), Base64 NO_WRAP.
 *
 * Headers added:
 * - X-Device-Id
 * - X-Timestamp
 * - X-Sequence
 * - X-Signature
 *
 * Concurrency & Serialization:
 * Directly serializes the entire cycle inside the interceptor:
 * nextSequence() -> canonical -> sign -> chain.proceed -> receive response.
 * This guarantees that concurrent requests through httpClient cannot reorder or race on the wire.
 */
class AttestationSigningInterceptor(
    private val deviceIdProvider: () -> String?
) : Interceptor {

    companion object {
        const val HEADER_DEVICE_ID = "X-Device-Id"
        const val HEADER_TIMESTAMP = "X-Timestamp"
        const val HEADER_SEQUENCE = "X-Sequence"
        const val HEADER_SIGNATURE = "X-Signature"

        // Global wire lock ensuring strict total ordering across all threads
        val wireLock = Any()

        fun computeSha256Hex(bytes: ByteArray): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
            val hexString = StringBuilder(digest.size * 2)
            for (b in digest) {
                hexString.append(String.format("%02x", b.toInt() and 0xff))
            }
            return hexString.toString()
        }

        fun buildCanonicalString(
            timestamp: String,
            sequence: String,
            method: String,
            requestTarget: String,
            bodySha256Hex: String
        ): String {
            return "$timestamp:$sequence:${method.uppercase()}:$requestTarget:$bodySha256Hex"
        }
    }

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        val path = request.url.encodedPath

        // Only sign protected endpoints (e.g. /api/tarot/...)
        // Bypass control endpoints (/api/auth/challenge, /api/auth/register-device, /health, /ready)
        if (!isProtectedEndpoint(path)) {
            return chain.proceed(request)
        }

        // Lock covers the entire sequence -> sign -> send -> response cycle.
        // Prevents out-of-order arrival and guarantees strict sequence monotony on the wire.
        synchronized(wireLock) {
            val deviceId = deviceIdProvider()
                ?: throw IllegalStateException("Device ID not registered yet. Please register device before calling protected API.")

            // 1. Calculate Request Target: encoded path + raw query
            val target = request.url.encodedPath + (request.url.encodedQuery?.let { "?$it" } ?: "")

            // 2. Read body bytes and calculate SHA-256 lowercase hex
            val body = request.body
            val rawBodyBytes = if (body != null) {
                require(!body.isOneShot() && !body.isDuplex()) {
                    "Cannot sign a streaming or one-shot request body"
                }
                val buffer = Buffer()
                body.writeTo(buffer)
                buffer.readByteArray()
            } else {
                ByteArray(0)
            }
            val bodyHash = computeSha256Hex(rawBodyBytes)

            // 3. Acquire sequence & timestamp strictly inside the synchronization lock
            val timestamp = System.currentTimeMillis().toString()
            val sequence = AtomicSequenceGenerator.nextSequenceString()

            // 4. Build canonical string
            val canonical = buildCanonicalString(
                timestamp = timestamp,
                sequence = sequence,
                method = request.method,
                requestTarget = target,
                bodySha256Hex = bodyHash
            )

            // 5. Sign with hardware private key
            val signature = KeystoreManager.signData(canonical)

            // 6. Attach headers and proceed over the wire
            val signedRequest = request.newBuilder()
                .header(HEADER_DEVICE_ID, deviceId)
                .header(HEADER_TIMESTAMP, timestamp)
                .header(HEADER_SEQUENCE, sequence)
                .header(HEADER_SIGNATURE, signature)
                .build()

            return chain.proceed(signedRequest)
        }
    }

    private fun isProtectedEndpoint(path: String): Boolean {
        return path.startsWith("/api/tarot")
    }
}
