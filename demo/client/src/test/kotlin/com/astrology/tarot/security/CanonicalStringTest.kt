package com.astrology.tarot.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

class CanonicalStringTest {

    @Test
    fun testEmptyBodyHash() {
        val emptyBytes = ByteArray(0)
        val hash = AttestationSigningInterceptor.computeSha256Hex(emptyBytes)
        // SHA-256 of empty string is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash)
    }

    @Test
    fun testNonEmptyBodyHash() {
        val body = "{\"question\":\"demo\"}"
        val hash = AttestationSigningInterceptor.computeSha256Hex(body.toByteArray(Charsets.UTF_8))
        // Verify lowercase hex
        assertTrue(hash.matches(Regex("^[0-9a-f]{64}$")))
    }

    @Test
    fun testCanonicalStringFormat() {
        val timestamp = "1710000000000"
        val sequence = "1"
        val method = "post"
        val target = "/api/tarot/read?param=b&param=a"
        val body = "{\"hello\":\"world\"}"
        val bodyHash = AttestationSigningInterceptor.computeSha256Hex(body.toByteArray(Charsets.UTF_8))

        val canonical = AttestationSigningInterceptor.buildCanonicalString(
            timestamp = timestamp,
            sequence = sequence,
            method = method,
            requestTarget = target,
            bodySha256Hex = bodyHash
        )

        val expected = "1710000000000:1:POST:/api/tarot/read?param=b&param=a:$bodyHash"
        assertEquals(expected, canonical)
    }

    @Test
    fun testMethodIsAlwaysUppercased() {
        val canonicalGet = AttestationSigningInterceptor.buildCanonicalString(
            "100", "1", "get", "/api/tarot/status", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assertTrue(canonicalGet.contains(":GET:"))

        val canonicalPost = AttestationSigningInterceptor.buildCanonicalString(
            "100", "2", "Post", "/api/tarot/read", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assertTrue(canonicalPost.contains(":POST:"))
    }

    @Test
    fun testTargetPreservesRawEncodingWithoutDecoding() {
        // Encoded slashes or parameters must NOT be decoded or re-ordered
        val target = "/api/tarot/read?special=%2F&raw=1&z=2&a=1"
        val canonical = AttestationSigningInterceptor.buildCanonicalString(
            timestamp = "100",
            sequence = "2",
            method = "GET",
            requestTarget = target,
            bodySha256Hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assertEquals("100:2:GET:/api/tarot/read?special=%2F&raw=1&z=2&a=1:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", canonical)
    }
}
