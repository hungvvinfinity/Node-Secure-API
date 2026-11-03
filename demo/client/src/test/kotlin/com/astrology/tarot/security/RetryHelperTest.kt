package com.astrology.tarot.security

import com.google.gson.JsonParser
import kotlinx.coroutines.runBlocking
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.Buffer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.UUID

class RetryHelperTest {

    private data class RecordedCall(
        val request: Request,
        val bodyString: String,
        val sequence: Long,
        val timestamp: Long,
        val signature: String
    )

    private val recordedCalls = mutableListOf<RecordedCall>()
    private var callCount = 0

    @Before
    fun setUp() {
        recordedCalls.clear()
        callCount = 0
        AtomicSequenceGenerator.configure(null as android.content.SharedPreferences?)
        AtomicSequenceGenerator.reset(0L)

        // Mock signer for JVM unit tests
        KeystoreManager.testSigner = { canonical ->
            "sig_for_${canonical.hashCode()}"
        }
    }

    @After
    fun tearDown() {
        KeystoreManager.testSigner = null
    }

    @Test
    fun testPreservesIdempotencyKeyAndGeneratesFreshSequenceAndTimestampOnRetry() = runBlocking {
        val testBaseUrl = "http://localhost:3000"
        val fixedDeviceId = "dev_test_device_123"

        // Mock Server Interceptor: Fails first attempt with 500, succeeds second attempt with 200
        val mockServerInterceptor = Interceptor { chain ->
            val req = chain.request()
            callCount++

            // Record request data
            val buffer = Buffer()
            req.body?.writeTo(buffer)
            val bodyStr = buffer.readUtf8()
            val seq = req.header("X-Sequence")?.toLongOrNull() ?: 0L
            val ts = req.header("X-Timestamp")?.toLongOrNull() ?: 0L
            val sig = req.header("X-Signature").orEmpty()

            recordedCalls.add(RecordedCall(req, bodyStr, seq, ts, sig))

            if (callCount == 1) {
                // First attempt fails with transient 500 server error
                Response.Builder()
                    .request(req)
                    .protocol(Protocol.HTTP_1_1)
                    .code(500)
                    .message("Internal Server Error")
                    .body("{\"error\":\"TRANSIENT_SERVER_ERROR\"}".toResponseBody("application/json".toMediaType()))
                    .build()
            } else {
                // Second attempt succeeds with 200 OK
                Response.Builder()
                    .request(req)
                    .protocol(Protocol.HTTP_1_1)
                    .code(200)
                    .message("OK")
                    .body("{\"status\":\"SUCCESS\",\"data\":{\"card\":\"The Star\"}}".toResponseBody("application/json".toMediaType()))
                    .build()
            }
        }

        val testHttpClient = OkHttpClient.Builder()
            .retryOnConnectionFailure(false)
            // Add AttestationSigningInterceptor first
            .addInterceptor(AttestationSigningInterceptor { fixedDeviceId })
            // Add mock server interceptor to simulate server response
            .addInterceptor(mockServerInterceptor)
            .build()

        val apiClient = ApiClient(testBaseUrl, testHttpClient, fixedDeviceId)
        val retryHelper = RetryHelper(apiClient)

        val fixedIdempotencyKey = UUID.randomUUID().toString()
        val result = retryHelper.readTarotWithRetry(
            question = "Will retry succeed?",
            maxRetries = 3,
            idempotencyKey = fixedIdempotencyKey
        )

        // 1. Verification of recovery
        assertTrue("RetryHelper must succeed when second attempt recovers", result.isSuccess)
        assertEquals("Server must be called exactly twice (1 failure + 1 retry success)", 2, recordedCalls.size)

        val call1 = recordedCalls[0]
        val call2 = recordedCalls[1]

        // 2. Verification of Idempotency-Key preservation
        val json1 = JsonParser.parseString(call1.bodyString).asJsonObject
        val json2 = JsonParser.parseString(call2.bodyString).asJsonObject
        val keyInBody1 = json1.get("idempotencyKey")?.asString
        val keyInBody2 = json2.get("idempotencyKey")?.asString

        assertEquals("Idempotency key must match the input key in call 1", fixedIdempotencyKey, keyInBody1)
        assertEquals("Idempotency key must match the input key in call 2", fixedIdempotencyKey, keyInBody2)
        assertEquals("Idempotency key must remain strictly invariant across retries", keyInBody1, keyInBody2)

        // Header Idempotency-Key must also be preserved
        assertEquals(fixedIdempotencyKey, call1.request.header("Idempotency-Key"))
        assertEquals(fixedIdempotencyKey, call2.request.header("Idempotency-Key"))

        // 3. Verification of fresh Sequence generation
        assertEquals("First attempt sequence must be 1", 1L, call1.sequence)
        assertEquals("Second attempt sequence must be 2", 2L, call2.sequence)
        assertTrue("Retry attempt must have higher sequence than previous attempt", call2.sequence > call1.sequence)

        // 4. Verification of fresh Timestamp generation
        assertTrue("Retry attempt timestamp must be >= previous attempt", call2.timestamp >= call1.timestamp)

        // 5. Verification of fresh Signature generation
        assertNotEquals("Signatures must be distinct because canonical string contains fresh sequence/timestamp",
            call1.signature, call2.signature)
    }
}
