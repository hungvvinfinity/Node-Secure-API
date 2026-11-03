package com.astrology.tarot.security

import com.google.gson.Gson
import com.google.gson.JsonParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.util.UUID

class ApiResponseException(
    val statusCode: Int,
    val errorCode: String?,
    val responseBody: String
) : Exception("HTTP $statusCode: $responseBody")

/**
 * Handles safe request retries adhering to CLIENT_PROTOCOL.md:
 *
 * "Không phát lại nguyên gói đã ký. Mỗi retry lấy sequence/timestamp mới, tạo signature mới;
 *  giữ idempotency key trong body đã ký. Nếu server đã commit sequence nhưng response bị mất,
 *  retry sequence cũ phải bị từ chối."
 */
class RetryHelper(private val api: ApiClient) {
    private val gson = Gson()
    private val jsonMediaType = "application/json; charset=utf-8".toMediaType()

    suspend fun readTarotWithRetry(
        question: String,
        maxRetries: Int = 3,
        idempotencyKey: String = UUID.randomUUID().toString(),
        onSuccess: (Request, String) -> Unit = { _, _ -> }
    ): Result<String> {
        require(maxRetries > 0) { "maxRetries must be greater than 0" }

        // The business idempotency key remains invariant across all retry attempts
        val payload = gson.toJson(
            mapOf(
                "question" to question,
                "idempotencyKey" to idempotencyKey
            )
        )

        repeat(maxRetries) { attempt ->
            try {
                // Must be executed with Serialization Queue to maintain strict wire ordering
                val result = RequestSerializationQueue.executeSerialized {
                    withContext(Dispatchers.IO) {
                        // Creating a new Request and passing through httpClient ensures
                        // the AttestationSigningInterceptor generates a fresh sequence,
                        // fresh timestamp, and fresh cryptographic signature for this attempt.
                        val request = Request.Builder()
                            .url("${api.baseUrl}/api/tarot/read")
                            .header("Idempotency-Key", idempotencyKey)
                            .post(payload.toRequestBody(jsonMediaType))
                            .build()

                        api.httpClient.newCall(request).execute().use { response ->
                            val bodyStr = response.body?.string().orEmpty()

                            // Server transient errors (5xx, 429) warrant retry
                            if (response.code >= 500 || response.code == 429) {
                                throw IOException("Transient server error ${response.code}: $bodyStr")
                            }

                            if (!response.isSuccessful) {
                                val errorCode = runCatching {
                                    JsonParser.parseString(bodyStr).asJsonObject.get("error")?.asString
                                }.getOrNull()
                                throw ApiResponseException(response.code, errorCode, bodyStr)
                            }

                            onSuccess(response.request, bodyStr)
                            bodyStr
                        }
                    }
                }
                return Result.success(result)
            } catch (e: IOException) {
                if (attempt == maxRetries - 1) {
                    return Result.failure(e)
                }
                delay(1000L * (attempt + 1))
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                return Result.failure(e)
            }
        }

        return Result.failure(IllegalStateException("Exhausted all $maxRetries retry attempts"))
    }
}
