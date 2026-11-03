package com.astrology.tarot.security

import android.content.Context
import android.content.SharedPreferences
import com.google.gson.Gson
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException

/**
 * Android API client for Node-Secure-API server.
 *
 * Responsibilities:
 * 1. Obtains hardware attestation challenge from /api/auth/challenge.
 * 2. Generates EC P-256 key pair in AndroidKeyStore with the challenge UTF-8.
 * 3. Registers device by submitting certificate chain to /api/auth/register-device.
 * 4. Persists the server-issued deviceId and resets sequence counter to 0.
 * 5. Executes signed requests to protected business endpoints (/api/tarot/read).
 */
class ApiClient {
    private val context: Context?
    private val prefs: SharedPreferences?
    private val gson = Gson()
    private val jsonMediaType = "application/json; charset=utf-8".toMediaType()

    val baseUrl: String
    var deviceId: String? = null
        private set

    // Independent un-intercepted client for registration & control calls
    private val controlClient: OkHttpClient = OkHttpClient.Builder()
        .retryOnConnectionFailure(false)
        .followRedirects(false)
        .followSslRedirects(false)
        .build()

    // Protected client configured with AttestationSigningInterceptor
    val httpClient: OkHttpClient

    /**
     * Standard Android application constructor.
     */
    constructor(context: Context, customBaseUrl: String? = null) {
        this.context = context
        val sp = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        this.prefs = sp
        this.baseUrl = normalizeUrl(
            customBaseUrl
                ?: sp.getString(KEY_SERVER_URL, null)
                ?: DEFAULT_BASE_URL
        )
        this.deviceId = sp.getString(KEY_DEVICE_ID, null)
        this.httpClient = OkHttpClient.Builder()
            .retryOnConnectionFailure(false) // Must be false: retries must re-sequence and re-sign
            .followRedirects(false)
            .followSslRedirects(false)
            .addInterceptor(AttestationSigningInterceptor { this.deviceId })
            .build()

        AtomicSequenceGenerator.configure(context)
    }

    /**
     * Testing constructor allowing injection of custom client without Android Context.
     */
    internal constructor(
        baseUrl: String,
        customHttpClient: OkHttpClient,
        initialDeviceId: String? = "test-device-id"
    ) {
        this.context = null
        this.prefs = null
        this.baseUrl = normalizeUrl(baseUrl)
        this.deviceId = initialDeviceId
        this.httpClient = customHttpClient
    }

    /**
     * Checks if the device has a valid registered deviceId, matching server URL,
     * and active hardware key in AndroidKeyStore.
     */
    fun isDeviceRegistered(): Boolean {
        val sp = prefs ?: return !deviceId.isNullOrEmpty()
        val registered = sp.getBoolean(KEY_REGISTERED, false)
        val registeredUrl = sp.getString(KEY_REGISTERED_URL, null)
        return registered &&
                registeredUrl == baseUrl &&
                !deviceId.isNullOrEmpty() &&
                KeystoreManager.isDeviceKeyReady()
    }

    /**
     * Registers the device with the Node-Secure-API server.
     * If force is false and device is already registered, returns immediately.
     */
    suspend fun registerDeviceOnce(force: Boolean = false): Result<String> = registrationMutex.withLock {
        withContext(Dispatchers.IO) {
            try {
                if (!force && isDeviceRegistered()) {
                    return@withContext Result.success(deviceId!!)
                }

                val sp = checkNotNull(prefs) { "Registration requires Android Context" }

                // Step 1: Request single-use challenge from server
                val challengeReq = Request.Builder()
                    .url("$baseUrl/api/auth/challenge")
                    .post(gson.toJson(mapOf("platform" to "android")).toRequestBody(jsonMediaType))
                    .build()

                val challenge = controlClient.newCall(challengeReq).execute().use { response ->
                    val bodyStr = response.body?.string().orEmpty()
                    if (!response.isSuccessful) {
                        throw IOException("Challenge request failed (${response.code}): $bodyStr")
                    }
                    val json = JsonParser.parseString(bodyStr).asJsonObject
                    json.get("challenge")?.asString
                        ?: throw IllegalStateException("Missing challenge in response: $bodyStr")
                }

                // Step 2: Invalidate existing registration status and generate new hardware key
                sp.edit().putBoolean(KEY_REGISTERED, false).apply()
                KeystoreManager.generateAttestedKeyPair(challenge, context)
                val certChain = KeystoreManager.getCertificateChainBase64()

                // Step 3: Register device on server
                val registerPayload = gson.toJson(
                    mapOf(
                        "challenge" to challenge,
                        "certificateChain" to certChain
                    )
                )

                val registerReq = Request.Builder()
                    .url("$baseUrl/api/auth/register-device")
                    .post(registerPayload.toRequestBody(jsonMediaType))
                    .build()

                val assignedDeviceId = controlClient.newCall(registerReq).execute().use { response ->
                    val bodyStr = response.body?.string().orEmpty()
                    if (!response.isSuccessful) {
                        throw IOException("Registration failed (${response.code}): $bodyStr")
                    }
                    val json = JsonParser.parseString(bodyStr).asJsonObject
                    json.get("deviceId")?.asString
                        ?: throw IllegalStateException("Missing deviceId in registration response: $bodyStr")
                }

                // Step 4: Atomically reset local sequence counter to 0 (server lastSequence = 0)
                AtomicSequenceGenerator.reset(0L)

                // Step 5: Persist device ID and registered state in non-backup SharedPreferences
                deviceId = assignedDeviceId
                val committed = sp.edit()
                    .putString(KEY_DEVICE_ID, assignedDeviceId)
                    .putBoolean(KEY_REGISTERED, true)
                    .putString(KEY_REGISTERED_URL, baseUrl)
                    .commit()

                if (!committed) {
                    throw IllegalStateException("Failed to commit device registration state to SharedPreferences")
                }

                Result.success(assignedDeviceId)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Result.failure(e)
            }
        }
    }

    /**
     * Executes a signed request with strict total ordering across concurrent callers.
     */
    suspend fun executeSerialized(request: Request): Result<String> {
        return RequestSerializationQueue.executeSerialized {
            withContext(Dispatchers.IO) {
                try {
                    httpClient.newCall(request).execute().use { response ->
                        val body = response.body?.string().orEmpty()
                        if (!response.isSuccessful) {
                            val errorCode = runCatching {
                                JsonParser.parseString(body).asJsonObject.get("error")?.asString
                            }.getOrNull()
                            Result.failure(ApiResponseException(response.code, errorCode, body))
                        } else {
                            Result.success(body)
                        }
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Result.failure(e)
                }
            }
        }
    }

    companion object {
        const val DEFAULT_BASE_URL = "http://10.0.2.2:3000"
        private const val PREFS_NAME = "app_secure_prefs"
        private const val KEY_SERVER_URL = "SERVER_BASE_URL"
        private const val KEY_DEVICE_ID = "DEVICE_ID"
        private const val KEY_REGISTERED = "registered"
        private const val KEY_REGISTERED_URL = "registered_server_url"

        private val registrationMutex = Mutex()

        fun normalizeUrl(url: String): String {
            val parsed = url.trim().toHttpUrl()
            require(
                parsed.encodedPath == "/" &&
                        parsed.query == null &&
                        parsed.fragment == null &&
                        parsed.username.isEmpty() &&
                        parsed.password.isEmpty()
            ) {
                "Server URL must be an HTTP(S) origin without path, query, or credentials: $url"
            }
            return parsed.toString().trimEnd('/')
        }

        fun saveServerUrl(context: Context, url: String) {
            val normalized = normalizeUrl(url)
            val preferences = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            check(preferences.edit().putString(KEY_SERVER_URL, normalized).commit()) {
                "Failed to save server URL"
            }
        }
    }
}
