package com.astrology.tarot.security

import android.content.Context
import android.content.SharedPreferences
import com.google.gson.Gson
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
import java.util.concurrent.TimeUnit

class HardwareAttestationRejectedException(message: String) : Exception(message)

/**
 * Dual-Tier Android API client for Node-Secure-API server.
 *
 * Responsibilities:
 * 1. Obtains hardware attestation challenge + PoW puzzle from /api/auth/challenge.
 * 2. Attempts Tier 1 (Hardware VIP) registration via AndroidKeyStore Key Attestation.
 * 3. Gracefully falls back to Tier 2 (Software Protected) by solving the PoW puzzle
 *    and registering standard EC P-256 SPKI PEM.
 * 4. Manages rolling 2-hour lease for software tier with silent background renewal.
 * 5. Respects client-side serialization queue and OkHttp timeouts for 3.0s tarpit delay.
 */
class ApiClient {
    private val context: Context?
    private val prefs: SharedPreferences?
    private val gson = Gson()
    private val jsonMediaType = "application/json; charset=utf-8".toMediaType()

    val baseUrl: String
    var deviceId: String? = null
        private set
    var tier: String = "hardware"
        private set
    var leaseExpiresAt: Long = 0L
        private set
    var clockOffsetMs: Long = 0L
        internal set

    // Independent un-intercepted client for registration & control calls (with adequate timeout for PoW/reg)
    private val controlClient: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .retryOnConnectionFailure(false)
        .followRedirects(false)
        .followSslRedirects(false)
        .build()

    // Protected client configured with AttestationSigningInterceptor
    // readTimeout >= 30s to comfortably tolerate 3.0s tarpit delay on Software Tier
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
        this.tier = sp.getString(KEY_TIER, "hardware") ?: "hardware"
        this.leaseExpiresAt = sp.getLong(KEY_EXPIRES_AT, 0L)
        this.clockOffsetMs = sp.getLong(KEY_CLOCK_OFFSET, 0L)
        currentAdjustedTime = { this.getAdjustedTimestamp() }

        // Restore KeystoreManager active tier on app startup
        KeystoreManager.activeTier = this.tier

        this.httpClient = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS) // Accommodates 3.0s tarpit delay
            .writeTimeout(30, TimeUnit.SECONDS)
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
        initialDeviceId: String? = "test-device-id",
        initialTier: String = "hardware"
    ) {
        this.context = null
        this.prefs = null
        this.baseUrl = normalizeUrl(baseUrl)
        this.deviceId = initialDeviceId
        this.tier = initialTier
        this.leaseExpiresAt = 0L
        this.clockOffsetMs = 0L
        currentAdjustedTime = { this.getAdjustedTimestamp() }
        this.httpClient = customHttpClient
    }

    /**
     * Returns current epoch milliseconds adjusted for server clock skew.
     */
    fun getAdjustedTimestamp(): Long = System.currentTimeMillis() + clockOffsetMs

    /**
     * Checks if the device has a valid registered deviceId and active key.
     * Also checks if the lease has not expired for software tier.
     */
    fun isDeviceRegistered(): Boolean {
        val sp = prefs ?: return !deviceId.isNullOrEmpty()
        val registered = sp.getBoolean(KEY_REGISTERED, false)
        val registeredUrl = sp.getString(KEY_REGISTERED_URL, null)

        if (!registered || registeredUrl != baseUrl || deviceId.isNullOrEmpty() || !KeystoreManager.isDeviceKeyReady()) {
            return false
        }

        if (tier == "software") {
            val expiresAt = sp.getLong(KEY_EXPIRES_AT, 0L)
            if (expiresAt > 0 && System.currentTimeMillis() >= expiresAt) {
                return false // Lease expired
            }
        }

        return true
    }

    // Optional mock registration handler for JVM unit tests where Android Context is unavailable
    internal var testRegistrationHandler: (suspend (force: Boolean) -> Result<String>)? = null

    /**
     * Registers the device with the Node-Secure-API server using Dual-Tier Strategy:
     * 1. Request challenge and PoW params from /api/auth/challenge.
     * 2. Try Tier 1 (Hardware Attestation).
     * 3. Fallback to Tier 2 (Software Key + PoW solution) if hardware attestation fails or is rejected.
     */
    suspend fun registerDeviceOnce(force: Boolean = false): Result<String> = registrationMutex.withLock {
        testRegistrationHandler?.let { return it(force) }
        withContext(Dispatchers.IO) {
            try {
                if (!force && isDeviceRegistered()) {
                    return@withContext Result.success(deviceId!!)
                }

                val sp = checkNotNull(prefs) { "Registration requires Android Context" }

                // Step 1: Request challenge + PoW parameters
                val challengeReq = Request.Builder()
                    .url("$baseUrl/api/auth/challenge")
                    .post(gson.toJson(mapOf("platform" to "android")).toRequestBody(jsonMediaType))
                    .build()

                val (challenge, powSalt, powDifficulty) = controlClient.newCall(challengeReq).execute().use { response ->
                    val bodyStr = response.body?.string().orEmpty()
                    if (!response.isSuccessful) {
                        throw IOException("Challenge request failed (${response.code}): $bodyStr")
                    }
                    val json = JsonParser.parseString(bodyStr).asJsonObject
                    val ch = json.get("challenge")?.asString
                        ?: throw IllegalStateException("Missing challenge in response: $bodyStr")

                    // Extract and synchronize dynamic server time offset
                    val serverTime = if (json.has("serverTime") && !json.get("serverTime").isJsonNull) {
                        json.get("serverTime").asLong
                    } else if (json.has("expiresAt") && !json.get("expiresAt").isJsonNull) {
                        json.get("expiresAt").asLong - 60_000L
                    } else {
                        System.currentTimeMillis()
                    }
                    val offset = serverTime - System.currentTimeMillis()
                    clockOffsetMs = offset
                    sp.edit().putLong(KEY_CLOCK_OFFSET, offset).apply()

                    // Extract PoW puzzle parameters
                    val powObj = json.getAsJsonObject("pow") ?: json.getAsJsonObject("powInfo")
                    val salt = powObj?.get("salt")?.asString ?: ""
                    val diff = powObj?.get("difficulty")?.asInt ?: 18
                    Triple(ch, salt, diff)
                }

                sp.edit().putBoolean(KEY_REGISTERED, false).apply()

                var assignedDeviceId: String? = null
                var assignedTier = "hardware"
                var assignedExpiresAt = 0L

                // Step 2: Attempt Tier 1: Hardware VIP Registration
                var hardwareSuccess = false
                var challengeConsumed = false
                try {
                    KeystoreManager.generateAttestedKeyPair(challenge, context)
                    val certChain = KeystoreManager.getCertificateChainBase64()

                    val hardwarePayload = gson.toJson(
                        mapOf(
                            "challenge" to challenge,
                            "certificateChain" to certChain
                        )
                    )

                    val regReq = Request.Builder()
                        .url("$baseUrl/api/auth/register-device")
                        .post(hardwarePayload.toRequestBody(jsonMediaType))
                        .build()

                    challengeConsumed = true // Challenge submitted to server (server consumes on receipt)

                    controlClient.newCall(regReq).execute().use { response ->
                        val bodyStr = response.body?.string().orEmpty()
                        if (response.isSuccessful) {
                            val json = JsonParser.parseString(bodyStr).asJsonObject
                            assignedDeviceId = json.get("deviceId")?.asString
                            assignedTier = json.get("tier")?.asString ?: "hardware"
                            assignedExpiresAt = 0L // Permanent lease
                            hardwareSuccess = true
                        } else {
                            // Hardware attestation rejected by backend policy (e.g. software cert, untrusted root, unlocked bootloader)
                            throw HardwareAttestationRejectedException("Server rejected hardware attestation (${response.code}): $bodyStr")
                        }
                    }
                } catch (e: Exception) {
                    // Hardware generation or server verification failed; proceed to Tier 2 fallback
                    hardwareSuccess = false
                }

                // Step 3: Fallback to Tier 2: Software Protected Registration with PoW
                if (!hardwareSuccess) {
                    var currentChallenge = challenge
                    var currentPowSalt = powSalt
                    var currentPowDifficulty = powDifficulty

                    // If the challenge was consumed by the server during Step 2, request a fresh challenge
                    if (challengeConsumed) {
                        val freshChallengeReq = Request.Builder()
                            .url("$baseUrl/api/auth/challenge")
                            .post(gson.toJson(mapOf("platform" to "android")).toRequestBody(jsonMediaType))
                            .build()

                        controlClient.newCall(freshChallengeReq).execute().use { response ->
                            val bodyStr = response.body?.string().orEmpty()
                            if (!response.isSuccessful) {
                                throw IOException("Fresh challenge request failed (${response.code}): $bodyStr")
                            }
                            val json = JsonParser.parseString(bodyStr).asJsonObject
                            currentChallenge = json.get("challenge")?.asString
                                ?: throw IllegalStateException("Missing challenge in response: $bodyStr")

                            // Synchronize dynamic server time offset on fresh challenge
                            val serverTime = if (json.has("serverTime") && !json.get("serverTime").isJsonNull) {
                                json.get("serverTime").asLong
                            } else if (json.has("expiresAt") && !json.get("expiresAt").isJsonNull) {
                                json.get("expiresAt").asLong - 60_000L
                            } else {
                                System.currentTimeMillis()
                            }
                            val offset = serverTime - System.currentTimeMillis()
                            clockOffsetMs = offset
                            sp.edit().putLong(KEY_CLOCK_OFFSET, offset).apply()

                            val powObj = json.getAsJsonObject("pow") ?: json.getAsJsonObject("powInfo")
                            currentPowSalt = powObj?.get("salt")?.asString ?: ""
                            currentPowDifficulty = powObj?.get("difficulty")?.asInt ?: 18
                        }
                    }

                    // Generate software key pair and export SPKI PEM
                    KeystoreManager.generateSoftwareKeyPair(context)
                    val publicKeyPem = KeystoreManager.getSoftwarePublicKeyPem()

                    // Solve PoW puzzle in client background
                    val powNonce = ProofOfWorkSolver.solveProofOfWork(
                        challenge = currentChallenge,
                        salt = currentPowSalt,
                        difficulty = currentPowDifficulty
                    )

                    val softwarePayload = gson.toJson(
                        mapOf(
                            "challenge" to currentChallenge,
                            "publicKeyPem" to publicKeyPem,
                            "powNonce" to powNonce
                        )
                    )

                    val regReq = Request.Builder()
                        .url("$baseUrl/api/auth/register-device")
                        .post(softwarePayload.toRequestBody(jsonMediaType))
                        .build()

                    controlClient.newCall(regReq).execute().use { response ->
                        val bodyStr = response.body?.string().orEmpty()
                        if (!response.isSuccessful) {
                            throw IOException("Software tier registration failed (${response.code}): $bodyStr")
                        }
                        val json = JsonParser.parseString(bodyStr).asJsonObject
                        assignedDeviceId = json.get("deviceId")?.asString
                            ?: throw IllegalStateException("Missing deviceId in registration response: $bodyStr")
                        assignedTier = json.get("tier")?.asString ?: "software"
                        // 2-hour rolling lease (prefer exact server expiresAt if returned)
                        assignedExpiresAt = if (json.has("expiresAt") && !json.get("expiresAt").isJsonNull) {
                            json.get("expiresAt").asLong
                        } else {
                            System.currentTimeMillis() + 2 * 3600 * 1000L
                        }
                    }
                }

                val finalDeviceId = assignedDeviceId
                    ?: throw IllegalStateException("Failed to obtain deviceId from registration")

                // Step 4: Reset local sequence counter to 0 (server lastSequence = 0)
                AtomicSequenceGenerator.reset(0L)

                // Step 5: Persist device ID, tier, and lease expiration
                deviceId = finalDeviceId
                tier = assignedTier
                leaseExpiresAt = assignedExpiresAt
                KeystoreManager.activeTier = assignedTier

                val committed = sp.edit()
                    .putString(KEY_DEVICE_ID, finalDeviceId)
                    .putString(KEY_TIER, assignedTier)
                    .putLong(KEY_EXPIRES_AT, assignedExpiresAt)
                    .putBoolean(KEY_REGISTERED, true)
                    .putString(KEY_REGISTERED_URL, baseUrl)
                    .commit()

                if (!committed) {
                    throw IllegalStateException("Failed to commit device registration state")
                }

                Result.success(finalDeviceId)
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
        const val DEFAULT_BASE_URL = "http://10.40.40.2:3000"
        private const val PREFS_NAME = "app_secure_prefs"
        private const val KEY_SERVER_URL = "SERVER_BASE_URL"
        private const val KEY_DEVICE_ID = "DEVICE_ID"
        private const val KEY_TIER = "device_tier"
        private const val KEY_EXPIRES_AT = "lease_expires_at"
        private const val KEY_REGISTERED = "registered"
        private const val KEY_REGISTERED_URL = "registered_server_url"
        const val KEY_CLOCK_OFFSET = "clock_offset_ms"

        // Singleton time provider allowing Interceptor to fetch adjusted time
        var currentAdjustedTime: (() -> Long)? = null

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
