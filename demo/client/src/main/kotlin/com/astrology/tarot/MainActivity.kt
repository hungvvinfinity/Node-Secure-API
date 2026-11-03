package com.astrology.tarot

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.astrology.tarot.security.ApiClient
import com.astrology.tarot.security.ApiResponseException
import com.astrology.tarot.security.AtomicSequenceGenerator
import com.astrology.tarot.security.AttestationSigningInterceptor
import com.astrology.tarot.security.KeystoreManager
import com.astrology.tarot.security.RetryHelper
import com.astrology.tarot.security.SecurityTierManager
import com.google.gson.Gson
import com.google.gson.JsonParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.Headers
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okio.Buffer
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

class MainActivity : AppCompatActivity() {

    private lateinit var etServerUrl: EditText
    private lateinit var tvDeviceId: TextView
    private lateinit var tvTier: TextView
    private lateinit var tvHwLevel: TextView
    private lateinit var tvSequence: TextView
    private lateinit var tvConsole: TextView
    private lateinit var svLog: ScrollView
    private lateinit var buttons: List<Button>

    // Un-intercepted raw OkHttpClient for executing replay, tamper, and expired attacks
    private val rawAttackClient = OkHttpClient.Builder()
        .retryOnConnectionFailure(false)
        .followRedirects(false)
        .followSslRedirects(false)
        .build()

    private val dateFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
    private val gson = Gson()
    private val jsonMediaType = "application/json; charset=utf-8".toMediaType()

    private data class SavedSignedPacket(
        val url: String,
        val headers: Headers,
        val bodyBytes: ByteArray,
        val contentType: MediaType?
    )

    private var lastSignedPacket: SavedSignedPacket? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        etServerUrl = findViewById(R.id.etServerUrl)
        tvDeviceId = findViewById(R.id.tvDeviceId)
        tvTier = findViewById(R.id.tvTier)
        tvHwLevel = findViewById(R.id.tvHwLevel)
        tvSequence = findViewById(R.id.tvSequence)
        tvConsole = findViewById(R.id.tvConsole)
        svLog = findViewById(R.id.svLog)

        val btnRegister = findViewById<Button>(R.id.btnRegister)
        val btnReadTarot = findViewById<Button>(R.id.btnReadTarot)
        val btnTestReplay = findViewById<Button>(R.id.btnTestReplay)
        val btnTestTamper = findViewById<Button>(R.id.btnTestTamper)
        val btnTestExpired = findViewById<Button>(R.id.btnTestExpired)

        buttons = listOf(btnRegister, btnReadTarot, btnTestReplay, btnTestTamper, btnTestExpired)

        val initialClient = ApiClient(this)
        etServerUrl.setText(initialClient.baseUrl)
        updateHeaderStatus(initialClient)

        // Detect and display hardware security level (StrongBox, TEE, or Software)
        val hwLevel = KeystoreManager.getOrDetectHardwareSecurityLevel(this)
        tvHwLevel.text = "Hardware Level: $hwLevel"
        log("Hệ thống khởi tạo thành công. Phần cứng: $hwLevel | Server: ${initialClient.baseUrl}")

        // 1. Button Register
        btnRegister.setOnClickListener {
            runAction {
                val api = getOrCreateClient() ?: return@runAction
                log("--- BẮT ĐẦU ĐĂNG KÝ THIẾT BỊ ---")
                log("1. Gửi POST /api/auth/challenge tới ${api.baseUrl}...")
                lastSignedPacket = null

                val result = api.registerDeviceOnce(force = true)
                updateHeaderStatus(api)

                if (result.isSuccess) {
                    val assignedId = result.getOrNull()
                    log("✅ Đăng ký thành công! Server cấp Device ID: $assignedId")
                    log("Đã lưu khóa EC P-256 trong Keystore và reset sequence về 0.")
                } else {
                    log("❌ Đăng ký thất bại: ${result.exceptionOrNull()?.message}")
                }
            }
        }

        // 2. Button Read Tarot
        btnReadTarot.setOnClickListener {
            runAction {
                val api = getOrCreateClient() ?: return@runAction
                log("--- GỌI API TAROT BẢO VỆ ---")

                if (!api.isDeviceRegistered()) {
                    log("Thiết bị chưa đăng ký. Đang tự động đăng ký với server...")
                    val regResult = api.registerDeviceOnce(force = true)
                    updateHeaderStatus(api)
                    if (regResult.isFailure) {
                        log("❌ Không thể đăng ký: ${regResult.exceptionOrNull()?.message}")
                        return@runAction
                    }
                }

                log("Đang tạo chữ ký số SHA256withECDSA với canonical string và gửi request...")
                var savedPacket: SavedSignedPacket? = null
                val idempotencyKey = UUID.randomUUID().toString()

                suspend fun doReadTarot(): Result<String> {
                    return RetryHelper(api).readTarotWithRetry(
                        question = "Hôm nay vận mệnh và bảo mật thế nào?",
                        idempotencyKey = idempotencyKey,
                        onSuccess = { request, responseBody ->
                            val buffer = Buffer()
                            request.body?.writeTo(buffer)
                            savedPacket = SavedSignedPacket(
                                url = request.url.toString(),
                                headers = request.headers,
                                bodyBytes = buffer.readByteArray(),
                                contentType = request.body?.contentType()
                            )
                        }
                    )
                }

                var tarotResult = doReadTarot()
                val failure = tarotResult.exceptionOrNull() as? ApiResponseException

                // Auto-recover if server restarted or device state lost (401)
                if (failure?.statusCode == 401 && failure.errorCode in setOf("OTP_REQUIRED", "DEVICE_NOT_REGISTERED", "DEVICE_NOT_FOUND")) {
                    log("Server yêu cầu đồng bộ lại thiết bị [401 ${failure.errorCode}]. Đang re-register...")
                    val reReg = api.registerDeviceOnce(force = true)
                    updateHeaderStatus(api)
                    if (reReg.isSuccess) {
                        log("Đăng ký lại thành công! Thử lại request Tarot...")
                        tarotResult = doReadTarot()
                    }
                }

                updateHeaderStatus(api)

                if (tarotResult.isSuccess) {
                    lastSignedPacket = savedPacket
                    val body = tarotResult.getOrNull()
                    log("✅ Tarot thành công: $body")
                    log("Đã lưu gói tin đã ký (Seq: ${AtomicSequenceGenerator.currentSequence()}) để thử nghiệm tấn công.")
                } else {
                    log("❌ Tarot thất bại: ${tarotResult.exceptionOrNull()?.message}")
                }
            }
        }

        // 3. Button Test Replay
        btnTestReplay.setOnClickListener {
            runAction {
                val packet = lastSignedPacket
                if (packet == null) {
                    log("⚠️ Vui lòng bấm Nút 2 trước để có gói tin mẫu đã ký!")
                    return@runAction
                }

                log("--- THỬ TẤN CÔNG REPLAY ---")
                log("Phát lại nguyên vẹn gói tin cũ (cùng Sequence ${packet.headers["X-Sequence"]}, Timestamp, Signature)...")

                val (code, body) = withContext(Dispatchers.IO) {
                    val request = Request.Builder()
                        .url(packet.url)
                        .headers(packet.headers)
                        .post(packet.bodyBytes.toRequestBody(packet.contentType))
                        .build()

                    rawAttackClient.newCall(request).execute().use { response ->
                        response.code to response.body?.string().orEmpty()
                    }
                }

                val error = runCatching {
                    JsonParser.parseString(body).asJsonObject.get("error")?.asString
                }.getOrNull()

                if (code == 401 && error in setOf("REPLAY_DETECTED", "EXPIRED_TIMESTAMP")) {
                    log("🛡️ AN NINH HOÀN HẢO: Server đã CHẶN ĐỨNG gói tin Replay [Mã HTTP $code: $error]!")
                } else {
                    log("❌ Kết quả không mong đợi: HTTP $code | Response: $body")
                }
            }
        }

        // 4. Button Test Tamper
        btnTestTamper.setOnClickListener {
            runAction {
                val packet = lastSignedPacket
                if (packet == null) {
                    log("⚠️ Vui lòng bấm Nút 2 trước để có gói tin mẫu đã ký!")
                    return@runAction
                }

                log("--- THỬ TẤN CÔNG SỬA ĐỔI NỘI DUNG (TAMPER) ---")
                log("Giữ nguyên 4 Headers an ninh nhưng tráo đổi nội dung Body...")

                val tamperedBody = gson.toJson(
                    mapOf(
                        "question" to "NỘI DUNG ĐÃ BỊ HACKER THAY ĐỔI!",
                        "idempotencyKey" to UUID.randomUUID().toString()
                    )
                )

                val (code, body) = withContext(Dispatchers.IO) {
                    val request = Request.Builder()
                        .url(packet.url)
                        .headers(packet.headers)
                        .post(tamperedBody.toRequestBody(packet.contentType))
                        .build()

                    rawAttackClient.newCall(request).execute().use { response ->
                        response.code to response.body?.string().orEmpty()
                    }
                }

                val error = runCatching {
                    JsonParser.parseString(body).asJsonObject.get("error")?.asString
                }.getOrNull()

                if (code == 401 && error == "INVALID_SIGNATURE") {
                    log("🛡️ TOÀN VẸN TUYỆT ĐỐI: Server phát hiện băm SHA256 không khớp và CHẶN ĐỨNG [Mã 401: $error]!")
                } else {
                    log("❌ Kết quả không mong đợi: HTTP $code | Response: $body")
                }
            }
        }

        // 5. Button Test Expired Timestamp
        btnTestExpired.setOnClickListener {
            runAction {
                val api = getOrCreateClient() ?: return@runAction
                if (!api.isDeviceRegistered() || api.deviceId.isNullOrEmpty()) {
                    log("⚠️ Cần đăng ký thiết bị trước.")
                    return@runAction
                }

                log("--- THỬ TẤN CÔNG TIMESTAMP QUÁ HẠN (>15s) ---")
                val expiredTimestamp = (System.currentTimeMillis() - 30_000L).toString()
                val seq = AtomicSequenceGenerator.nextSequenceString()
                val payload = gson.toJson(mapOf("question" to "Thử timestamp cũ"))
                val bodyBytes = payload.toByteArray(Charsets.UTF_8)
                val bodyHash = AttestationSigningInterceptor.computeSha256Hex(bodyBytes)
                val target = "/api/tarot/read"

                val canonical = AttestationSigningInterceptor.buildCanonicalString(
                    timestamp = expiredTimestamp,
                    sequence = seq,
                    method = "POST",
                    requestTarget = target,
                    bodySha256Hex = bodyHash
                )
                val signature = KeystoreManager.signData(canonical)

                val (code, body) = withContext(Dispatchers.IO) {
                    val request = Request.Builder()
                        .url("${api.baseUrl}$target")
                        .header("Content-Type", "application/json; charset=utf-8")
                        .header("X-Device-Id", api.deviceId!!)
                        .header("X-Timestamp", expiredTimestamp)
                        .header("X-Sequence", seq)
                        .header("X-Signature", signature)
                        .post(bodyBytes.toRequestBody(jsonMediaType))
                        .build()

                    rawAttackClient.newCall(request).execute().use { response ->
                        response.code to response.body?.string().orEmpty()
                    }
                }

                val error = runCatching {
                    JsonParser.parseString(body).asJsonObject.get("error")?.asString
                }.getOrNull()

                if (code == 401 && error == "EXPIRED_TIMESTAMP") {
                    log("🛡️ ĐỘ TƯƠI ĐƯỢC BẢO VỆ: Server từ chối gói tin quá hạn [Mã 401: $error]!")
                } else {
                    log("❌ Kết quả không mong đợi: HTTP $code | Response: $body")
                }
                updateHeaderStatus(api)
            }
        }
    }

    private fun getOrCreateClient(): ApiClient? {
        val url = etServerUrl.text.toString().trim()
        return try {
            val api = ApiClient(this, url)
            ApiClient.saveServerUrl(this, url)
            api
        } catch (e: Exception) {
            log("❌ URL server không hợp lệ: ${e.message}")
            null
        }
    }

    private fun updateHeaderStatus(api: ApiClient) {
        tvDeviceId.text = "Device ID: ${api.deviceId ?: "(chưa đăng ký)"}"
        tvTier.text = "Tier: ${SecurityTierManager.determineSecurityTier(this)}"
        tvSequence.text = "Seq: ${AtomicSequenceGenerator.currentSequence()}"
    }

    private fun runAction(action: suspend () -> Unit) {
        buttons.forEach { it.isEnabled = false }
        lifecycleScope.launch {
            try {
                action()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                log("❌ Lỗi: ${e.message}")
            } finally {
                buttons.forEach { it.isEnabled = true }
            }
        }
    }

    private fun log(message: String) {
        tvConsole.append("\n[${dateFormat.format(Date())}] $message")
        svLog.post { svLog.fullScroll(ScrollView.FOCUS_DOWN) }
    }
}
