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
    private lateinit var tvLease: TextView
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
        tvLease = findViewById(R.id.tvLease)
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
        tvHwLevel.text = "HW: $hwLevel"
        val initialOffsetSec = initialClient.clockOffsetMs / 1000
        val offsetSign = if (initialOffsetSec >= 0) "+${initialOffsetSec}s" else "${initialOffsetSec}s"
        log("Hệ thống khởi tạo thành công. Phần cứng: $hwLevel | Lệch đồng hồ: $offsetSign | Server: ${initialClient.baseUrl}")

        // 1. Button Register
        btnRegister.setOnClickListener {
            runAction {
                val api = getOrCreateClient() ?: return@runAction
                log("--- BẮT ĐẦU ĐĂNG KÝ THIẾT BỊ (DUAL-TIER) ---")
                log("1. Xin challenge & PoW puzzle từ ${api.baseUrl}...")
                lastSignedPacket = null

                val result = api.registerDeviceOnce(force = true)
                updateHeaderStatus(api)

                if (result.isSuccess) {
                    val assignedId = result.getOrNull()
                    val tierName = if (api.tier == "hardware") "Tier 1: Hardware VIP" else "Tier 2: Software Protected (PoW)"
                    val offsetSec = api.clockOffsetMs / 1000
                    val offsetStr = if (offsetSec >= 0) "+${offsetSec}s" else "${offsetSec}s"
                    log("✅ Đăng ký thành công! Cấp bậc: $tierName | Device ID: $assignedId | Độ lệch đồng hồ với server: $offsetStr")
                    if (api.tier == "software") {
                        log("ℹ️ Software Tier: Kích hoạt Rolling Lease 2h và Tarpit Delay 3.0s chống botnet.")
                    } else {
                        log("ℹ️ Hardware VIP Tier: Lease vĩnh viễn, 0ms latency fast-track.")
                    }
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
                    log("Thiết bị chưa đăng ký hoặc lease đã hết hạn. Đang đăng ký tự động...")
                    val regResult = api.registerDeviceOnce(force = true)
                    updateHeaderStatus(api)
                    if (regResult.isFailure) {
                        log("❌ Không thể đăng ký: ${regResult.exceptionOrNull()?.message}")
                        return@runAction
                    }
                }

                // Check silent lease renewal if lease is about to expire
                if (SecurityTierManager.isLeaseExpiringSoon(this@MainActivity)) {
                    log("ℹ️ Lease sắp hết hạn (< 5 phút), thực hiện Silent Renewal ngầm...")
                    api.registerDeviceOnce(force = true)
                    updateHeaderStatus(api)
                }

                log("Đang tạo chữ ký số SHA256withECDSA với canonical string và gửi request...")
                if (api.tier == "software") {
                    log("⏳ Đang xử lý qua hàng rào Tarpit Delay 3.0s của Software Tier...")
                }

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

                // Auto-recover on lease expiration, clock skew, or device state loss
                if (failure?.statusCode == 401 && failure.errorCode in setOf("OTP_REQUIRED", "DEVICE_NOT_REGISTERED", "DEVICE_NOT_FOUND", "LEASE_EXPIRED", "DEVICE_LEASE_EXPIRED", "EXPIRED_TIMESTAMP")) {
                    log("Server báo [401 ${failure.errorCode}]. Đang thực hiện Silent Renewal & Time Sync ngầm...")
                    val reReg = api.registerDeviceOnce(force = true)
                    updateHeaderStatus(api)
                    if (reReg.isSuccess) {
                        val offsetSec = api.clockOffsetMs / 1000
                        val offsetStr = if (offsetSec >= 0) "+${offsetSec}s" else "${offsetSec}s"
                        log("Silent Renewal & Time Sync thành công (Độ lệch: $offsetStr)! Đang tự động gọi lại request Tarot...")
                        tarotResult = doReadTarot()
                    }
                } else if (failure?.statusCode == 429 && failure.errorCode == "CONCURRENT_REQUEST_DISALLOWED") {
                    log("🛡️ CONCURRENCY LOCK: Software Tier chặn yêu cầu đồng thời (tối đa 1 request in-flight)!")
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
                val expiredTimestamp = (api.getAdjustedTimestamp() - 30_000L).toString()
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

        handleAutoAction(intent)
    }

    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleAutoAction(intent)
    }

    private fun handleAutoAction(intent: android.content.Intent?) {
        val autoAction = intent?.getStringExtra("AUTO_ACTION") ?: return
        when (autoAction) {
            "REGISTER" -> {
                findViewById<Button>(R.id.btnRegister).postDelayed({
                    findViewById<Button>(R.id.btnRegister).performClick()
                }, 500)
            }
            "READ_TAROT" -> {
                findViewById<Button>(R.id.btnReadTarot).postDelayed({
                    findViewById<Button>(R.id.btnReadTarot).performClick()
                }, 500)
            }
            "TEST_ALL" -> {
                findViewById<Button>(R.id.btnRegister).postDelayed({
                    findViewById<Button>(R.id.btnRegister).performClick()
                    findViewById<Button>(R.id.btnReadTarot).postDelayed({
                        findViewById<Button>(R.id.btnReadTarot).performClick()
                    }, 4000)
                }, 500)
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
        val tierEnum = SecurityTierManager.determineSecurityTier(this)
        tvDeviceId.text = "Device ID: ${api.deviceId ?: "(chưa đăng ký)"}"
        tvTier.text = tierEnum.displayName
        tvSequence.text = "Seq: ${AtomicSequenceGenerator.currentSequence()}"

        val remainingMinutes = SecurityTierManager.getLeaseRemainingMinutes(this)
        tvLease.text = when {
            api.tier == "hardware" -> "Lease: Vĩnh viễn (VIP)"
            remainingMinutes > 0 -> "Lease: Còn ${remainingMinutes}m (Tarpit 3s)"
            else -> "Lease: Hết hạn (Cần renew)"
        }
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
        android.util.Log.i("TarotApp", message)
        tvConsole.append("\n[${dateFormat.format(Date())}] $message")
        svLog.post { svLog.fullScroll(ScrollView.FOCUS_DOWN) }
    }
}
