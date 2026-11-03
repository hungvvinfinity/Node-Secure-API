# Node-Secure-API Android Client Demo

Mô-đun demo Android Client hoàn chỉnh cho hệ thống **Node-Secure-API**, tích hợp bảo mật phần cứng Android KeyStore (StrongBox & TEE Hardware Attestation), chống Replay Attack bằng sequence counter 64-bit strictly increasing, serialization queue trên OkHttp Interceptor, và kiểm soát tính toàn vẹn gói tin bằng chữ ký số `SHA256withECDSA`.

---

## 1. Cấu trúc thư mục

```text
demo/client/
├── build.gradle.kts                      # Cấu hình Gradle Android (compileSdk 36, minSdk 26, targetSdk 36)
├── settings.gradle.kts                   # Project name: NodeSecureApiClient
├── local.properties                      # sdk.dir trỏ tới Android SDK
├── proguard-rules.pro                    # Quy tắc bảo vệ code ProGuard/R8
├── gradlew, gradlew.bat, gradle/         # Gradle Wrapper (Gradle 9.4.1)
├── README.md                             # Tài liệu kỹ thuật chi tiết của demo client
├── src/
│   ├── main/
│   │   ├── AndroidManifest.xml           # Khai báo app, allowBackup=false, dataExtractionRules
│   │   ├── res/
│   │   │   ├── xml/
│   │   │   │   ├── data_extraction_rules.xml     # Loại trừ SharedPreferences nhạy cảm khỏi Cloud & Transfer (Android 12+)
│   │   │   │   ├── legacy_backup_rules.xml       # Full backup rules cho Android 11 trở xuống
│   │   │   │   └── network_security_config.xml   # Cho phép cleartext HTTP cho môi trường dev/LAN
│   │   │   ├── values/
│   │   │   │   ├── strings.xml                   # Resource chuỗi
│   │   │   │   └── themes.xml                    # Theme Material 3
│   │   │   └── layout/
│   │   │       └── activity_main.xml             # UI trực quan: 5 nút thao tác và console log
│   │   └── kotlin/
│   │       └── com/astrology/tarot/
│   │           ├── MainActivity.kt               # Controller UI demo: xin challenge, đăng ký, gọi Tarot, test replay/tamper/expired
│   │           └── security/
│   │               ├── KeystoreManager.kt             # Sinh EC P-256 (PURPOSE_SIGN) trong AndroidKeyStore, StrongBox fallback TEE, export cert chain
│   │               ├── ApiClient.kt                   # Gọi /api/auth/challenge, /api/auth/register-device, quản lý deviceId
│   │               ├── AttestationSigningInterceptor.kt # Đồng bộ hóa wire lock, băm SHA-256, tạo canonical, ký ECDSA, gắn 4 headers
│   │               ├── AtomicSequenceGenerator.kt     # Sequence 64-bit strictly increasing bắt đầu từ 1, persist an toàn
│   │               ├── RequestSerializationQueue.kt   # Mutex tuần tự hóa toàn bộ luồng gửi request và nhận response
│   │               ├── RetryHelper.kt                 # Retry an toàn: giữ nguyên Idempotency-Key nhưng rút seq & timestamp mới
│   │               └── SecurityTierManager.kt         # Quản lý phân tầng bảo mật
│   └── test/
│       └── kotlin/
│           └── com/astrology/tarot/security/
│               ├── CanonicalStringTest.kt             # Unit test format canonical string, uppercase method, raw query preservation
│               ├── AtomicSequenceGeneratorTest.kt     # Unit test sequence tăng dần, reset, multithread concurrency (16 threads)
│               └── RetryHelperTest.kt                 # Unit test bảo toàn idempotencyKey, sinh sequence & timestamp mới khi retry
└── simulator/
    ├── client_simulator.ts               # Test suite giả lập Android Client kết nối server Node-Secure-API
    └── run_simulation.sh                 # Script chạy nhanh toàn bộ 8 bài test tích hợp
```

---

## 2. Các điểm bảo mật cốt lõi đã áp dụng

1. **Hardware Key Attestation (NIST P-256 / secp256r1)**:
   - Khóa ký sinh hoàn toàn bên trong phần cứng bảo mật `AndroidKeyStore`.
   - Mục đích sử dụng khóa: Thiết lập nghiêm ngặt **`KeyProperties.PURPOSE_SIGN`** cho private key bất đối xứng.
   - Ưu tiên chip bảo mật chuyên dụng **StrongBox** (`setIsStrongBoxBacked(true)`), tự động fallback an toàn sang **TEE** (`setIsStrongBoxBacked(false)`).
   - Hàm `getOrDetectHardwareSecurityLevel()` ưu tiên truy vấn trực tiếp `KeyInfo` của khóa thật `KEY_ALIAS` để xác định cấp độ bảo mật phần cứng thực tế.
   - Tham số `setAttestationChallenge` nhận **chuỗi UTF-8 của hex challenge 64 ký tự** do server cấp, chống tấn công replay challenge.
   - Vô hiệu hóa `setUserAuthenticationRequired(false)` để tránh việc phiên làm việc bị xóa khi người dùng thay đổi mã PIN/khóa màn hình.
   - Trích xuất toàn bộ chuỗi chứng chỉ X.509 (`getCertificateChain`) dạng DER base64 từ leaf tới Google Hardware Root.

2. **Chuẩn hóa Canonical String & Chữ ký số**:
   - Định dạng chuẩn: `timestamp:sequence:METHOD:request-target:bodySha256Hex`.
   - `timestamp`: epoch milliseconds decimal string.
   - `sequence`: số nguyên 64-bit thập phân canonical (từ 1 đến 9223372036854775807), không có số 0 ở đầu.
   - `METHOD`: HTTP method in hoa (`POST`, `GET`).
   - `request-target`: giữ nguyên bản encoded path và encoded query trên đường truyền (không sort, không decode).
   - `bodySha256Hex`: lowercase hex 64 ký tự của băm SHA-256 trên byte body thô (body rỗng dùng SHA-256 của mảng byte rỗng).
   - Ký bằng thuật toán `SHA256withECDSA`, trả về định dạng DER ASN.1 Sequence `(r, s)` base64.
   - Đính kèm 4 headers an ninh: `X-Device-Id`, `X-Timestamp`, `X-Sequence`, `X-Signature`.

3. **Củng cố Kiến trúc Serialization Queue & Concurrency Lock**:
   - Khóa đồng bộ `wireLock` được tích hợp **trực tiếp bên trong `AttestationSigningInterceptor.kt`**, bao phủ toàn bộ chu kỳ: rút `nextSequence()` -> tính canonical string -> ký số -> `chain.proceed(signedRequest)` -> nhận response từ server.
   - Nhờ đó, mọi request đi qua `httpClient` đều được bảo đảm tuần tự hóa tuyệt đối trên đường truyền, không thể bị race condition hoặc out-of-order làm server từ chối bởi `REPLAY_DETECTED`.

4. **Retry An Toàn & Idempotency Key**:
   - Khi mạng bị rớt hoặc retry: giữ nguyên `idempotencyKey` trong body JSON.
   - BẮT BUỘC rút sequence mới và timestamp mới, ký lại chữ ký mới cho mỗi lần gửi qua client. Gói tin cũ đã gửi không bao giờ được phát lại.

5. **Chống Trích Xuất Dữ Liệu & Cloud Backup**:
   - Sử dụng `data_extraction_rules.xml` (Android 12+) và `legacy_backup_rules.xml` (Android 11 trở xuống) loại trừ hoàn toàn `app_secure_prefs.xml` và `security_demo_prefs.xml` khỏi Google Drive Cloud Backup và chuyển dữ liệu thiết bị (Device-to-Device transfer).
   - Trong `AndroidManifest.xml`, đặt `android:allowBackup="false"`.

---

## 3. Hướng dẫn Biên dịch & Chạy Test

### Biên dịch Android Client & Chạy Unit Tests:
```bash
cd /home/hungvu/Pictures/Node-Secure-API/demo/client

# Chạy toàn bộ Unit Tests (10 tests PASS)
./gradlew testDebugUnitTest

# Đóng gói APK Debug
./gradlew assembleDebug
```

### Chạy Verification Test Suite (Simulator):
```bash
cd /home/hungvu/Pictures/Node-Secure-API/demo/client/simulator
./run_simulation.sh
```
Suite sẽ kiểm tra 8 kịch bản an ninh thực tế và cho kết quả 100% PASS.
