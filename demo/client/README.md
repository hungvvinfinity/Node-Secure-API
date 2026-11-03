# Node-Secure-API Android Client Demo (Dual-Tier Edition)

Mô-đun demo Android Client hoàn chỉnh cho hệ thống **Node-Secure-API**, tích hợp kiến trúc phân tầng bất đối xứng **Dual-Tier** theo đặc tả `docs/ANDROID_COMPATIBILITY_PLAN.md`:
- **Tier 1: Hardware VIP**: TEE / StrongBox Key Attestation, VIP fast-track (0ms delay), lease vĩnh viễn.
- **Tier 2: Software Protected**: Tương thích 100% thiết bị cũ/unlock bootloader/không có Google Play Services; bảo vệ bằng bài toán Proof of Work (PoW), Rolling Lease 2h, Tarpit Delay 3.0s, và Concurrency Lock (tối đa 1 request in-flight).

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
│   │   │       └── activity_main.xml             # UI trực quan: Dual-Tier Status, Lease Timer, nút thao tác và console log
│   │   └── kotlin/
│   │       └── com/astrology/tarot/
│   │           ├── MainActivity.kt               # Controller UI demo: xin challenge, đăng ký, gọi Tarot, Silent Renewal
│   │           └── security/
│   │               ├── ProofOfWorkSolver.kt           # Bộ giải & xác minh thuật toán Proof of Work (PoW) tối ưu
│   │               ├── KeystoreManager.kt             # Quản lý khóa Dual-Tier: Hardware Attestation & Software SPKI PEM
│   │               ├── ApiClient.kt                   # Dual-Tier client: tự động chuyển tầng, quản lý lease 2h, silent renewal
│   │               ├── AttestationSigningInterceptor.kt # Đồng bộ hóa wire lock, băm SHA-256, tạo canonical, ký ECDSA, gắn 4 headers
│   │               ├── AtomicSequenceGenerator.kt     # Sequence 64-bit strictly increasing bắt đầu từ 1, persist an toàn
│   │               ├── RequestSerializationQueue.kt   # Mutex tuần tự hóa toàn bộ luồng gửi request và nhận response
│   │               ├── RetryHelper.kt                 # Retry an toàn: giữ nguyên Idempotency-Key nhưng rút seq & timestamp mới
│   │               └── SecurityTierManager.kt         # Quản lý trạng thái Tier (Hardware VIP / Software Protected / Lease timer)
│   └── test/
│       └── kotlin/
│           └── com/astrology/tarot/security/
│               ├── ProofOfWorkSolverTest.kt           # Unit test bộ đếm leading zero bits, giải và kiểm tra PoW
│               ├── CanonicalStringTest.kt             # Unit test format canonical string, uppercase method, raw query preservation
│               ├── AtomicSequenceGeneratorTest.kt     # Unit test sequence tăng dần, reset, multithread concurrency (16 threads)
│               └── RetryHelperTest.kt                 # Unit test bảo toàn idempotencyKey, sinh sequence & timestamp mới khi retry
└── simulator/
    ├── client_simulator.ts               # Test suite giả lập Android Client kết nối server Node-Secure-API (14 test cases)
    └── run_simulation.sh                 # Script chạy nhanh toàn bộ 14 bài test Dual-Tier
```

---

## 2. Các điểm bảo mật cốt lõi đã áp dụng

1. **Dual-Tier Key Management ([`KeystoreManager.kt`](file:///home/hungvu/Pictures/Node-Secure-API/demo/client/src/main/kotlin/com/astrology/tarot/security/KeystoreManager.kt))**:
   - **Tier 1 (Hardware VIP)**: Sinh cặp khóa EC P-256 (`secp256r1`) trong `AndroidKeyStore` gắn attestation challenge UTF-8, thử StrongBox trước rồi fallback TEE. Xuất chuỗi chứng chỉ X.509 DER base64 từ leaf tới Google Hardware Root.
   - **Tier 2 (Software Protected)**: Fallback mượt mà sang khóa EC P-256 phần mềm nếu thiết bị không hỗ trợ attestation. Xuất khóa công khai chuẩn SPKI PEM (`exportSpkiPem`).
   - Cung cấp giao diện ký số đồng nhất: `signData(canonicalString)` ký `SHA256withECDSA` sinh chuẩn DER ASN.1 Sequence `(r, s)` base64 cho cả 2 loại khóa.

2. **Proof of Work Solver ([`ProofOfWorkSolver.kt`](file:///home/hungvu/Pictures/Node-Secure-API/demo/client/src/main/kotlin/com/astrology/tarot/security/ProofOfWorkSolver.kt))**:
   - Giải bài toán PoW trong background: tìm `nonce` sao cho `SHA256(challenge + ":" + salt + ":" + nonce)` có đủ số leading zero bits.
   - Tối ưu hóa hiệu năng bằng các bước băm byte-level, giải nhanh bài toán độ khó 14–18 bit trong ~10–300ms mà không làm đơ giao diện người dùng.

3. **Chuyển Tầng Tự Động & Silent Renewal ([`ApiClient.kt`](file:///home/hungvu/Pictures/Node-Secure-API/demo/client/src/main/kotlin/com/astrology/tarot/security/ApiClient.kt))**:
   - Khi đăng ký: Tự động thử Tier 1 trước. Nếu phần cứng ném lỗi hoặc server từ chối cert, tự động kích hoạt PoW solver và đăng ký Tier 2.
   - Quản lý Rolling Lease 2h: Lưu `leaseExpiresAt`. Khi mở app hoặc khi lease sắp hết hạn (< 5 phút) hoặc khi nhận lỗi 401 (`DEVICE_LEASE_EXPIRED` / `DEVICE_NOT_REGISTERED`), tự động làm mới ngầm (Silent Renewal) không làm gián đoạn người dùng.
   - Cấu hình OkHttp timeout (`readTimeout = 30s`) để chịu được độ trễ 3.0s Tarpit Delay trên Software Tier.

4. **Serialization Queue & Concurrency Lock**:
   - Khóa đồng bộ `wireLock` bên trong `AttestationSigningInterceptor` đảm bảo tối đa 1 request in-flight được xử lý trên đường truyền mạng, tương thích hoàn toàn với Concurrency Lock của Software Tier trên server (chống lỗi 429 `CONCURRENT_REQUEST_DISALLOWED`).

5. **Chống Replay & Toàn Vẹn Dữ Liệu**:
   - Chuỗi canonical: `timestamp:sequence:METHOD:request-target:bodySha256Hex`.
   - Bộ đếm sequence strictly increasing 64-bit persist vào `SharedPreferences` trước khi gửi.
   - Retry an toàn: bảo toàn `idempotencyKey`, sinh mới sequence và timestamp.

---

## 3. Hướng dẫn Biên dịch & Chạy Test

### Biên dịch Android Client & Chạy Unit Tests:
```bash
cd /home/hungvu/Pictures/Node-Secure-API/demo/client

# Chạy toàn bộ 14 Unit Tests Kotlin (PASS 100%)
./gradlew testDebugUnitTest

# Đóng gói APK Debug
./gradlew assembleDebug
```

### Chạy Verification Test Suite (14 Tests Dual-Tier):
```bash
/home/hungvu/Pictures/Node-Secure-API/demo/client/simulator/run_simulation.sh
```
Suite sẽ kiểm tra toàn diện 14 kịch bản cho cả 2 Tier:
- **Part I (Hardware VIP)**: Challenge & PoW metadata, Hardware Registration, Fast-track Tarot read, Replay attack, Tamper attack, Expired timestamp, Out-of-order sequence, Safe Retry.
- **Part II (Software Protected)**: EC P-256 SPKI PEM & PoW solving, Software registration (tier: software, 2h lease), Tarpit Delay 600ms+, Replay & Tamper attacks, Concurrency Lock (429), 2-hour Lease Expiration (401) & Silent Renewal recovery.
