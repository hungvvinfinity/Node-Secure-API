# Hướng dẫn Tích hợp Client Swift (iOS) với Node-Secure-API

Mã nguồn này được thiết kế theo nguyên tắc **Zero-Dependency** và **Drop-In Ready**:
- Chỉ cần **copy & paste** duy nhất file [`AppAttestClient.swift`](./AppAttestClient.swift) vào Xcode project của bạn.
- Thuần 100% Apple Native SDK (`Foundation`, `CryptoKit`, `DeviceCheck`, `Security`), không cần bất kỳ thư viện bên thứ 3 nào.
- Tự động nhận diện môi trường: chạy trên **Xcode Simulator** thì dùng mock test, chạy trên **iPhone thật** thì tự kích hoạt chip **Secure Enclave** phần cứng.
- Tự động lưu trữ thông tin thiết bị (`deviceId`, `keyId`, `sequence`, `clockOffsetMs`) vào **iOS Keychain** bảo mật với cờ `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
- Tích hợp sẵn **Actor-isolated FIFO Wire Serialization Gate** triệt tiêu hoàn toàn rủi ro Reentrancy và đảo thứ tự sequence / assertion counter trên wire.
- Tích hợp sẵn **SecureApiRetryHelper** tự động phục hồi ngầm (Silent Recovery) khi gặp lệch đồng hồ (`EXPIRED_TIMESTAMP`), Redis boot quarantine (`RETRY_WITH_FRESH_TIMESTAMP`), hoặc mất đăng ký (`DEVICE_NOT_REGISTERED`).

---

## 1. Yêu cầu Hệ thống Cần Cài đặt (System Requirements)

- **Node.js 24+**: Cần thiết để chạy backend Node-Secure-API và bộ kiểm thử interoperability.
- **Swift 6.x trên Linux**:
  - Dùng để kiểm thử cú pháp, typecheck và chạy CI/CD cross-platform cho client Swift trên Linux.
  - Cài đặt thông qua toolchain manager `swiftly`:
    ```bash
    curl -O https://swift-server.github.io/swiftly/swiftly-install.sh && bash swiftly-install.sh && swiftly install latest
    ```
  - Nạp biến môi trường Swiftly:
    ```bash
    source ~/.local/share/swiftly/env.sh
    ```
  - *Môi trường trên hệ thống hiện tại đã cấu hình Swift 6.4.2.*
- **macOS với Xcode 15+**: Bắt buộc khi build và chạy ứng dụng iOS thật hoặc iOS Simulator với Apple SDK (`DeviceCheck`, `CryptoKit`).

---

## 2. Hướng dẫn Chạy Test Suite cho iOS Client & Backend

### Kiểm thử Backend & Interoperability từ thư mục gốc dự án:
```bash
# 1. Chạy toàn bộ test suite của dự án (tự động phát hiện Swift trên máy):
npm test

# 2. Chạy riêng các test case cho iOS (interoperability, assertion, receipt, replay):
npm run test:ios
```

### Kiểm thử Cú pháp & Typecheck iOS Swift Client trên Linux:
```bash
# Nạp môi trường Swift
source ~/.local/share/swiftly/env.sh

# Typecheck file client trực tiếp bằng swiftc (không cần Xcode/macOS)
swiftc -typecheck demo/swift/AppAttestClient.swift
```

---

## 3. Yêu cầu Cấu hình Dự án Xcode (App Attest Entitlement)

Trên Apple Developer Portal và Xcode:
1. Vào **Signing & Capabilities** trong Target ứng dụng của bạn.
2. Bấm `+ Capability` và chọn **App Attest**.
3. File `.entitlements` của bạn sẽ có trường:
   ```xml
   <key>com.apple.developer.devicecheck.appattest-environment</key>
   <string>development</string> <!-- hoặc "production" khi phát hành App Store -->
   ```
   > [!IMPORTANT]
   > Giá trị `development` hoặc `production` trên iOS phải tương ứng với biến môi trường `IOS_APP_ATTEST_ENV` trên server Node-Secure-API (mặc định trên server là `production`).

---

## 4. Cách tích hợp nhanh (3 bước)

### Bước 1: Kéo file vào Xcode
Kéo file [`AppAttestClient.swift`](./AppAttestClient.swift) thả vào cây thư mục của project Xcode (chọn *Copy items if needed*).

### Bước 2: Khởi tạo Client
Trong `AppDelegate.swift`, `App.swift` hoặc Dependency Injection Container:

```swift
import Foundation

// App ID = <AppIDPrefix/TeamID>.<bundleId> (ví dụ: "TEAMID123.com.astrology.tarot")
let baseURL = URL(string: "https://api.yourdomain.com")!
let apiClient = SecureApiClient(
    appId: "TEAMID123.com.astrology.tarot",
    storage: KeychainSecureStorage() // Tự động lưu trữ credentials & sequence an toàn vào Keychain
)
let retryHelper = SecureApiRetryHelper(client: apiClient, baseURL: baseURL)
```

### Bước 3: Đăng ký & Gửi Request Nghiệp vụ được Bảo vệ

```swift
Task {
    do {
        // 1. Khôi phục từ Keychain nếu đã đăng ký trước đó
        let isRestored = try await apiClient.restoreFromStorage()

        if !isRestored {
            // Thiết bị mới: Thực hiện đăng ký phần cứng với server (Challenge -> Attest -> Register)
            let deviceId = try await apiClient.register(baseURL: baseURL)
            print("Đăng ký thiết bị thành công! Device ID: \(deviceId)")
        }

        // 2. Gửi request nghiệp vụ có bảo vệ tuần tự hóa và retry tự động
        let url = URL(string: "https://api.yourdomain.com/api/tarot/read")!
        let questionPayload = [
            "question": "Tarot hôm nay của tôi thế nào?"
        ]

        // 3. Tự động:
        //    - Tạo idempotencyKey duy nhất và gắn đồng thời vào body JSON lẫn header Idempotency-Key
        //    - Khóa tuần tự đường truyền (Wire-level FIFO Gate) chống race condition và đảo thứ tự
        //    - Tăng monotonic sequence và commit đĩa đồng bộ trước khi gửi ra wire
        //    - Bù lệch đồng hồ hệ thống (clockOffsetMs)
        //    - Băm SHA-256 canonical payload (target + raw body)
        //    - Ký chữ ký phần cứng Secure Enclave (Apple App Attest Assertion)
        //    - Tự động re-sync đồng hồ khi gặp 401 EXPIRED_TIMESTAMP và retry gói mới
        let (data, response) = try await retryHelper.executeWithRetry(
            url: url,
            method: "POST",
            jsonPayload: questionPayload
        )

        if response.statusCode == 200 {
            let resStr = String(data: data, encoding: .utf8) ?? ""
            print("Gửi request nghiệp vụ thành công: \(resStr)")
        }
    } catch {
        print("Lỗi: \(error.localizedDescription)")
    }
}
```

---

## 5. Cơ chế Môi trường (Simulator vs iPhone Thật)

Lớp `AppAttestFactory` trong `AppAttestClient.swift` tuân thủ nguyên tắc fail-closed và phân định rõ ràng:

- **Khi chạy trên Simulator (`#if targetEnvironment(simulator)`):**
  - Tự động kích hoạt `MockAppAttestService`.
  - Sinh cặp khóa EC P-256 chuẩn NIST trong bộ nhớ.
  - Tự động sinh `keyId` chuẩn Base64 của SHA-256 uncompressed EC point (65 bytes `0x04 || X || Y`).
  - Tạo `authenticatorData` 37 bytes mang cờ `0x40` (cờ AT chuẩn iOS) và chữ ký DER ASN.1 cho các assertion của request.
  - *Lưu ý về đăng ký backend*: Do server Node-Secure-API thực thi thẩm tra chuỗi chứng chỉ Apple PKI nghiêm ngặt (`x5c` neo vào Apple Root CA), `MockAppAttestService` phục vụ kiểm thử đơn vị nội bộ client hoặc các môi trường test harness có hỗ trợ mock bypass.

- **Khi chạy trên iPhone Thật:**
  - Tự động kích hoạt `RealAppAttestService` gọi trực tiếp `DCAppAttestService.shared`.
  - Khóa riêng được tạo và lưu trữ an toàn trong chip **Secure Enclave** phần cứng.
  - Assertion được Apple App Attest tạo và chứng thực bằng phần cứng.
  - Nếu thiết bị không hỗ trợ App Attest (`isSupported == false`), client trả lỗi rõ ràng, tuyệt đối **không tự ý hạ policy hay thay bằng mock phần mềm** trên thiết bị thật (tuân thủ `CLIENT_PROTOCOL.md`).

---

## 6. Các Header An ninh Được Tự động Sinh ra

| Tên Header | Định dạng sinh bởi `SecureApiClient` | Mô tả an ninh |
| :--- | :--- | :--- |
| `Content-Type` | `application/json; charset=utf-8` | Định dạng body JSON nghiêm ngặt |
| `X-Device-Id` | Chuỗi 64 ký tự hex SHA-256 | Định danh thiết bị xác thực phần cứng (`SHA256("ios:" + spkiDerBase64)`) |
| `X-Timestamp` | Epoch milliseconds đã bù lệch (`clockOffsetMs`) | Chống replay quá khứ / hết hạn (ngưỡng ±15s). Tự động re-sync khi lệch |
| `X-Sequence` | Chuỗi số nguyên đếm đơn điệu (`1, 2, 3...`) | Lưu trữ bền vững trong Keychain, chống Replay tuyệt đối |
| `X-Assertion` | Chuỗi Base64 đóng gói CBOR Map gồm `signature` (ECDSA DER) và `authenticatorData` | Bằng chứng mật mã không thể giả mạo từ Secure Enclave |
| `Idempotency-Key`| UUID v4 ngẫu nhiên | Đảm bảo tính idempotent, được nhúng đồng bộ cả trong header và body đã ký |

---

## 7. Tài liệu tham khảo
- Đặc tả xác minh từng bit/byte của iOS Assertion: [`docs/IOS_REQUEST_VERIFICATION_SPEC.md`](../../docs/IOS_REQUEST_VERIFICATION_SPEC.md)
- Hướng dẫn tích hợp toàn hệ thống: [`docs/CLIENT_INTEGRATION_GUIDE.md`](../../docs/CLIENT_INTEGRATION_GUIDE.md)
- Đặc tả giao thức Wire Format: [`docs/CLIENT_PROTOCOL.md`](../../docs/CLIENT_PROTOCOL.md)
