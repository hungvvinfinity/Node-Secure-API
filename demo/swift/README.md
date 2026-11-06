# Hướng dẫn Tích hợp Client Swift (iOS) với Node-Secure-API

Mã nguồn này được thiết kế theo nguyên tắc **Zero-Dependency** và **Drop-In Ready**:
- Chỉ cần **copy & paste** duy nhất file [`AppAttestClient.swift`](./AppAttestClient.swift) vào Xcode project của bạn.
- Thuần 100% Apple Native SDK (`Foundation`, `CryptoKit`, `DeviceCheck`, `Security`), không cần bất kỳ thư viện bên thứ 3 nào.
- Tự động nhận diện môi trường: chạy trên **Xcode Simulator** thì dùng giả lập, cắm **iPhone thật** thì tự kích hoạt chip **Secure Enclave** phần cứng.
- Tự động lưu trữ thông tin thiết bị (`deviceId`, `keyId`, `sequence`, `clockOffsetMs`) vào **iOS Keychain** bảo mật với cờ `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.

---

## 1. Yêu cầu Cấu hình Dự án Xcode (App Attest Entitlement)

Trên Apple Developer Portal và Xcode:
1. Vào **Signing & Capabilities** trong Target ứng dụng của bạn.
2. Bấm `+ Capability` và chọn **App Attest**.
3. File `.entitlements` của bạn sẽ có trường:
   ```xml
   <key>com.apple.developer.devicecheck.appattest-environment</key>
   <string>development</string> <!-- hoặc "production" khi phát hành App Store -->
   ```
   > [!IMPORTANT]
   > Giá trị `development` hoặc `production` trên iOS phải tương ứng với biến môi trường `IOS_APP_ATTEST_ENV` trên server Node-Secure-API (mặc định: `development`).

---

## 2. Cách tích hợp nhanh (3 bước)

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

        // 2. Chuẩn bị URL và body nghiệp vụ
        let url = URL(string: "https://api.yourdomain.com/api/tarot/read")!
        let bodyData = try JSONSerialization.data(withJSONObject: [
            "question": "Tarot hôm nay của tôi thế nào?"
        ])

        // 3. Tự động:
        //    - Tăng monotonic sequence chống Replay
        //    - Bù lệch đồng hồ hệ thống (clockOffsetMs)
        //    - Băm SHA-256 canonical payload (target + raw body)
        //    - Ký chữ ký phần cứng Secure Enclave (Apple App Attest Assertion)
        let request = try await apiClient.createSignedRequest(
            url: url,
            method: "POST",
            body: bodyData,
            idempotencyKey: UUID().uuidString
        )

        // 4. Gửi qua URLSession tiêu chuẩn
        let (data, response) = try await URLSession.shared.data(for: request)
        if let httpRes = response as? HTTPURLResponse, httpRes.statusCode == 200 {
            print("Gửi request nghiệp vụ thành công!")
        }
    } catch {
        print("Lỗi: \(error.localizedDescription)")
    }
}
```

---

## 3. Cơ chế Tự động Switch (Simulator vs iPhone Thật)

Lớp `AppAttestFactory` trong `AppAttestClient.swift` sử dụng cờ biên dịch của Xcode:

- **Khi chạy trên Simulator (`#if targetEnvironment(simulator)`):**
  - Tự động kích hoạt `MockAppAttestService`.
  - Sinh cặp khóa EC P-256 chuẩn NIST trong bộ nhớ.
  - Tự động sinh `keyId` chuẩn Base64 của SHA-256 uncompressed EC point (65 bytes `0x04 || X || Y`).
  - Đóng gói `authenticatorData` 37 bytes mang cờ `0x40` (cờ AT chuẩn iOS) và chữ ký DER ASN.1, cho phép gọi và debug toàn diện backend Node-Secure-API mà không cần thiết bị thật.

- **Khi chạy trên iPhone Thật:**
  - Tự động kích hoạt `RealAppAttestService` gọi trực tiếp `DCAppAttestService.shared`.
  - Khóa riêng được tạo và lưu trữ an toàn trong chip **Secure Enclave** phần cứng.
  - Assertion được Apple App Attest tạo và chứng thực bằng phần cứng.

---

## 4. Các Header An ninh Được Tự động Sinh ra

| Tên Header | Giá trị sinh bởi `SecureApiClient` | Mô tả an ninh |
| :--- | :--- | :--- |
| `Content-Type` | `application/json; charset=utf-8` | Định dạng body JSON nghiêm ngặt |
| `X-Device-Id` | Chuỗi định danh thiết bị (`dev_...`) | Định danh thiết bị đã qua Hardware Attestation |
| `X-Timestamp` | Epoch milliseconds đã bù lệch (`clockOffsetMs`) | Chống replay quá khứ / hết hạn (ngưỡng ±15s) |
| `X-Sequence` | Chuỗi số nguyên đếm đơn điệu (`1, 2, 3...`) | Lưu trữ bền vững trong Keychain, chống Replay tuyệt đối |
| `X-Assertion` | Chuỗi Base64 đóng gói CBOR Map gồm `signature` (ECDSA DER) và `authenticatorData` | Bằng chứng mật mã không thể giả mạo từ Secure Enclave |
| `Idempotency-Key`| UUID v4 ngẫu nhiên | Đảm bảo tính idempotent khi retry mạng |

---

## 5. Tài liệu tham khảo
- Đặc tả xác minh từng bit/byte của iOS Assertion: [`docs/IOS_REQUEST_VERIFICATION_SPEC.md`](../../docs/IOS_REQUEST_VERIFICATION_SPEC.md)
- Hướng dẫn tích hợp toàn hệ thống: [`docs/CLIENT_INTEGRATION_GUIDE.md`](../../docs/CLIENT_INTEGRATION_GUIDE.md)
