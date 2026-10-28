# Giao thức client Android và iOS

Backend không có shared secret nhúng trong APK/IPA. Hai platform dùng cùng registration service và replay guard, nhưng bằng chứng hardware khác nhau. Tham khảo README cho request/response cụ thể của HTTP adapter.

## Byte và số

- Challenge là 64 ký tự hex đại diện 32 random byte. Để giữ thiết kế gốc, byte đưa vào Android `setAttestationChallenge` là **UTF-8 của chuỗi hex**, không phải hex-decode. iOS `clientDataHash` cho registration là SHA256 của cùng byte UTF-8.
- Timestamp là epoch milliseconds, chuỗi decimal canonical, không dấu, không số thập phân/exponent; sai số tối đa 15 giây.
- Sequence là decimal canonical từ 1 đến 9223372036854775807, gửi trong header như string. Không qua JavaScript Number hoặc JSON numeric khi có thể vượt 2^53. Leading zero không được chấp nhận.
- Body hash là SHA256(rawBody), lowercase hex. Body rỗng dùng SHA256 của mảng byte rỗng. Chữ ký bảo vệ whitespace và encoding nguyên bản.
- Canonical UTF-8 không newline cuối: `timestamp:sequence:METHOD:request-target:bodyHash`.
- `request-target` là encoded path và query nguyên bản, ví dụ `/api/tarot/read?a=%2F&b=1`. Không sort, decode hoặc re-encode query. Chỉ target mà router/proxy giữ nguyên mới có thể verify đúng.

## Android

1. Xin challenge cho platform `android`.
2. Tạo EC `secp256r1` trong AndroidKeyStore, purposes SIGN, digest SHA256, challenge UTF-8. Ưu tiên StrongBox nếu hỗ trợ; fallback TEE vẫn phải vượt policy của backend. Tắt userAuthenticationRequired cho key bảo vệ API theo thiết kế gốc.
3. Gửi `getCertificateChain(alias)` từ leaf tới root, mỗi certificate DER base64. Không gửi public key riêng để yêu cầu server tin.
4. Lưu deviceId server trả về cùng key alias và sequence vào vùng không backup. Nếu đăng ký bị lặp, không yêu cầu backend reset sequence; dùng key mới khi cần re-attest theo lifecycle.
5. Với mỗi request, serialize body **một lần**, tạo canonical từ byte sẽ gửi, ký `SHA256withECDSA` (DER sequence r,s), base64 chuẩn. Gửi X-Device-Id, X-Timestamp, X-Sequence, X-Signature.

Ví dụ tạo request target với OkHttp:

```kotlin
val target = request.url.encodedPath +
    (request.url.encodedQuery?.let { "?$it" } ?: "")
val bodyHash = MessageDigest.getInstance("SHA-256")
    .digest(rawBytes).joinToString("") { "%02x".format(it) }
val canonical = "$timestamp:$sequence:${request.method}:$target:$bodyHash"
val signer = Signature.getInstance("SHA256withECDSA")
signer.initSign(privateKeyFromAndroidKeyStore)
signer.update(canonical.toByteArray(Charsets.UTF_8))
val signature = Base64.encodeToString(signer.sign(), Base64.NO_WRAP)
```

Đây là đoạn tích hợp, không phải Android app hoàn chỉnh. Đừng dùng interceptor đọc lại one-shot/duplex body; request đã ký phải giữ đúng byte. Serialize các request được bảo vệ bằng hàng đợi/mutex bao phủ cả send và response để giữ thứ tự; AtomicLong đơn lẻ không bảo đảm thứ tự đến server.

Loại cả key metadata và counter khỏi cloud backup **và** device-to-device transfer. Android 12+ dùng `data-extraction-rules`; phiên bản cũ dùng full-backup-content. Không backup private key hardware bằng bất kỳ cách nào. Khi metadata bị restore nhưng key không tồn tại, tạo key và đăng ký mới; không crash hoặc ký bằng software key thay thế.

## iOS

1. Kiểm tra `DCAppAttestService.shared.isSupported`; trường hợp không hỗ trợ đi qua luồng tài khoản/quota riêng đã được server xác minh, không hạ policy attestation.
2. Xin challenge platform `ios`. Gọi `generateKey`, lưu keyId; gọi `attestKey(keyId, clientDataHash: SHA256(challenge UTF8))`.
3. Gửi keyId base64 nguyên bản và attestationObject base64. Server kiểm tra Apple App Attestation chain, nonce, RP hash AppID, AAGUID và credential key binding.
4. Mỗi request dùng cùng canonical như Android. Gọi `generateAssertion(keyId, clientDataHash: SHA256(canonical UTF8))`; gửi base64 assertion qua X-Assertion cùng X-Device-Id, X-Timestamp, X-Sequence. Không ký raw request bằng một Secure Enclave key tự tạo khác.
5. App Attest quản lý Apple counter uint32. Client vẫn quản lý sequence ứng dụng int64. Hai counter độc lập; backend commit cả hai atomically. Phải serialize/retry để tránh assertion counter bị đảo thứ tự.

Giao thức dùng canonical có timestamp/sequence và replay state server làm freshness cho assertion của request. Đây là lựa chọn của thiết kế stateful hiện tại; nếu thêm server-issued nonce riêng cho từng assertion theo mô hình challenge-response của Apple thì phải version protocol và thêm round trip tương ứng, không lén đổi canonical trên một platform.

App Attest development và production khác AAGUID; chỉ server chọn environment. Đừng gửi header yêu cầu server chấp nhận development attestation. Phải xác minh App ID **prefix** thật; không mặc định mọi app đều dùng Team ID làm prefix.

## Retry và idempotency

Không phát lại nguyên gói đã ký. Mỗi retry lấy sequence/timestamp mới, tạo signature/assertion mới; giữ idempotency key trong body đã ký. Nếu server đã commit sequence nhưng response bị mất, retry sequence cũ phải bị từ chối. Nghiệp vụ cần trả lại kết quả cũ theo idempotency key bằng unique constraint/transaction của business database.

Nếu seq thấp hơn đã lưu do network reorder, retry với seq cao hơn. Nếu mất counter bền vững, cần rekey/re-attest; không có endpoint client tự đặt lại replay state.

Request không được coi thành công ở nghiệp vụ chỉ vì đã vượt authentication. UI cần xử lý timeout, replay, đăng ký bị thu hồi và yêu cầu đăng nhập riêng theo mã lỗi server.
