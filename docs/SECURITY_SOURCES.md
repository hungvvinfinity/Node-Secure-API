# Nguồn bảo mật và quy trình cập nhật

Đã truy xuất trực tiếp: **2026-10-28 UTC** (2026-10-29 tại Việt Nam). Các đường dẫn dưới đây là nguồn sơ cấp. Cập nhật kiến thức là một bước của mỗi phase/release, không phải lời hứa code sẽ tự theo mọi thay đổi tương lai.

| Nguồn | Phiên bản / nội dung đối chiếu | Ảnh hưởng triển khai |
|---|---|---|
| [android/keyattestation](https://github.com/android/keyattestation) | main commit [34652d3df68b8d6887a6670b00eb0856090dae6d](https://github.com/android/keyattestation/commit/34652d3df68b8d6887a6670b00eb0856090dae6d), committed 2026-10-26; README, verifier, constraints, provider | Xác minh ở server; app identity; challenge; chain; revocation. Thư viện gốc là Kotlin, backend Node dùng implementation riêng được test, không import Kotlin giả. |
| [Android Developers: key attestation](https://developer.android.com/privacy-and-security/security-key-attestation) | Hướng dẫn chain, extension và root rotation | EC root mới bắt đầu ký từ 2026-02-01; không giả định attestation luôn ở leaf. Chọn occurrence đầu tiên từ root; không tin descendant tự nối. |
| [AOSP: attestation schema](https://source.android.com/docs/security/features/keystore/attestation) | KeyMint/Keymaster KeyDescription, AuthorizationList, RootOfTrust, ApplicationId | Parse EXPLICIT ASN.1 tags chính xác; rootOfTrust phải hardware-enforced; package version giữ BigInt. |
| [Google roots](https://android.googleapis.com/attestation/root) | Endpoint JSON chính thức | Trust chỉ từ snapshot server quản lý; hỗ trợ root RSA và EC. Không lấy CA từ client. |
| [Google revocation status](https://android.googleapis.com/attestation/status) | Endpoint JSON entries | Kiểm tra serial mọi certificate; timeout/size/freshness hữu hạn, stale hoặc malformed thì từ chối đăng ký. |
| [Apple: validating apps](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server) ([Markdown](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server.md)) | App Attest attestation/assertion, App ID prefix, environment, receipt và extensions | Nonce SHA256(authData || SHA256(challenge)); keyId hash của X9.62 point; RP hash; AAGUID; Apple counter; CBOR COSE key. App ID prefix có thể khác Team ID, cấu hình theo prefix thực tế. |
| [Apple: validation guide](https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide) ([Markdown](https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide.md)) | Sample attestation năm 2026 | Tham khảo cấu trúc thật và extensions; sample hết hạn không được chấp nhận ở thời gian hiện tại. Cần đối chiếu thuật toán, không dùng mọi intermediate value của sample làm oracle vì một số giá trị trong guide không nhất quán. |
| [Apple: establishing integrity](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity) | generateKey/attestKey/generateAssertion | Không thay App Attest bằng Secure Enclave key client tự khai. |
| [Apple private CA](https://www.apple.com/certificateauthority/private/) | App Attestation root | Tách root App Attestation khỏi Apple root TLS/receipt CA; receipt risk API là integration riêng. |
| [Apple: preparing App Attest](https://developer.apple.com/documentation/devicecheck/preparing-to-use-the-app-attest-service) | Rechecked 2026-10-28 UTC; sandbox/production, entitlement, staged onboarding | TestFlight/distribution dùng production. Preparation nêu `appattestsandbox` nhưng validation nêu `appattestdevelop`; code giữ strict AAGUID theo validation, hardware canary cần ghi GUID quan sát được trước khi review thay đổi tương thích. Không suy diễn hai tài liệu đã thống nhất. |
| [Apple: assessing fraud risk](https://developer.apple.com/documentation/devicecheck/assessing-fraud-risk) | Receipt CMS, App ID/key binding, timestamps và fraud-risk service | Xác minh receipt bằng Apple Root G3 riêng, signer App Attest marker; lưu receipt để risk worker sử dụng. Chưa gọi API fraud-risk có credential server. |
| [Node release schedule](https://nodejs.org/en/about/previous-releases) | Node24 đang LTS; host test v24.21.0, Docker runtime smoke v24.22.1 | engines >=24 <25; kiểm tra patch security trước deploy và pin digest image được kiểm duyệt. |
| [Node24 crypto](https://nodejs.org/docs/latest-v24.x/api/crypto.html) | X509Certificate, ECDSA DER, SHA256 | Không tự viết thuật toán ECDSA; crypto từ OpenSSL/Node. |
| [Redis Lua](https://redis.io/docs/latest/develop/programmability/eval-intro/) | EVAL atomic; Lua5.1 number không giữ mọi int64 | Sequence so sánh độ dài/lexicographic trên decimal canonical; verify trước commit, commit counter+sequence trong một script. |

## Mỗi lần đổi phase hoặc release

`npm run security:sources` (cần Git và network) kiểm tra read-only commit upstream và fingerprint Google roots so với snapshot đã review trong `docs/upstream-snapshot.json`. CI chạy hàng tuần và khi workflow_dispatch. Drift làm job fail để yêu cầu review; script không sửa trust bundle. Kiểm tra này không phát hiện mọi thay đổi tài liệu Apple/AOSP, vẫn cần bước đối chiếu thủ công bên dưới.

1. Truy xuất lại tài liệu chính thức và commit upstream. Ghi retrieval date, commit/version, thay đổi validation/trust/schema trong file này.
2. Refresh root bundle trong quy trình review riêng; so fingerprint với nguồn chính thức; giữ root cũ còn hợp lệ trong rotation window. Không âm thầm trust URL từ payload/certificate.
3. Refresh revocation theo chu kỳ hữu hạn; theo dõi tuổi snapshot, lỗi fetch, readiness. Không kéo dài tuổi khi refresh thất bại.
4. Chạy npm audit, xem release notes của runtime và dependencies; update lockfile có review; chạy bộ test adversarial và canary trên thiết bị thật.
5. Ghi rõ test nào là fixture, Redis thật, test thiết bị thật, load test; không dùng số throughput/memory từ tài liệu gốc làm kết quả benchmark.

Tài liệu gốc có khẳng định “100% botnet”, chi phí và thời gian ký/verify cố định. Implementation không thể chứng minh các khẳng định đó. Signing oracle trên thiết bị thật, relay, key invalidation, mất state Redis và request đến lệch thứ tự vẫn cần policy vận hành/quota phù hợp.
