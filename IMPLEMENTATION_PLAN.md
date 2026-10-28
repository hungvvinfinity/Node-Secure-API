# Kế hoạch triển khai Node Secure API

Đối chiếu nguồn trực tiếp ngày 2026-10-28 UTC. Đầu vào: SECURITY_SOLUTION.md và PSEUDO_CODE.md; hai tài liệu gốc được giữ nguyên. Khi bắt đầu, thư mục chưa có source code hoặc Git repository.

## Thiết kế giữ nguyên

- POST /api/auth/challenge: nonce mật mã 32 byte, chuỗi hex, TTL 60 giây, dùng một lần, ràng buộc platform phía server.
- POST /api/auth/register-device: xác thực attestation trên backend, trích public key đã được chứng thực, không nhận public key tự khai của client.
- Request nghiệp vụ: X-Device-Id, X-Timestamp (milliseconds), X-Sequence (decimal signed-positive int64), X-Signature (DER ECDSA base64 cho Android); iOS dùng X-Assertion cho App Attest assertion. Chọn provider từ record đã lưu, không từ header client.
- Canonical UTF-8: timestamp:sequence:METHOD:request-target:SHA256(rawBody), SHA256 lowercase hex. request-target bao gồm query nguyên bản, không URL-decode/reorder. Body giữ nguyên từng byte, không stringify fallback; từ chối content encoding nén để tránh biến đổi byte.
- Timestamp lệch tối đa 15 giây; sequence 1..9223372036854775807, cấm leading zero; BigInt trong Node và so sánh chuỗi decimal trong Redis Lua, tuyệt đối không tonumber(sequence).
- Xác thực chữ ký trước khi cập nhật sequence; commit sequence/counter nguyên tử trước khi chạy nghiệp vụ. Store lỗi thì từ chối, không fallback sang memory ở production.
- deviceId được server suy ra từ platform và SPKI đã xác minh; đăng ký lại không được ghi đè/reset counter. Record không tự hết hạn để tránh mở lại replay; thao tác xóa/khôi phục phải theo quy trình quản trị và rekey.
- Cùng một DeviceSecurityProvider gồm verifyRegistration và verifyRequest; mọi chính sách challenge, canonical, replay, HTTP dùng chung. src/contracts.ts là contract giao việc.

## Cập nhật bắt buộc so với pseudo-code

1. Trust bundle lấy từ endpoint chính thức có cả RSA và EC root mới 2026; cập nhật có kiểm soát ngoài request path. Revocation list phải có độ tươi hữu hạn, lỗi/malformed/stale phải fail closed. Không lấy URL từ certificate/client.
2. Chain validation gồm signatures, issuer, validity, CA/basicConstraints, key usage, path length, unknown critical extensions và trust anchor. Chọn extension attestation đầu tiên từ root xuống; reject extension nằm trên key khác leaf để tránh đăng ký key do attacker nối chain. Provisioning extension có thì kiểm tra vị trí kế tiếp.
3. Parse ASN.1 explicit tag 709 đúng cấu trúc; kiểm tra package + minimum version + tập signer digest; cả hai security levels thuộc TEE/StrongBox; rootOfTrust hardware-enforced bắt buộc locked + Verified. Key dùng ký là EC P-256, purpose SIGN, origin GENERATED, digest SHA256, curve P256 phù hợp KeyMint.
4. AtomicLong không đảm bảo thứ tự đến server: client serialize request được bảo vệ hoặc retry với sequence/timestamp/signature mới. Sequence thấp đến sau bị từ chối theo thiết kế strict monotonic.
5. Không khẳng định chặn mọi bot/signing oracle hoặc đạt throughput/chi phí từ tài liệu nếu chưa đo. Attestation không thay quota, rate limit, auth người dùng. Tier 2 phải có auth riêng và không được nâng thành Tier 1 bởi client.
6. iOS sử dụng Apple App Attest; Secure Enclave key tự khai không thay được App Attest. Chỉ dùng production AAGUID trong production; counter Apple uint32 độc lập sequence ứng dụng int64.

## Phase 1 — Android + core

Agent agy `secure-core`: Node 24 LTS + TypeScript ESM; service, HTTP adapter, Redis store/Lua, config fail closed, health/readiness, limits, shutdown. Memory store chỉ cho unit test/local injection rõ ràng. Không mock CA từ HTTP. Demo business handler phải được ghi rõ là ví dụ, không giả lập dịch vụ AI/OTP/S3.

Agent agy `secure-android`: verifier Android + shared X509 utilities + trust/revocation loader. Đọc source android/keyattestation và tài liệu Google/AOSP hiện tại; port quy tắc sang Node, không giả vờ gọi được thư viện Kotlin trong Node. Có nguồn và Apache attribution nếu chuyển mã.

Agent agy `security-tests` độc lập: đọc yêu cầu/contract trước, tự tạo fixture mật mã và test vector, không sửa source production để làm test pass. Viết case/hypothesis rõ trong docs/TEST_MATRIX.md, báo mọi gap. Test CA chỉ được dependency injection trong test; không tồn tại cờ client nới trust.

Gate: build/typecheck, tests unit/HTTP/Redis thật, coverage report, review fail-closed, roots/revocation malformed + stale; không chuyển phase nếu gate đỏ.

## Phase 2 — iOS qua cùng interface

Sau gate Android, giao `secure-android` triển khai src/platform/ios.ts bằng App Attest: bounded CBOR, fmt apple-appattest, x5c chain tới Apple App Attestation Root, nonce extension 1.2.840.113635.100.8.2 = SHA256(authData || SHA256(challenge UTF-8)), RP ID hash SHA256(TeamID.BundleID), production/development AAGUID tách biệt cấu hình server, initial signCount=0, credentialId/keyId/public-key hash khớp. Assertion kiểm tra RP hash + signature over authData || SHA256(canonical) + counter tăng; counter và sequence commit chung atomic store.

Agent test độc lập bổ sung cùng contract suite cho hai provider và iOS forged nonce/app id/key id/AAGUID/assertion/replay/concurrent counter cases. `secure-core` chỉ tích hợp provider/config, không tạo pipeline replay thứ hai.

## Test & tiêu chí nghiệm thu

Happy: TEE, StrongBox, challenge hợp lệ, chữ ký DER P256, body rỗng/JSON/query, BigInt >2^53, iOS registration/assertion hợp lệ, HTTP end-to-end, Redis thật.

Edge/attack: expired/future timestamps ở biên; expired/reused/concurrent challenge; truncated/oversized ASN.1/CBOR/cert; wrong root/signature/issuer/CA/path length/critical extension/validity/revoked serial; stale revocation; missing/duplicate/spoofed attestation; software security level; app/package/version/signer/boot mismatch; malicious test headers; unknown device; key overwrite; malformed/leading-zero/negative/overflow sequence; tamper whitespace/query/method; invalid signature không đốt sequence; 20+ request đồng thời cùng sequence chỉ một thành công; Redis lỗi không chạy business handler; iOS replay/counter rollback.

Không dùng test stub trả success làm bằng chứng verifier thật hoạt động. Test synthetic chain phải chạy crypto thật. Device smoke test thật phải ghi chưa chạy nếu không có thiết bị/profile/signing credentials.

## Cách chạy & triển khai

README và docs/DEPLOYMENT.md phải có npm ci/build/test; cấu hình package/signer/min version và TeamID.BundleID; download/review roots, revocation refresh + max-age + readiness; Redis durable AOF/noeviction/ACL/TLS/backup và không reset counter khi restart; reverse proxy TLS giữ raw target/body, giới hạn body/rate cho challenge/register; runbook clock/NTP, root rotation, retry/rekey, rollback và canary. Dockerfile nonroot + compose Redis cho kiểm thử local; không publish/deploy ra bên ngoài khi chưa có yêu cầu.

## Nguồn cần revalidate mỗi phase

- https://github.com/android/keyattestation (README, verifier, constraints, provider và roots.json; ghi commit khi sử dụng)
- https://developer.android.com/privacy-and-security/security-key-attestation
- https://source.android.com/docs/security/features/keystore/attestation
- https://android.googleapis.com/attestation/root
- https://android.googleapis.com/attestation/status
- https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server
- https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity
- https://www.apple.com/certificateauthority/
- https://nodejs.org/en/about/previous-releases

Mỗi lần release hoặc đổi phase: cập nhật docs/SECURITY_SOURCES.md với retrieval date/version/commit và tác động; CI kiểm tra dependency audit; không tự nâng trust policy từ dữ liệu client hay tự áp dụng dependency breaking changes.

## Bổ sung khi thực thi và yêu cầu mới

- Gate nền tảng phase1 đã qua: 99 tests, 0 failure, 0 skip, build/typecheck và Redis thật. Hai fixture upstream chứng minh root RSA reissue cùng SPKI và root EC mới 2026 được chấp nhận ở thời gian lịch sử hợp lệ.
- Tái sử dụng đúng validity policy upstream: Android target leaf không dựa validity do thiết bị kiểm soát; intermediate factory đã được phân loại từ signed chain có thể hết hạn nhưng vẫn phải đúng signature/name/trust/revocation. RKP intermediate hết hạn bị từ chối. Không suy luận factory chỉ vì chain có bốn cert. Apple dùng profile strict riêng.
- Factory fixture upstream có thể dùng key DIGEST_NONE; test expiry ở chain validator, không nới chính sách key SIGN/SHA256/P256 của sản phẩm để làm fixture pass.
- Sequence/public key/deviceId/Apple counter được lưu Redis không TTL, không reset khi restart. Bổ sung test đóng/mở store và HTTP server với cùng namespace rồi kiểm tra replay/số tiếp theo.
- Agent `secure-core` triển khai iOS sau gate phase1; agent `secure-android` chuyển sang cache identity/KeyObject có giới hạn; `security-tests` vẫn độc lập viết tất cả test. Root review/tích hợp/benchmark.
- Đường request cache nóng cần một Redis atomic commit; cache không thay replay decision. Kết quả đo local và cách chạy lại nằm trong docs/PERFORMANCE.md.

## Kết quả bàn giao

Đã hoàn thành cả hai phase qua cùng interface, test độc lập và root/peer review. Bộ test cuối: 205 pass, 0 fail, 0 skip với Redis thật; Docker runtime và restart Redis thật đã được xác minh. Chi tiết lỗi sửa, bằng chứng và phần cần canary trước production ở [docs/REVIEW.md](docs/REVIEW.md). Không thay đổi hai tài liệu thiết kế gốc.

Theo yêu cầu tiếp tục: thêm `compose.test.yaml` và `npm run test:docker` để build/test toàn bộ trong container với Redis thật tự khởi động, không phụ thuộc Redis cài sẵn. Gate Redis cấu hình sai phải fail; bổ sung 7 regression thành 212 tests. Compose restart chính service Redis rồi kiểm tra replay state và pending challenge. [Runbook canary](docs/CANARY.md) dành cho giai đoạn chưa có thiết bị thật, không tuyên bố hardware attestation đã chạy.
