# Kết quả triển khai và review

Hoàn tất trên môi trường local ngày **2026-10-29, Asia/Ho_Chi_Minh** (2026-10-28 UTC). Hai tài liệu đầu vào được giữ nguyên. Kế hoạch ở [IMPLEMENTATION_PLAN.md](../IMPLEMENTATION_PLAN.md); source mới dùng Node.js 24 + TypeScript, Android và iOS cùng `DeviceSecurityProvider`, `SecurityService` và Redis replay guard.

## Phân công và cách review

Ba agent **agy** chạy qua [Herdr skill](/home/hungvu/.agents/skills/herdr/SKILL.md): `secure-core`, `secure-android`, `security-tests`. Agent test riêng viết fixture, happy path, edge case và integration tests; không sửa production để ép test pass. Sau bàn giao, root đọc và tích hợp toàn bộ security boundary, sửa các lỗi phát hiện, rồi giao peer viết thêm test Android adversarial, CBOR và cache revocation cho code của người khác. Root tự chạy lại các kiểm tra bên dưới.

Review bao gồm trust anchors, certificate validity/revocation, ASN.1/CBOR limits, app/key binding, signature/canonical bytes, timestamp, Redis connection lifecycle/Lua races, persistence, cache, production composition, HTTP errors, cấu hình và tài liệu. Kết quả test không phải chứng minh hình thức rằng phần mềm không còn lỗi.

Lượt peer review của `secure-core` đọc lại phần integration do root quản lý (`config`, `runtime`, HTTP, Redis/cache và CMS receipt), không xác nhận thêm lỗi có thể tái hiện. Gate phase ban đầu đạt 205/205 với Redis thật; sau bổ sung Redis probe/gate, lượt Compose đạt 212/212. Lượt peer chạy thiếu Redis URL có skip không được dùng làm bằng chứng nghiệm thu persistence. Ma trận test đã được đối chiếu lại tên case, số lượng, phiên bản runtime và ngưỡng timestamp 15 giây.

## Google key mới và ngoại lệ validity

- Đối chiếu trực tiếp `android/keyattestation` tại commit **34652d3df68b8d6887a6670b00eb0856090dae6d**, ngày commit 2026-10-26. `npm run security:sources` xác nhận Google root snapshot không drift tại lần kiểm tra cuối.
- Hỗ trợ Google RSA root và EC root 2026. So khớp trust theo **SPKI** kèm signature/self-signature và chain constraints, chấp nhận RSA root được reissue với cùng key; không pin cứng toàn bộ DER của phiên bản root cũ.
- Port quy tắc validity từ [upstream validator](https://github.com/android/keyattestation/blob/34652d3df68b8d6887a6670b00eb0856090dae6d/src/main/kotlin/provider/KeyAttestationCertPathValidator.kt), đối chiếu bằng fixture upstream có provenance và Apache license. Kotlin upstream không được import trực tiếp vào Node.
- Android leaf có validity do thiết bị quyết định; root được tin theo key. Intermediate factory đã phân loại đúng từ signed chain được miễn kiểm tra **hết hạn**, vẫn kiểm tra notBefore, signatures, issuer/CA constraints và revocation. Không coi mọi chain bốn cert là factory. RKP hết hạn bị từ chối; iOS dùng profile strict riêng.
- Fixture factory `blueline/sdk28/TEE_EC_NONE` chứng minh ngoại lệ ở **chain validator**. Full provider vẫn từ chối key `DIGEST_NONE`; không hạ policy SIGN/SHA256/P256 để làm fixture pass. Fixture `tegu` xác minh EC root mới và `caiman` xác minh RSA reissue/RKP ở thời gian lịch sử hợp lệ.

## Các lỗi đã sửa trong review

| Vấn đề | Thay đổi và bằng chứng |
|---|---|
| Production composition chưa nối đủ dependency bảo mật | Entrypoint bắt buộc Redis, official roots, Google CRL thật và provider theo config; Docker smoke chạy cả Android/iOS. Không có HTTP switch mock CA. |
| Redis handshake treo hoặc cold-start đồng thời lỗi | Deadline cho connect/command, dùng chung in-flight handshake, không offline queue/reconnect vô hạn; test blackhole TCP và 20 cold pings. Timeout chỉ đóng đúng connection của operation đó. |
| Sequence có thể mất precision trong Lua | So sánh decimal string, giới hạn signed-positive int64; counter iOS uint32 và sequence commit chung một Lua script. Test >2^53 và 20 request cùng sequence chỉ một winner. |
| Cache có thể che state đã xóa/đổi key | Mỗi request vẫn CAS trên Redis; record không tồn tại/key mismatch bị chặn trước business. Cache chỉ giữ identity/KeyObject có giới hạn. |
| CRL malformed, SUSPENDED hoặc snapshot quá hạn | Validate mọi entry, normalize serial hex, chặn cả REVOKED/SUSPENDED; tôn trọng max-age=0/no-cache/no-store, HTTP Age, TTL boundary và clock rollback. Refresh lỗi không gia hạn cache. |
| Factory expiry hoặc root rotation bị xử lý quá rộng/quá chặt | SPKI pins, signed-intermediate classification và Android validity profile như trên; real upstream fixtures kiểm tra riêng factory/RKP/revoked. |
| ASN.1/CBOR không rõ ràng hoặc input tốn tài nguyên | Bounded bytes/depth/nodes; duplicate tags/extension OIDs/semantic map keys, wrong types, negative integers, trailing bytes, invalid UTF-8 và unknown critical extensions bị từ chối. |
| iOS receipt chỉ tin chain Apple chung | Xác minh CMS, App ID, key và thời gian; signer phải non-CA và có marker App Attest `1.2.840.113635.100.12.15`, dùng Apple Root G3 riêng. |
| iOS assertion thiếu ràng buộc hoặc hash sai | Nonce/keyId/COSE/RP/AAGUID kiểm tra ở registration; assertion kiểm tra App ID/môi trường đã lưu, counter và app properties nếu cấu hình. Thiếu metadata identity cũng bị từ chối. Ký/verify composite đúng một SHA256, có test âm double-hash. |
| Raw body bị thay đổi hoặc aborted request được coi rỗng | Canonical dùng raw target/query/body; test sửa một bit, whitespace/method/query, duplicate headers, encoding/body limits. Body overflow đóng connection sau response. |
| Receipt lớn đi qua mỗi request | Receipt vẫn lưu bền vững ở trường Redis riêng; hot HMGET và RAM cache không tải receipt. |

## Kiểm tra đã thực hiện

Môi trường host Node **v24.21.0**, Redis **8.10.3** qua container `redis:8-alpine`, AOF + appendfsync always, namespace test riêng. Test không dùng FLUSHDB. Dependencies được khóa bằng `package-lock.json`.

| Kiểm tra | Kết quả |
|---|---|
| `npm run typecheck` | Pass |
| `npm run build` | Pass |
| `npm run test:docker` | **212 pass, 0 fail, 0 skip**, 16 test files, 45 suites; khoảng 3,24 giây cho suite có coverage trong container, chưa gồm build/audit/orchestration |
| Coverage của **các file src được instrument trong suite** | 90,20% line; 75,93% branch; 93,33% function. Không bao gồm entrypoint/runtime chưa được import bởi test runner. |
| `npm audit --audit-level=moderate` | 0 vulnerabilities tại thời điểm kiểm tra |
| `npm run security:sources` | Commit và hai Google root fingerprints khớp snapshot đã review |
| `npm run test:redis-restart` | Restart thật Redis container riêng; key, sequence >2^53 và counter iOS còn nguyên; replay/rollback bị chặn, số tiếp theo được chấp nhận, đăng ký lại không reset |
| HTTP server restart integration | Android và iOS tiếp tục dùng record Redis cũ, từ chối replay và chấp nhận sequence/counter mới |
| Docker build + runtime | Node **v24.22.1** trong image; build thành công bằng `--network=host` vì bridge DNS local lỗi; chạy user `node`, official trust/CRL + Redis thật, `/health`, `/ready`, challenge Android/iOS đều 200 |
| Compose toàn bộ project | `compose.yaml`: API runtime + Redis, healthchecks, dependency readiness, durable volume, loopback ports; `compose.demo.yaml` có identity ví dụ rõ ràng, official trust không thay đổi |
| `npm run test:stack` | Chạy qua API port thật: health/readiness/challenge 200; protected request thiếu proof 401; synthetic root + header test bị từ chối `UNTRUSTED_ROOT_CA` 403 |
| Redis Compose restart | Restart chính service Redis giữa hai test processes: public key hash giữ ngoài Redis vẫn khớp, sequence >2^53/counter/challenge còn nguyên; replay/rollback bị chặn và số mới thành công |
| Redis thiếu/lỗi trong CI | Required-env gate exit 1 khi thiếu URL; URL cấu hình nhưng unavailable làm integration fail, không skip. Probe blackhole có deadline và test xác nhận client socket đóng trước cleanup |
| Canary preflight | 5 local control cases pass; runtime demo thật health/readiness pass. Report luôn ghi `hardwareAttestationVerified: false` |

[Ma trận test](TEST_MATRIX.md) ánh xạ từng case tới invariant. CI chạy chính `npm run test:docker`: build, typecheck/coverage/audit trong test image, Redis service restart và cleanup project/volume riêng; tiếp theo dựng stack demo API + Redis và chạy `test:stack` qua published port, rồi dừng stack. Source drift chạy hàng tuần hoặc thủ công. `npm test` không cấu hình Redis chỉ dành cho unit-only; không dùng kết quả có skip để nghiệm thu. Smoke Docker/runtime không chứng minh đã attest thiết bị thật. Runbook và mẫu bằng chứng ở [CANARY.md](CANARY.md).

## Hiệu năng và persistence

Đã bổ sung k6 2.3 capacity sweep trên **runtime API Docker thật** với key tổng hợp seed vào Redis benchmark riêng. Mức đã xác nhận 60s: **1 process 4.000 RPS** (240.000 accepted, p95 6,09ms), **4 process 9.000 RPS** (540.001 accepted, p95 5,70ms), cả hai 0 HTTP lỗi và 0 drops. Các mức ép tải khoảng 5.500/12.000 accepted/s có drops, không được gọi là strict pass. Phương pháp, giới hạn generator/warm-up, CPU/RAM và toàn bộ report kể cả fail nằm trong [CAPACITY.md](CAPACITY.md). Benchmark không thay hardware canary hoặc tải AI/TLS production.

Cache nóng còn **một Redis atomic commit mỗi request**, không xác minh lại X.509 hoặc tải CRL trên đường request đã đăng ký. Benchmark local AOF + fsync always: cache nóng khoảng **2.691 accepted request/giây, p95 7,72 ms**, baseline đọc Redis mỗi request 2.076 request/giây, p95 11,18 ms. Điều kiện và script tái chạy ở [PERFORMANCE.md](PERFORMANCE.md); đây không phải capacity production hay số đo thiết bị hardware.

Restart process không reset key, deviceId, sequence hoặc Apple counter. Redis cần persistence/replication đúng yêu cầu triển khai: AOF và Lua không tự bảo đảm không mất ACK qua asynchronous failover hoặc restore backup. Runbook và retry/rekey ở [DEPLOYMENT.md](DEPLOYMENT.md).

## Giới hạn còn lại trước release production

- Chưa chạy Android TEE/StrongBox và iOS App Attest trên thiết bị thật với app signing identity/entitlement của sản phẩm. Cần canary thiết bị thật và proxy/TLS production theo deployment guide.
- Chưa có benchmark tải production, Redis failover/restore drill hay audit bảo mật bên ngoài. Không cam kết chặn 100% bot, signing oracle hoặc throughput từ tài liệu thiết kế.
- AI/OTP Tier 2, quota, S3/MinIO và database idempotency là integration của sản phẩm; Tarot handler hiện là ví dụ. Không coi replay guard là exactly-once business transaction.
- Thu hồi thiết bị đã đăng ký cần xóa/thu hồi record hoặc re-attestation theo lifecycle riêng. CRL ở registration không tự thu hồi mọi device record cũ. Apple fraud-risk refresh API cần server credentials và worker riêng; receipt đã được xác minh/lưu bền vững nhưng chưa gọi risk API.

Repository hiện có Git local. Xem `git log` để đối chiếu commit; chưa push/PR hoặc deploy ra hệ thống bên ngoài. Stack demo local có thể giữ chạy để kiểm tra; identity ví dụ không thay app identity thật của sản phẩm.
