# Triển khai và vận hành

## Chuẩn bị

- Gate tự động dùng `npm run test:docker`: tự build image và Redis bằng `compose.test.yaml`, chạy integration với crypto/HTTP/Redis thật và restart Redis service để kiểm tra persistence. Host không cần Redis hoặc `node_modules`; mỗi lượt tạo project/volume riêng và cleanup. Xem [CANARY.md](CANARY.md) cho fallback build network và bước hardware canary.
- Node.js 24 LTS, npm và Redis. Xem `.env.example` để cấu hình tên biến thực tế của server.
- Lấy package name, SHA256 của **app signing certificate** trong Play Console (không nhầm upload key) và minimum version chấp nhận. Các giá trị trong tài liệu gốc là ví dụ, không phải cấu hình production.
- Với iOS, lấy App ID prefix thực tế và bundle ID; prefix thường là Team ID nhưng có ngoại lệ. Bật entitlement App Attest; tách development/production.
- Dùng Redis namespace riêng cho môi trường. Không dùng chung state production và test.

```bash
npm ci
npm run typecheck
npm run build
docker compose up -d redis
REDIS_TEST_URL=redis://127.0.0.1:6379 npm test
REDIS_TEST_URL=redis://127.0.0.1:6379 npm run test:ci
```

`compose.yaml` chỉ cấp Redis local bind loopback, durable volume, AOF và noeviction. Không chạy `docker compose down -v` với dữ liệu cần giữ. Runtime production dùng Redis được quản lý nội bộ, ACL, TLS và backup; không công khai cổng Redis ra Internet.

## Chạy gateway

Copy `.env.example` sang `.env`, điền app identity thật và Redis URL, rồi chạy:

```bash
npm run build
node --env-file=.env dist/server.js
```

Giữ các root/anchor và revocation policy dưới quyền server. Không triển khai `ALLOW_DEV_ROOT_CA`, `X-Test-Mode` hay switch từ payload client để chấp nhận CA test. Constructor injection chỉ dành cho test với process/config riêng; entrypoint production không nhận root client.

Health endpoint phải kiểm tra Redis và độ tươi revocation trước khi coi instance sẵn sàng nhận đăng ký. Theo dõi lỗi refresh sớm hơn max age; fail closed khi snapshot quá hạn. Request đã đăng ký được xác minh bằng public key/counter lưu tại server; revocation của **device đang đăng ký từ trước** cần chính sách re-attestation/thu hồi record riêng, không tự được bảo đảm chỉ bằng CRL lúc registration.

## Container

```bash
docker build -t node-secure-api:local .
docker run --rm --env-file .env -p 127.0.0.1:3000:3000 node-secure-api:local
```

Nếu Docker bridge không phân giải được DNS khi `npm ci` (ví dụ `EAI_AGAIN`), sửa DNS/network của Docker. Trên Linux có thể xác minh build bằng `docker build --network=host -t node-secure-api:local .`; đây là lựa chọn cho môi trường build, không phải yêu cầu gateway production chạy bằng host network.

Redis URL bên trong container phải trỏ tới mạng Redis có thể truy cập từ container; `127.0.0.1` trong container không phải host. Image chạy bằng user `node`. Với release production, pin digest của Node/Redis image sau khi scan/review; Dockerfile/compose dùng major tag để thuận tiện local, không coi major tag là artifact bất biến.

`npm run test:redis-restart` dùng Docker tạo Redis riêng, bật AOF + appendfsync always, ghi sequence vượt 2^53 và counter iOS, restart thật container rồi xác minh state/replay/số tiếp theo. Script tự xóa đúng container nó tạo; không restart Redis đang được các test khác dùng.

## TLS và reverse proxy

1. TLS kết thúc ở load balancer/gateway đáng tin cậy; kết nối nội bộ phải được bảo vệ theo network policy.
2. Giữ nguyên request target (path + query byte nguyên bản), body byte và method đã ký. Không rewrite path, normalize query, JSON reformat hoặc tự giải nén trước validator. Với routing prefix, chốt canonical target giữa client và proxy rồi test bằng capture thật.
3. Cấm compressed request body ở endpoint được bảo vệ nếu pipeline không giữ đúng byte đã ký. Giới hạn body nhỏ cho JSON; dùng presigned upload riêng cho ảnh lớn. Không trả presigned URL giả; tích hợp SDK S3/MinIO và giới hạn object key/type/size khi có storage thật.
4. Rate limit riêng cho `/api/auth/challenge` và `/api/auth/register-device` tại edge theo IP/network và quota hệ thống; giới hạn connection, header và request timeout. Challenge không yêu cầu chứng thực nên có thể bị lạm dụng làm cạn bộ nhớ.
5. Đồng bộ NTP trên gateway. Alert khi clock drift đến gần 15 giây. Không bật `trust proxy`/tin IP forwarded ngoài tập proxy tin cậy.

## Replay state và Redis

- Sequence lưu dưới dạng chuỗi decimal canonical; Lua so sánh chuỗi, không chuyển sequence qua floating point. iOS uint32 signCount và sequence int64 commit trong cùng thao tác atomic.
- Record thiết bị không tự hết hạn và không được reset sequence khi deploy/restart/register lại. Đăng ký lại cùng key phải bị từ chối; key mới tạo ID mới. Phải có job quản trị/lifecycle để thu hồi key, không cho client xóa/reset tùy ý.
- Bật AOF, noeviction, ACL tối thiểu; memory đầy thì fail closed. Backup phải giữ counter và key đồng bộ. Không tự fallback memory nếu Redis lỗi.
- Redis replication/failover bất đồng bộ có thể mất lần ghi đã được ACK. Lua atomic **không** tự bảo đảm durability qua failover. Thiết kế mức bảo đảm persistence/replication phù hợp trước production; nếu state rollback, tạm dừng protected traffic, điều tra và rekey/thu hồi thiết bị liên quan. Không coi restore backup là an toàn tự động cho replay/counter.
- Cấu hình Redis Cluster cần client/slot-aware adapter và mọi key của một atomic transaction cùng hash slot. Chỉ bật Cluster sau khi integration test chạy đúng adapter thực tế; URL Redis standalone không tự biến thành Cluster client.

## Retry, key lifecycle và tích hợp nghiệp vụ

- Client giữ sequence bền vững cùng key, loại khỏi cloud backup; serialize request được bảo vệ. AtomicLong chỉ tạo số duy nhất, không sửa thứ tự request đến server.
- Khi retry, tạo timestamp + sequence + signature/assertion mới. Có thể tăng sequence vượt số trước; không cần liên tiếp. Request bị lỗi business sau auth vẫn đã dùng sequence.
- Idempotency key nghiệp vụ nằm trong body đã ký, gắn với device/user + operation + hash payload. Business service cần persistent unique constraint/transaction/outbox để không trừ tiền hoặc tính AI hai lần. Authentication/replay guard không tạo exactly-once business semantics.
- Khi key bị mất/invalidated/counter iOS cạn, tạo key mới và re-attest; không reset counter của key cũ. Rate limit registration và quản lý liên kết tài khoản để giảm key farm.
- Tier 2 là integration auth tài khoản/OTP riêng. Không cho header `tier=2` hoặc `platform` tự khai bỏ qua Tier 1. Đừng mở API AI chỉ vì client nói rằng máy không hỗ trợ attestation.
- Handler Tarot đi kèm là ví dụ để kiểm thử luồng xác thực. Thay bằng business handler thật, quota và auth người dùng của sản phẩm; không xem ví dụ là dịch vụ AI/OTP đã triển khai.

## Root rotation và cập nhật

Theo `docs/SECURITY_SOURCES.md` ở mỗi phase/release. Lấy roots từ endpoint chính thức ngoài request path, kiểm tra fingerprint/validity và rollout có canary. Hỗ trợ Android RSA + EC root mới 2026 song song. Revocation refresh thất bại không được gia hạn timestamp snapshot.

Với iOS chỉ tin App Attestation root cho attestation chain; receipt/fraud-risk là chain và định dạng khác. Nếu cần fraud assessment, xác minh receipt độc lập theo Apple, lưu receipt an toàn và tích hợp Apple server API bằng credential server; không dùng receipt client tự khai làm quota đáng tin cậy.

## Canary và rollback

1. Chạy typecheck/build, tất cả fixture tests, Redis integration tests với namespace riêng, dependency audit.
2. Chạy Android thật trên TEE/StrongBox; iOS thật qua App Attest production và development tách riêng; kiểm tra root rotation, key invalidation, retry và network reorder.
3. Chạy qua chính reverse proxy production với raw body chứa whitespace và query có percent encoding. Kiểm tra sửa một byte bị từ chối.
4. Rollout canary, theo dõi latency, tỷ lệ error theo mã, registration failure, CRL age, Redis errors/memory, clock drift. Không log private key, toàn bộ attestation/payload cá nhân hoặc assertion.
5. Rollback artifact/config tương thích với **state hiện có**. Không rollback database counter và không mở policy chấp nhận software/development root để chữa lỗi rollout.

Chưa có benchmark 50 triệu request/ngày hoặc smoke test thiết bị thật thì không dùng các con số hiệu năng/“chặn 100% bot” trong tài liệu gốc làm cam kết triển khai.
