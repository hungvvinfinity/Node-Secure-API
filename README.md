# Node Secure API

Backend Node.js 24 + TypeScript dựa trên [SECURITY_SOLUTION.md](SECURITY_SOLUTION.md). Android dùng hardware Key Attestation; iOS dùng Apple App Attest. Hai platform triển khai cùng [DeviceSecurityProvider](src/contracts.ts); challenge, canonical request và Redis replay guard dùng chung.

[Kế hoạch và phase gates](IMPLEMENTATION_PLAN.md) · [Kế hoạch tương thích Android](docs/ANDROID_COMPATIBILITY_PLAN.md) · [Review và kết quả xác minh](docs/REVIEW.md) · [Ma trận kiểm thử](docs/TEST_MATRIX.md) · [Triển khai](docs/DEPLOYMENT.md) · [Giao thức client](docs/CLIENT_PROTOCOL.md) · [Nguồn và quy trình cập nhật](docs/SECURITY_SOURCES.md)

## Chạy toàn bộ project bằng Docker Compose

`compose.yaml` chạy **API Node.js + Redis**, build image runtime, chờ Redis healthy và kiểm tra readiness API. Dữ liệu Redis ở named volume; API publish tại `http://127.0.0.1:3000`. Không cần Node/Redis cài trên host khi gọi Compose trực tiếp.

```bash
cp .env.example .env
# Điền package name, app signing SHA256; bật/cấu hình iOS nếu dùng
docker compose up --build -d --wait
docker compose ps
docker compose logs -f api
```

Chưa có app identity thật thì dùng cấu hình **demo khởi động** rõ ràng:

```bash
docker compose -f compose.yaml -f compose.demo.yaml up --build -d --wait
```

Demo bật cả Android/iOS với app identity ví dụ, vẫn dùng Google/Apple roots và CRL thật; không chấp nhận CA/chữ ký giả. Có thể xin challenge, kiểm tra API/Redis và lỗi authentication, chưa đăng ký được app sản phẩm cho đến khi cấu hình identity thật.

Trên máy hiện tại thiếu Buildx/bridge build DNS lỗi, lệnh đã dùng thành công là:

```bash
DOCKER_BUILDKIT=0 DOCKER_BUILD_NETWORK=host REDIS_BIND_PORT=0 npm run stack:demo
```

`API_PORT` đổi cổng API host; `REDIS_BIND_PORT=0` cấp cổng Redis loopback ngẫu nhiên để tránh xung đột. Trong container API luôn dùng `redis://redis:6379`; `.env` host Redis URL không ghi đè kết nối nội bộ này. Dừng bằng `npm run stack:down` hoặc `npm run stack:demo:down`; không thêm `-v` nếu cần giữ dữ liệu.

Sau khi stack healthy, có thể chạy `npm ci && npm run test:stack` trên host để xác minh cổng API thật, challenge hai platform, protected route 401 và CA tổng hợp bị runtime từ chối 403. Với server chỉ bật Android, dùng `STACK_TEST_PLATFORMS=android npm run test:stack`.

## Chạy Node trên host

```bash
npm ci
docker compose up -d redis
cp .env.example .env
# Điền package name, app signing certificate SHA256 và cấu hình trong .env
npm run typecheck
npm run build
node --env-file=.env dist/server.js
```

Redis là bắt buộc cho entrypoint chạy thật. `MemorySecurityStore` chỉ được inject trong test. Không có HTTP header/payload cho phép bỏ qua trust CA hoặc chuyển sang mock attestation.

## HTTP API

| Endpoint | Input | Kết quả |
|---|---|---|
| `POST /api/auth/challenge` | JSON `{"platform":"android"}` hoặc `{"platform":"ios"}` | challenge 64 ký tự hex, expiresAt milliseconds; TTL 60 giây, dùng một lần |
| `POST /api/auth/register-device` | Android: challenge, certificateChain (DER base64 từ leaf tới root); iOS: challenge, attestationObject base64, keyId base64 | deviceId do server suy ra từ public key đã xác minh |
| `POST /api/tarot/read` | Raw body cùng các security headers | Handler ví dụ sau khi xác thực; thay bằng business handler của sản phẩm |
| `GET /health` | Không | Liveness |
| `GET /ready` | Không | Readiness của security dependencies |

Ví dụ xin challenge:

```bash
curl -sS http://127.0.0.1:3000/api/auth/challenge \
  -H 'Content-Type: application/json' \
  --data-binary '{"platform":"android"}'
```

Registration phải sử dụng chứng thực từ thiết bị thật. Test sử dụng CA/chữ ký tổng hợp chỉ qua constructor injection trong process test, không phải chế độ đăng ký từ cURL để bỏ qua hardware.

Android request gửi `X-Device-Id`, `X-Timestamp`, `X-Sequence`, `X-Signature` (DER ECDSA P256 base64). iOS dùng `X-Assertion` thay chữ ký ECDSA trực tiếp. Provider được chọn từ record server đã lưu; client không được chọn provider để hạ policy khi gọi API.

Canonical UTF-8:

```text
timestamp:sequence:METHOD:raw-path-and-query:sha256-of-raw-body-lowercase-hex
```

Timestamp lệch tối đa 15 giây. Sequence canonical decimal từ `1` đến `9223372036854775807`, giữ dưới dạng string/BigInt. Chữ ký phải hợp lệ trước khi sequence được commit atomically. Mỗi retry dùng sequence/timestamp và bằng chứng mới; nghiệp vụ dùng idempotency key trong body đã ký và transaction riêng.

## Kiểm thử

Toàn bộ test với Redis thật qua Docker Compose, không cần cài Redis hay dependency trên host:

```bash
npm run test:docker
```

Lệnh tự build image, chờ Redis healthy, chạy suite/coverage/typecheck/audit rồi restart chính service Redis và kiểm tra replay state. Mỗi lần dùng project/volume riêng và tự cleanup. Redis test không publish cổng host. Trên Linux thiếu Buildx hoặc bridge DNS lỗi: `DOCKER_BUILDKIT=0 DOCKER_BUILD_NETWORK=host npm run test:docker`.

Nếu dùng Redis test đã có sẵn:

```bash
npm run typecheck
npm run build
REDIS_TEST_URL=redis://127.0.0.1:6379 npm test
REDIS_TEST_URL=redis://127.0.0.1:6379 npm run test:ci
npm audit --audit-level=moderate
npm run security:sources
```

`REDIS_TEST_URL` dành cho Redis test riêng; tests dùng random prefix và không flush database. Đã cấu hình Redis test mà không kết nối được thì test fail; `test:ci` từ chối chạy nếu thiếu biến này. `npm test` không cấu hình Redis chỉ dành cho unit-only local và có thể skip integration; không dùng kết quả đó làm nghiệm thu. `security:sources` cần Git/network, báo drift của commit upstream Android và Google root fingerprints để review; không tự thay trust bundle. CI chạy chính Compose test pipeline, có job kiểm tra drift hàng tuần.

Kết quả Compose: **212 test pass, 0 fail, 0 skip** với Redis thật. [Báo cáo review](docs/REVIEW.md) ghi các lỗi đã sửa, Docker smoke, Redis restart, coverage và giới hạn thực tế. Fixture mật mã và Redis thật không thay cho smoke test Android/iOS thật, kiểm thử proxy production hoặc benchmark tải. [Runbook canary](docs/CANARY.md) có tiêu chí pass/fail và mẫu bằng chứng cho thiết bị thật.

## Benchmark capacity bằng k6

```bash
npm run benchmark:capacity
# Trên môi trường Linux hiện tại:
DOCKER_BUILDKIT=0 DOCKER_BUILD_NETWORK=host npm run benchmark:capacity
# Scale 4 API process, giữ chung Redis:
CAPACITY_API_REPLICAS=4 CAPACITY_REPORT_FILE=capacity-four.json npm run benchmark:capacity
```

Runner build stack benchmark riêng, seed key tổng hợp, phát request ECDSA hợp lệ vào **runtime API thật** bằng k6, tăng tải/dò biên rồi xác nhận 60 giây. Báo cáo tách accepted/rejected/dropped, p95/p99 và CPU/RAM; không tính request lỗi thành throughput thành công. Fixture private key chỉ ở thư mục tạm và được xóa khi cleanup. Không đụng Redis của stack demo.

Đây là Android steady-state với key đã seed, không đo registration hardware, iOS, TLS/proxy hoặc AI business workload. Ngưỡng dùng để dò capacity: p95 <100ms, p99 <250ms, lỗi <1%, dropped=0. `CAPACITY_RATES`, `CAPACITY_STAGE_SECONDS`, `CAPACITY_CONFIRM_SECONDS`, `CAPACITY_VUS` cho phép đổi workload; report ghi cấu hình và không tuyên bố một con số RPS tối đa cho mọi môi trường. Xem [CAPACITY.md](docs/CAPACITY.md) và raw JSON sau mỗi lần chạy.

## Phạm vi tích hợp

Gateway này triển khai xác minh thiết bị và request. Handler Tarot là ví dụ; AI, tài khoản/OTP Tier 2, database idempotency, quota và S3/MinIO presigned uploads cần được nối vào hệ thống sản phẩm. Không nâng trust của thiết bị bằng header Tier 2 hoặc fallback software key.

Thiết kế không chứng minh chặn mọi bot/signing oracle. Không dùng các ước tính chi phí, CPU, RAM hoặc throughput trong tài liệu gốc làm số đo của implementation này.
