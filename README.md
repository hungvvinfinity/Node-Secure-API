# Node Secure API

Backend Node.js 24 + TypeScript dựa trên [SECURITY_SOLUTION.md](SECURITY_SOLUTION.md). Android dùng hardware Key Attestation; iOS dùng Apple App Attest. Hai platform triển khai cùng [DeviceSecurityProvider](src/contracts.ts); challenge, canonical request và Redis replay guard dùng chung.

[Kế hoạch và phase gates](IMPLEMENTATION_PLAN.md) · [Review và kết quả xác minh](docs/REVIEW.md) · [Ma trận kiểm thử](docs/TEST_MATRIX.md) · [Triển khai](docs/DEPLOYMENT.md) · [Giao thức client](docs/CLIENT_PROTOCOL.md) · [Nguồn và quy trình cập nhật](docs/SECURITY_SOURCES.md)

## Chạy local

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

## Phạm vi tích hợp

Gateway này triển khai xác minh thiết bị và request. Handler Tarot là ví dụ; AI, tài khoản/OTP Tier 2, database idempotency, quota và S3/MinIO presigned uploads cần được nối vào hệ thống sản phẩm. Không nâng trust của thiết bị bằng header Tier 2 hoặc fallback software key.

Thiết kế không chứng minh chặn mọi bot/signing oracle. Không dùng các ước tính chi phí, CPU, RAM hoặc throughput trong tài liệu gốc làm số đo của implementation này.
