# Canary với thiết bị thật

Trạng thái hiện tại: **chưa chạy hardware canary** vì chưa có thiết bị và app signing identity. Docker Compose chạy mật mã/chữ ký, HTTP và Redis thật bằng fixture CA chỉ inject trong test. Nó không chứng minh phần cứng Android/Apple đã attest app của sản phẩm.

## 1. Chuẩn bị staging

- Ghi image digest, commit/version và thời gian chạy. Dùng Redis staging riêng, AOF + noeviction, policy replication/backup đã review; không dùng database production.
- Android: package name, SHA256 **app signing certificate**, minimum version; build app với key SIGN/SHA256/P256 trong AndroidKeyStore. Chuẩn bị TEE và StrongBox nếu thiết bị hỗ trợ, ghi rõ mode không hỗ trợ.
- iOS: App ID prefix thực tế + bundle ID, entitlement App Attest và provisioning profile. Development canary dùng staging riêng với `IOS_APP_ATTEST_ENV=development`, `NODE_ENV=development`; bản production/TestFlight dùng cấu hình production. Không đổi AAGUID/policy theo header client.
- Cấu hình TLS/proxy giữ nguyên encoded path/query/raw body; đồng bộ NTP. Các thiết bị gửi request tuần tự theo [CLIENT_PROTOCOL.md](CLIENT_PROTOCOL.md).

Đối chiếu hướng dẫn chính thức trước khi chạy: [Android server validation](https://developer.android.com/privacy-and-security/security-key-attestation), [Apple chuẩn bị App Attest](https://developer.apple.com/documentation/devicecheck/preparing-to-use-the-app-attest-service), [Apple establishing integrity](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity). Chứng thực được xác minh trên server; không để ứng dụng tự quyết định trust.

Đối chiếu ngày 2026-10-28 UTC phát hiện hai trang Apple chưa thống nhất: trang preparation nêu sandbox AAGUID `appattestsandbox`, còn [quy trình validation](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server) nêu development AAGUID `appattestdevelop`. Code hiện theo quy trình validation, chỉ nhận `appattestdevelop` khi server cấu hình development; production chỉ nhận `appattest` + 7 byte zero. Khi có thiết bị, ghi AAGUID quan sát được để review tương thích nếu cần; không tự chấp nhận mọi AAGUID hoặc đổi policy production để làm canary pass.

## 2. Gate Docker trước hardware

```bash
npm run test:docker
```

Lệnh build image test, tạo Compose project ngẫu nhiên, chờ Redis healthy, chạy typecheck + coverage/integration + audit, seed replay state, restart service Redis thật rồi kiểm tra tiếp tục sequence/counter/challenge. Redis không publish cổng host. Cuối lượt chạy xóa đúng project/network/volume test vừa tạo; không đụng Redis trong `compose.yaml`.

Nếu máy Linux thiếu Buildx hoặc bridge DNS lỗi như môi trường hiện tại:

```bash
DOCKER_BUILDKIT=0 DOCKER_BUILD_NETWORK=host npm run test:docker
```

Host cần Node 24 + Docker Compose; không cần host Redis hoặc `node_modules` cho lệnh orchestration này. Image tự chạy `npm ci`. Lượt build đầu cần truy cập registry/npm. Không gắn Docker socket vào test runner.

## 3. Preflight endpoint

```bash
CANARY_BASE_URL=https://staging.example.com npm run canary:preflight
```

Thay URL bằng origin staging thật. Script chỉ GET `/health` và `/ready`, yêu cầu 200 cùng JSON status `UP`/`READY`, không follow redirect, giới hạn thời gian và kích thước response. HTTP chỉ cho loopback để smoke local; remote bắt buộc HTTPS. Exit 0 chỉ nghĩa preflight pass; report luôn có `hardwareAttestationVerified: false`. Không dùng ví dụ URL làm bằng chứng đã triển khai.

## 4. Case và tiêu chí pass

| ID | Thao tác | Kỳ vọng và bằng chứng |
|---|---|---|
| C01 | Xin challenge cho đúng platform, tạo key/attestation thật, đăng ký trong 60s | 200 + deviceId; backend ghi nhận app identity và public key đã verify. Ghi fingerprint root, provisioning method và security level cho Android; AAGUID/environment cho iOS bằng tooling nội bộ được cấp quyền. |
| C02 | Dùng lại challenge hoặc challenge hết TTL | 401, không tạo record mới. Challenge hết TTL phải xin lại; không hạ TTL policy để sửa lỗi thiết bị/network. |
| C03 | Đăng ký bằng key khác với challenge/nonce cũ; package/signer/App ID không khớp | Từ chối trước lưu record. Test wrong app bằng staging config hoặc app fixture riêng, không sửa allowlist production. |
| C04 | Request ký đúng với body rỗng, JSON có whitespace, query chứa `%2F`, Unicode | 200 qua đúng proxy; signature/assertion bảo vệ nguyên byte gửi. iOS counter tăng. |
| C05 | Giữ signature/assertion, sửa một byte body hoặc đổi method/query | 401; lastSequence/signCount không tăng, business handler không chạy. |
| C06 | Gửi lại nguyên request đã được chấp nhận | 401 replay/counter error; business không chạy lần hai. |
| C07 | Ký 20 bản cùng sequence, gửi đồng thời | Chính xác một request vượt auth; 19 request bị chặn. Sau đó quay lại gửi tuần tự. Không yêu cầu một mã lỗi duy nhất giữa replay và iOS counter khi có race. |
| C08 | Với iOS, assertion counter cũ và sequence mới | 401; cả sequence/counter giữ nguyên. Assertion counter tiếp theo, sequence mới được chấp nhận. |
| C09 | Timestamp quá ±15s; sequence `0`, leading zero, overflow int64 | Timestamp 401; malformed sequence 400. Không dùng clock skew lớn để chữa sai NTP. |
| C10 | Restart app/server instance, giữ Redis staging và key client; gửi lại request cũ rồi số mới | Request cũ bị chặn, số mới được chấp nhận; deviceId/public key không thay. Lưu sequence/counter trước và sau. |
| C11 | Restart Redis staging có durability đã cấu hình, reconnect app | Giữ nguyên replay state; số cũ bị chặn, số mới thành công. Chỉ làm trên staging riêng; đây không phải kiểm chứng asynchronous failover/restore backup. |
| C12 | Dừng Redis staging có kiểm soát trong khi cache identity đang nóng | Protected request bị từ chối trước business, readiness 503. Khôi phục Redis rồi số mới thành công; không fallback memory. |
| C13 | Bật app iOS development gửi sang instance production | Đăng ký bị từ chối; không có header chọn môi trường thay server. |
| C14 | Thử device/app không hỗ trợ attestation hoặc key invalidated | Client xử lý lỗi/rekey theo lifecycle; không chuyển sang software key tự khai để truy cập API được bảo vệ. |
| C15 | Root Google RSA/EC 2026 và factory-expiry/RKP cases | Thu thập chain từ thiết bị nếu có. Mẫu không có thiết bị tương ứng ghi NOT_RUN; fixture upstream trong Compose đã kiểm tra riêng, không tuyên bố hardware coverage chỉ từ fixture. |

Đối với request timeout sau auth, sequence có thể đã commit. Retry phải ký timestamp/sequence mới, cùng idempotency key nghiệp vụ. Thiết bị iOS có thể đã tăng counter khi generateAssertion kể cả request bị từ chối; lần sau dùng assertion mới, không ép giảm counter.

## 5. Bằng chứng và quyết định rollout

Copy [canary-evidence.template.json](canary-evidence.template.json), ghi PASS/FAIL/NOT_RUN từng case, expected/actual HTTP + error code, redacted trace ID và state trước/sau. Giữ private key trên thiết bị; không gửi private key, credential Redis hoặc toàn bộ receipt/payload vào report/log công khai. Không có public debug endpoint đọc state; kiểm tra Redis/metadata bằng quyền vận hành staging được cấp sẵn.

Chỉ xét rollout khi case bắt buộc của platform được hỗ trợ pass, không có unexplained skip, raw-byte proxy check pass và reviewer xác nhận artifact/config/state tương thích. Case thiết bị không có phải được ghi rõ phạm vi trước release. Khi lỗi bảo mật hoặc state rollback: dừng canary, giữ bằng chứng, sửa và chạy lại; không mở trust policy, reset sequence hoặc restore counter cũ để làm test xanh.
