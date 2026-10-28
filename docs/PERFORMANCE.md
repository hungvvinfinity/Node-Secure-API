# Đường request và phép đo local

Đã đo ngày 2026-10-28 UTC với Node v24.21.0, Redis thật trong container test, **AOF + appendfsync always**, HTTP loopback, 16 thiết bị tổng hợp, mỗi thiết bị gửi tuần tự. 1.024 request mỗi chế độ sau warm-up. Tất cả request phải trả 200, không tính request bị từ chối thành throughput thành công.

| Chế độ | Request/giây | p50 ms | p95 ms | Redis đọc record | Atomic commit |
|---|---:|---:|---:|---:|---:|
| Đọc Redis mỗi request | 2.076 | 7,25 | 11,18 | 1.024 | 1.024 |
| Cache identity nóng | 2.691 | 5,72 | 7,72 | 0 | 1.024 |

Đây là **một lần chạy local**, gồm chi phí ký bằng software của sender, HTTP, ECDSA verify và Redis. Không đo Android TEE/StrongBox, Apple App Attest, proxy/TLS production hoặc nghiệp vụ AI. Không suy ra cam kết 50 triệu request/ngày từ phép đo này.

Microbenchmark riêng 10.000 ECDSA verify: dùng PEM mỗi lần 595,95 ms; dùng KeyObject cache 480,37 ms. Số đo phụ thuộc CPU, runtime, dữ liệu và cạnh tranh tài nguyên. Lượt đo trước dùng Redis fsync mặc định everysec; bảng hiện tại đã đo lại với cấu hình persistence mạnh hơn giống compose.

## Tối ưu đã áp dụng

- X.509/ASN.1/revocation chỉ ở registration; request thường xác minh bằng public key đã chứng thực.
- Cache KeyObject EC P256 tối đa 4.096 entries để tránh parse PEM lặp lại.
- Cache identity thiết bị bằng LRU tối đa 4.096 entries, TTL 5 phút. Cache không chứa quyết định “request hợp lệ”.
- Mọi sequence/counter commit đi tới Redis Lua; Lua kiểm tra record còn tồn tại, đúng public key, sequence tăng, và iOS counter tăng trong cùng thao tác. Xóa/đổi key ở Redis vẫn chặn cached device khi commit.
- Cache lạnh đọc HMGET các trường cần xác thực. Apple receipt được lưu bền vững ở trường `receipt` riêng trong hash thiết bị, không được truyền/parse lại trên đường request. Risk worker nội bộ có thể đọc trường này; không có endpoint client công khai đọc receipt.
- SHA256 trên raw bytes; không JSON parse/stringify lại để thử chữ ký. Body có giới hạn; ảnh lớn phải dùng luồng upload riêng.
- Kết nối Redis dùng chung, đồng bộ hóa handshake khi nhiều request đến cùng lúc; hàng đợi, handshake và command có giới hạn. Request sai chữ ký không ghi sequence.

Cache biến mất khi restart và được nạp lại từ Redis. Private key, public key và replay state không được tạo lại/reset khi process restart. Redis cần durability đúng như `DEPLOYMENT.md`; ứng dụng cache không sửa được state rollback do failover/storage mất dữ liệu.

## Chạy lại

```bash
BENCHMARK_REDIS_URL=redis://127.0.0.1:6379 npm run benchmark
# Tùy chọn:
BENCHMARK_REDIS_URL=redis://127.0.0.1:6379 \
BENCHMARK_REQUESTS=10000 BENCHMARK_DEVICES=64 npm run benchmark
```

Script chỉ bind HTTP loopback, seed key tổng hợp trực tiếp vào namespace Redis ngẫu nhiên để đo steady state, rồi xóa đúng các key của lượt đo. Nó không thêm mock CA/endpoint vào server sản phẩm. Cần Redis dành riêng cho kiểm thử để kết quả không bị workload khác làm sai lệch.

Để quyết định capacity production, đo nhiều lần trên artifact/container triển khai thật, qua TLS/proxy thật, với phân bố cache hit/miss, burst, slow client, payload sizes, thiết bị và Redis failover đại diện; quan sát p95/p99, CPU, RSS, event-loop lag và accepted requests/giây.
