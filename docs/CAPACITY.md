# Capacity đo bằng k6 trên runtime Docker

Đo ngày **2026-10-29 tại Việt Nam**. Đây là số đo cục bộ cho authenticated Android steady-state trên API hiện có, không phải cam kết RPS production hoặc chứng minh một giá trị tối đa tuyệt đối.

## Môi trường và workload

- AMD Ryzen 7 8845H, 16 logical CPU, khoảng 26,7 GiB RAM. API, Redis và k6 cùng chạy trên máy này; máy cũng đang chạy môi trường phát triển, không phải máy benchmark độc quyền.
- Runtime Node v24.22.1 trong image runtime thật, Redis 8.10.3; **AOF + appendfsync always**, noeviction và named volume. Không hạ durability để tăng RPS.
- Grafana k6 **2.3.0**, image pin digest trong `compose.benchmark.yaml`. Dùng [constant-arrival-rate](https://grafana.com/docs/k6/latest/using-k6/scenarios/executors/constant-arrival-rate/), không dùng vòng lặp kín khiến client tự giảm tải khi server chậm.
- Body 18 byte `{"benchmark":true}`, route `POST /api/tarot/read`. Mỗi request ký ECDSA P-256 SHA256 thật, server verify thật và commit sequence bằng Redis Lua thật. Handler trả Tarot demo; không đo AI/OTP/database business/TLS/proxy.
- Seed 512 public key tổng hợp vào **Redis benchmark riêng**, dùng production `RedisSecurityStore`. Private key PKCS8 chỉ ở fixture tạm cho k6, không được gửi qua API hay commit. API runtime vẫn giữ official roots/revocation; không thêm mock-CA switch.
- Một key cho mỗi VU, mỗi VU gửi tuần tự; sequence offset tăng giữa các stage. k6 WebCrypto trả P1363 64 byte, script chuyển sang DER trước khi gửi. Cache identity/KeyObject được làm nóng tự nhiên trong lượt chạy.
- Bốn replica dùng chung Redis; k6 kết nối tới service DNS `api`, chọn IP ngẫu nhiên khi mở connection và reuse connection theo mặc định. Đây không phải phép đo L7 load balancer/TLS production. Xem [k6 DNS behavior](https://grafana.com/docs/k6/latest/using-k6/k6-options/reference/#dns).

## Cách xác định ngưỡng

Sweep mặc định 15 giây mỗi mức, tăng tới khi không đạt; refine biên theo bước 250 RPS rồi xác nhận 60 giây. Nếu xác nhận không đạt, runner giảm candidate khoảng 20% và thử lại, tối đa ba lượt. Mức được xác nhận là một **lower bound đã đo**, không có nghĩa mọi mức cao hơn đều không thể chạy.

Tiêu chí giữ nguyên trong mọi lượt: p95 HTTP <100ms, p99 <250ms, HTTP error <1%, dropped iteration =0, số request được chấp nhận ít nhất 99% số dự kiến. Chỉ status 200 tăng `accepted`; từ chối không được tính là throughput thành công. Request chưa được k6 phát đi được báo riêng là `dropped`, không được gọi là lỗi server. [k6 giải thích dropped iterations](https://grafana.com/docs/k6/latest/using-k6/scenarios/concepts/dropped-iterations/) có thể bắt nguồn từ generator hoặc hệ thống quá tải.

`http_req_duration` gồm send/wait/receive của HTTP, không phải tổng latency của thiết bị: không gồm Android TEE, ký bằng phần cứng, key import hay DNS/connect ban đầu. Signing trend dùng `Date.now()` có độ phân giải 1ms, không dùng để suy luận chi phí ký dưới millisecond.

CPU/RAM lấy từ Docker stats khoảng mỗi hai giây. CPU tổng API là tổng các replica cùng mẫu; 100% tương đương khoảng một logical CPU. Trường `resourcePeaks.<service>.memory` là RSS/container memory **tại mẫu CPU cao nhất**, không phải cam kết peak RAM tuyệt đối. Samples có thể bỏ lỡ đỉnh ngắn.

## Báo cáo và tính minh bạch

- [Single process, 256 VU preallocated](capacity-single.json): lượt ban đầu, 4.000 RPS/60s có 8 dropped iterations nên **không** được đánh dấu strict pass.
- [Single process, 512 VU preallocated](capacity-single-512vus.json): cấp sẵn toàn bộ VU để tránh chi phí tăng pool trong lúc đo; xác nhận 4.000 RPS, 240.000 accepted, 0 reject/drop, p95 6,09ms, p99 12,28ms. Lượt 5.250 RPS/60s vẫn có 519 drops nên không được công bố là strict pass.
- [Bốn process, 256 VU preallocated](capacity-4-replicas.json): xác nhận 9.000 RPS/60s, 540.001 accepted, 0 reject/drop, p95 5,70ms, p99 8,92ms. Lượt 12.000 RPS đạt khoảng 11.991 accepted/s nhưng có 141 drops nên không dùng con số đó làm capacity strict pass.
- [Bốn process, 512 VU, cold jump 10.000 RPS](capacity-four-512vus.json): khoảng 9.977 accepted/s, 0 HTTP lỗi nhưng 341 drops ngay lượt 15s đầu, nên không có mức confirmed trong report này. Lượt này bắt đầu trực tiếp ở 10.000 sau smoke 50 RPS, khác lượt sweep tăng dần đã làm nóng JIT/cache. Nó cho thấy không thể dùng một kết quả hot steady-state làm bảo đảm cho burst startup. Không đổi tiêu chí để ép pass.

| Mức đã xác nhận 60s | Accepted | HTTP lỗi | Dropped | p95 HTTP | p99 HTTP |
|---|---:|---:|---:|---:|---:|
| 1 API, 4.000 RPS | 240.000 | 0 | 0 | 6,09ms | 12,28ms |
| 4 API, 9.000 RPS | 540.001 | 0 | 0 | 5,70ms | 8,92ms |

Ceiling throughput quan sát khi ép tải: khoảng **5.500 accepted/s** cho một process và **12.000 accepted/s** cho bốn process; các mức này có dropped iterations nên không phải strict no-drop capacity. Bảng xác nhận dùng lần lượt 512 và 256 VU preallocated, cùng maxVUs=512 và 512 synthetic devices; đây là so sánh thực nghiệm, không phải phép đo scaling độc lập mọi biến.

Các kết quả sweep/refine/confirmation, kể cả các mức fail, đều có trong raw JSON. Lượt smoke chưa phát được request hợp lệ do API k6 cũ/timer không hỗ trợ đã bị runner chặn; không dùng làm số đo capacity. Sau đó đã sửa dùng WebCrypto global của k6 2.3 và `Date.now()`, xác minh chữ ký hợp lệ bằng traffic 200 thật.

Kết quả cho thấy scale nhiều API process có lợi trên máy này; một process có thể tiến gần bão hòa CPU trước Redis. Đây là suy luận từ CPU samples và throughput, không phải profile chứng minh duy nhất một bottleneck. Đừng suy ra throughput cả ngày, AI workload hoặc môi trường khác từ một lượt 60 giây.

## Chạy lại

```bash
# Chỉ cần Node 24 và Docker Compose trên host; build/test chạy trong container.
DOCKER_BUILDKIT=0 DOCKER_BUILD_NETWORK=host npm run benchmark:capacity

# Bốn process, chọn dải tải và tên report riêng:
DOCKER_BUILDKIT=0 DOCKER_BUILD_NETWORK=host \
CAPACITY_API_REPLICAS=4 CAPACITY_VUS=512 \
CAPACITY_RATES=500,1000,2000,4000,8000,12000,16000 \
CAPACITY_REPORT_FILE=capacity-four-512vus.json npm run benchmark:capacity
```

Máy có Buildx và build network bình thường có thể bỏ hai biến Docker đầu. `CAPACITY_STAGE_SECONDS` và `CAPACITY_CONFIRM_SECONDS` (3..300s) đổi thời lượng; giữ ít nhất 60s xác nhận khi so sánh kết quả. Khi tất cả mức đều pass, tăng dải tải và chạy lại; chưa chạm failure thì chưa tìm được vùng bão hòa.

Hãy bắt đầu từ tải thấp để có baseline và warm-up nhất quán. Nếu tùy chỉnh dải bắt đầu cao và mức đầu đã fail, runner báo `confirmedTargetRps: null`; không diễn giải thành capacity bằng 0. Giữ cả các report fail/burst khi đánh giá capacity và headroom.

Mỗi lượt dùng Compose project/network/Redis volume riêng, không publish port benchmark. Report JSON ghi vào `docs/<CAPACITY_REPORT_FILE>`; raw summaries/logs/resource samples ở thư mục `/tmp/secure-api-capacity-*` được in đầu lượt. Cuối lượt runner xóa container/network/Redis volume của chính nó và xóa fixture private key; giữ summaries không chứa private key để kiểm tra. Không dùng script seed với database production.

Trước capacity planning thật, cần đo máy phát tải riêng, TLS/proxy thật, iOS assertion riêng, payload/cache distributions thực tế, long soak và failover. Fixture benchmark không thay hardware canary trong [CANARY.md](CANARY.md).
