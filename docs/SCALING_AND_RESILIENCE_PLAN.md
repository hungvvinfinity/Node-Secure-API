# Kế Hoạch Scale Ngang Tuyến Tính & Bền Vững Hóa Trạng Thái Hệ Thống (PostgreSQL + Redis + Docker Compose)

Tài liệu này đặc tả chi tiết kiến trúc mở rộng (horizontal scaling) và giải pháp triệt tiêu điểm nghẽn, loại bỏ rủi ro mất trạng thái cho **Node Secure API**. Kế hoạch chuyển đổi hệ thống từ mô hình phụ thuộc hoàn toàn vào một node Redis đơn lẻ sang **Kiến trúc Lưu Trữ Phân Tầng (Tiered Storage Architecture)** với PostgreSQL làm nguồn chân lý dữ liệu (Source of Truth) và Redis làm công cụ kiểm tra chuỗi tăng đơn điệu siêu tốc (High-Speed Replay Engine).

---

## 1. Bối Cảnh & Phân Tích Căn Nguyên (Root Cause Analysis)

### 1.1 Vấn đề 1: Khi nhỏ phục vụ tốt nhưng khi tải cao không scale ngang được
Hiện tại hệ thống hỗ trợ tăng số lượng tiến trình API (`CAPACITY_API_REPLICAS`), tuy nhiên khi lưu lượng request tăng mạnh, khả năng scale ngang bị suy giảm nghiêm trọng do 5 rào cản kiến trúc:

1. **Nút thắt Redis đơn luồng (Single-Threaded Execution Bottleneck):**
   - Mọi request nghiệp vụ đã đăng ký đều bắt buộc phải chạy qua hàm CAS `COMMIT_SEQUENCE_LUA` trên Redis để kiểm tra `sequence` tăng dần và `signCount` của iOS.
   - Redis xử lý lệnh trên một luồng duy nhất (single-threaded event loop). Khi scale từ 1 lên 4, 8 hay 16 container API, toàn bộ năng lực CPU dành cho việc giải mã mật mã (ECDSA P-256) được dàn đều ra các CPU core, nhưng **toàn bộ luồng ghi tuần tự lại dồn về 1 socket Redis duy nhất**.
   - Kết quả đo lường thực tế tại [CAPACITY.md](CAPACITY.md): 1 tiến trình API đạt ~4.000 RPS; 4 tiến trình API chỉ đạt ~9.000 RPS (tỷ lệ tăng trưởng 2.25x thay vì 4x) và bắt đầu xuất hiện tình trạng rớt iteration khi ép tải lên 12.000 RPS do Redis đạt ngưỡng bão hòa xử lý.

2. **Phân mảnh bộ nhớ đệm L1 giữa các Replica (Cache Fragmentation):**
   - `CachingSecurityStore` duy trì một LRU cache cục bộ trong RAM của từng tiến trình Node.js (mặc định 4.096 entries).
   - Nếu Load Balancer phân phối request theo cơ chế Round-Robin hoặc Least Connections ngẫu nhiên: các request liên tiếp từ cùng một điện thoại $A$ sẽ rơi lần lượt vào Replica 1, Replica 2, Replica 3, Replica 4...
   - Hệ quả: Tỷ lệ Cache Hit của L1 RAM bị suy giảm mạnh ($1/N$ với $N$ là số replica). Mỗi replica đều bị "Cache Miss" cho thiết bị $A$, dẫn đến việc cả $N$ replica đều phải gọi lệnh `HMGET` vào Redis để kéo public key và metadata về RAM. Điều này gây ra hiện tượng **khuếch đại lệnh đọc (Read Amplification)** lên Redis gấp nhiều lần số replica.

3. **Nghẽn kết nối đơn lẻ và bão Reconnect (Connection Chokepoint & Storm):**
   - Trong `src/store/redis.ts`, mỗi tiến trình API chỉ duy trì **1 kết nối TCP duy nhất** tới Redis với cấu hình `commandsQueueMaxLength: 4096` và `reconnectStrategy: false`.
   - Khi có đột biến tải (>500 concurrent request/tiến trình), nếu Redis bị trễ quá 1.000ms (`commandTimeoutMs`), lệnh `this.discard(client)` lập tức phá hủy socket TCP. Khi socket bị hủy, toàn bộ các request đang xếp hàng trong hàng đợi đều bị đánh fail 503 `STORE_ERROR`, đồng thời kích hoạt bão tạo lại kết nối (`ensureConnected`) cùng lúc, gây tê liệt gateway.

4. **Khuếch đại nguy cơ DoS bộ nhớ từ `/api/auth/challenge`:**
   - Endpoint `/api/auth/challenge` hoàn toàn mở (không cần chữ ký hay chứng thực phần cứng), mỗi lần gọi sẽ sinh ra chuỗi hex 64 ký tự và ghi vào Redis với TTL 60s.
   - Khi bị botnet tấn công spam hàng chục nghìn challenge/giây, Redis sẽ bị quá tải bộ nhớ RAM. Do Redis cấu hình `--maxmemory-policy noeviction`, khi đầy RAM Redis sẽ từ chối mọi lệnh ghi mới (`OOM command not allowed`), làm sập cả luồng commit sequence của các thiết bị thật.

5. **Lặp lại việc tải Google CRL (Upstream Polling Duplication):**
   - Mỗi instance API trong `src/runtime.ts` đều kích hoạt timer 5 phút chạy ngầm độc lập để tải danh sách thu hồi khóa của Google. Khi scale lên 20-50 replicas, sẽ có 20-50 request HTTPS đồng thời bắn tới hạ tầng Google, dễ dẫn đến bị chặn IP hoặc lãng phí băng thông mạng.

---

### 1.2 Vấn đề 2: Điểm nghẽn ở Redis và rủi ro mất trạng thái khi chậm hoặc restart

1. **Nghẽn IOPS do cấu hình `appendfsync always`:**
   - Trong `compose.yaml`, Redis chạy với tham số:
     `command: ["redis-server", "--appendonly", "yes", "--appendfsync", "always", "--maxmemory-policy", "noeviction"]`
   - Chế độ `always` ép buộc hệ điều hành phải thực thi lệnh `fsync()` vật lý xuống ổ cứng sau **từng lệnh ghi đơn lẻ** trước khi trả lời tiến trình API.
   - Các dòng ổ cứng đám mây tiêu chuẩn (như AWS EBS gp3 với baseline 3.000 IOPS) sẽ lập tức đạt ngưỡng giới hạn vật lý khi hệ thống chạm 3.000 writes/giây. Hàng đợi ghi đĩa của Linux bị dồn ứ, đẩy độ trễ của Redis từ <1ms lên 50ms - 200ms, kéo sập toàn bộ các kết nối API qua timeout.

2. **Rủi ro mất sạch toàn bộ dữ liệu thiết bị (Single Point of Failure):**
   - Hiện tại, Redis là **nơi duy nhất trên toàn hệ thống** lưu trữ thông tin đăng ký thiết bị (`sec:device:<deviceId>`).
   - Redis vốn dĩ là một In-Memory Datastore. Nếu gặp một trong các tình huống sau:
     - Quản trị viên vô tình chạy lệnh `docker compose down -v` làm xoá named volume `redis-data`.
     - Ổ cứng lưu AOF bị hỏng hoặc file AOF bị corrupt trong quá trình ghi.
     - Nâng cấp cluster / node failover trong môi trường Cloud nhưng cơ chế snapshot chưa kịp sync.
   - **Hậu quả thảm khốc:** Toàn bộ danh tính thiết bị đã được Google/Apple chứng thực bị xóa sạch vĩnh viễn. Vì Private Key đã được tạo và niêm phong trong chip TEE / Secure Enclave của điện thoại và ứng dụng phía client tin rằng nó đã đăng ký thành công, **100% người dùng hiện hữu sẽ bị khóa ngoài ứng dụng (báo lỗi `DEVICE_NOT_REGISTERED`)**, không thể tự phục hồi trừ khi người dùng xóa app cài lại.

---

## 2. Phân Tích Chuyên Sâu: Cân Nhắc Khi Chuyển Sang `appendfsync everysec`

### 2.1 Bản chất kỹ thuật & Sự khác biệt

| Tiêu Chí So Sánh | `appendfsync always` | `appendfsync everysec` |
|---|---|---|
| **Cơ chế ghi** | Ghi vào Kernel Page Cache $\rightarrow$ Gọi ngay `fsync()` chặn luồng chính cho tới khi đĩa cứng xác nhận | Ghi vào Kernel Page Cache $\rightarrow$ Trả lời ngay cho client; Background thread riêng gọi `fsync()` mỗi giây 1 lần |
| **Throughput ghi** | Bị trần cứng bởi IOPS đĩa: **1.000 – 3.000 ops/sec** | Tốc độ ghi RAM thuần túy: **50.000 – 100.000+ ops/sec** |
| **Độ trễ p99** | **15ms – 100ms+** (rất nhạy cảm với disk I/O contention) | **< 1ms – 2ms** (cực kỳ ổn định) |
| **Mất dữ liệu khi Restart chuẩn (`SIGTERM`)** | **0 byte** (Không mất dữ liệu) | **0 byte** (Không mất dữ liệu, Redis luôn flush đệm trước khi tắt) |
| **Mất dữ liệu khi Sập nguồn đột ngột (`kill -9`)** | Không mất (chỉ mất giao dịch chưa ACK) | **Mất dữ liệu trong khoảng 0 – 1 giây cuối cùng** |

### 2.2 Đánh giá rủi ro thực tế đối với `Node-Secure-API` khi mất 1 giây cuối

Nếu máy chủ Redis bị rút nguồn đột ngột và mất 1 giây dữ liệu gần nhất:

1. **Rủi ro với Danh tính Thiết bị (`createDeviceNX`):**
   - *Nếu chỉ có Redis:* Thiết bị đăng ký trong 1 giây đó sẽ bị mất vĩnh viễn.
   - *Khi đã tích hợp PostgreSQL (Kiến trúc Lưu Trữ Phân Tầng):* **RỦI RO HOÀN TOÀN BẰNG 0**.
   - Mọi thiết bị mới đăng ký đều được ghi thành công vào PostgreSQL (ACID) trước khi nạp vào Redis. Khi Redis bật lại và thiếu record đó, Gateway tự động truy vấn PostgreSQL và nạp ngược lại vào Redis (Cache-aside) mà không có bất kỳ gián đoạn nào.

2. **Rủi ro với Chuỗi Replay (`lastSequence` & `signCount`):**
   - Giả sử lúc $t_0$, Thiết bị A gửi request với `seq = 500`. Redis ghi nhận `lastSequence = 500`.
   - Ngay sau đó Redis sập nguồn trước khi kịp `fsync` giây đó. Khi khởi động lại, đĩa chỉ lưu trạng thái trước đó là `seq = 499`.
   - **Lỗ hổng Replay xuất hiện nếu:** Kẻ tấn công nghe lén được gói tin `seq = 500` trên đường truyền và phát lại đúng gói tin này. Vì Redis hiện tại có `lastSequence = 499`, phép so sánh $500 > 499$ sẽ coi gói tin là hợp lệ.
   - Tuy nhiên, cửa sổ thời gian để kẻ tấn công có thể phát lại bị giới hạn bởi:
     $$\Delta t = |t_{\text{now}} - t_{\text{request}}| \le 15.000\,\text{ms}$$

### 2.3 Giải pháp triệt tiêu hoàn toàn rủi ro Replay: Timestamp Quarantine 15s

Để loại bỏ 100% rủi ro replay mà không phải trả giá bằng việc hạ throughput ghi xuống mức 3.000 ops/sec của `appendfsync always`, hệ thống áp dụng cơ chế **Kiểm Dịch Thời Gian (Timestamp Quarantine)**:

```mermaid
sequenceDiagram
    autonumber
    participant Redis as Redis Server
    participant Gateway as Node API Gateway
    participant Attacker as Kẻ Tấn Công (Gói tin bắt lén)
    participant Client as Thiết Bị Thật

    Note over Redis: Sự cố: Redis bị sập nguồn đột ngột!
    Redis->>Redis: Khởi động lại (State lùi lại tối đa 1 giây)
    Gateway->>Redis: Nhận diện Redis vừa boot: Ghi nhận T_boot
    Note over Gateway: KÍCH HOẠT QUARANTINE TRONG 15 GIÂY (T_boot -> T_boot + 15s)

    Attacker->>Gateway: Phát lại gói tin seq=500 (Timestamp = T_boot - 500ms)
    Gateway->>Gateway: Kiểm tra: Timestamp < T_boot?
    Gateway-->>Attacker: 401 Unauthorized (RETRY_WITH_FRESH_TIMESTAMP)

    Client->>Gateway: Gửi request mới với Timestamp hiện tại (Timestamp = T_boot + 2s)
    Gateway->>Gateway: Kiểm tra: Timestamp >= T_boot? (Hợp lệ!)
    Gateway->>Redis: Commit CAS (Sequence mới)
    Gateway-->>Client: 200 OK
```

- **Quy tắc Kiểm Dịch:** Khi API Gateway phát hiện kết nối Redis mới được khởi tạo lại sau khi mất kết nối (hoặc qua lệnh `INFO server` lấy `uptime_in_seconds < 15`):
  1. Gateway lưu mốc $T_{\text{boot}} = \text{Date.now()}$.
  2. Trong suốt khoảng thời gian từ $T_{\text{boot}}$ đến $T_{\text{boot}} + 15.000\,\text{ms}$: Mọi request có `X-Timestamp` nhỏ hơn $T_{\text{boot}}$ sẽ bị từ chối với mã lỗi rõ ràng `RETRY_WITH_FRESH_TIMESTAMP` (status 401).
  3. Mọi request có `X-Timestamp` $\ge T_{\text{boot}}$ (được tạo mới sau khi Redis khởi động) được xử lý bình thường.
- **Hiệu quả:**
  - Triệt tiêu 100% nguy cơ replay gói tin cũ bị lùi sequence do mất 1 giây fsync.
  - Ứng dụng client chân chính chỉ cần tự động retry lại với timestamp tươi là lập tức thành công.

---

## 3. Kiến Trúc Mục Tiêu (Target Architecture)

```mermaid
flowchart TD
    Client["Client Devices (Android TEE / iOS Secure Enclave)"]

    subgraph IngressLayer["Tầng Cửa Ngõ (Edge & Reverse Proxy)"]
        NGINX["NGINX Ingress Load Balancer\n• Hash $http_x_device_id consistent\n• Rate-limit: /api/auth/challenge (20 r/s)\n• Keepalive Upstream Connections"]
    end

    subgraph ComputeLayer["Tầng Tính Toán (API Gateway Cluster)"]
        API1["API Replica 1\n(L1 Cache: 32k keys)"]
        API2["API Replica 2\n(L1 Cache: 32k keys)"]
        API3["API Replica 3\n(L1 Cache: 32k keys)"]
        API4["API Replica 4\n(L1 Cache: 32k keys)"]
    end

    subgraph StorageLayer["Tầng Lưu Trữ Hai Lớp (Tiered Storage)"]
        subgraph L2Cache["L2 Fast Replay Engine (In-Memory)"]
            Redis["Redis 8-alpine\n• appendfsync everysec\n• volatile-lru (maxmemory 2GB)\n• Replay Lua CAS (<1ms)"]
            RVol[("Named Volume: redis-data")]
        end

        subgraph L3Durable["L3 Durable Source of Truth (ACID)"]
            Postgres["PostgreSQL 16\n• Bảng devices (JSONB metadata)\n• Point-in-time Recovery (PITR)\n• Connection Pooling"]
            PGVol[("Named Volume: pg-data")]
        end
    end

    Client -->|HTTPS Requests| NGINX
    NGINX -->|Hash(Device-A) -> Replica 1| API1
    NGINX -->|Hash(Device-B) -> Replica 2| API2
    NGINX -->|Hash(Device-C) -> Replica 3| API3
    NGINX -->|Hash(Device-D) -> Replica 4| API4

    API1 & API2 & API3 & API4 -->|1. commitSequence (CAS Lua)| Redis
    API1 & API2 & API3 & API4 -->|2. createDeviceNX & Fallback getDevice| Postgres
    Redis --- RVol
    Postgres --- PGVol
```

### Nguyên lý hoạt động phối hợp giữa L1, L2 và L3:
1. **L1 Memory Cache (RAM Node.js - 32.768 entries):**
   - Nhờ NGINX định tuyến **Consistent Hashing theo `X-Device-Id`**, mọi request của cùng một điện thoại luôn về đúng 1 replica API cố định.
   - Tỷ lệ Cache Hit của L1 đạt **>95%**.
   - Hầu hết các request không cần đọc `HMGET` từ Redis, tiết kiệm 95% băng thông đọc của Redis.
2. **L2 Replay Engine (Redis In-Memory - `appendfsync everysec`):**
   - Đảm bảo tính tuần tự tuyệt đối của `lastSequence` và `signCount` qua Lua Script nguyên tử.
   - Tốc độ xử lý < 1ms, chịu tải >60.000 requests/giây.
3. **L3 Durable Store (PostgreSQL 16):**
   - Lưu trữ vĩnh viễn danh tính thiết bị phần cứng, chứng chỉ public key, token attestation, receipt Apple và metadata đăng ký.
   - Là nguồn dữ liệu chuẩn mực để nạp lại vào Redis bất cứ khi nào Redis khởi động lại trắng dữ liệu.

---

## 4. Thiết Kế Chi Tiết Các Thành Phần

### 4.1 Tầng Lưu Trữ Bền Vững PostgreSQL (`src/store/durable/`)

#### Schema Bảng Thiết Bị (`schema.sql`):
```sql
CREATE TABLE IF NOT EXISTS devices (
    device_id VARCHAR(64) PRIMARY KEY,
    platform VARCHAR(16) NOT NULL,
    public_key_pem TEXT NOT NULL,
    key_id VARCHAR(128),
    sign_count BIGINT,
    last_sequence VARCHAR(32) NOT NULL DEFAULT '0',
    registered_at BIGINT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    receipt TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_devices_platform ON devices(platform);
CREATE INDEX IF NOT EXISTS idx_devices_registered_at ON devices(registered_at);
```

#### Triển khai `PostgresDeviceStore` (`src/store/durable/postgres-store.ts`):
- Sử dụng module `pg` với `pg.Pool` hỗ trợ giới hạn kết nối (mặc định 20 kết nối/pool, `connectionTimeoutMillis: 2000`).
- Phương thức:
  - `saveDevice(device: DeviceRecord): Promise<boolean>`: Sử dụng câu lệnh `INSERT ... ON CONFLICT (device_id) DO NOTHING`. Trả về `true` nếu tạo mới thành công, `false` nếu đã tồn tại (tương đương ngữ nghĩa `NX`).
  - `getDevice(deviceId: string): Promise<DeviceRecord | null>`: Truy vấn theo khóa chính `device_id`.
  - `checkpointSequence(deviceId: string, sequence: string, signCount?: number): Promise<void>`: Cập nhật mốc sequence mới nhất vào DB bền vững.

#### Triển khai `HybridSecurityStore` (`src/store/hybrid.ts`):
Lớp bọc tích hợp cả PostgreSQL và Redis:
```typescript
export class HybridSecurityStore implements SecurityStore {
  constructor(
    private readonly redisStore: RedisSecurityStore,
    private readonly postgresStore: PostgresDeviceStore
  ) {}

  async createDeviceNX(device: DeviceRecord): Promise<boolean> {
    // 1. Ghi bền vững vào PostgreSQL trước (Source of Truth)
    const inserted = await this.postgresStore.saveDevice(device);
    if (!inserted) {
      return false; // Đã tồn tại thiết bị trong cơ sở dữ liệu
    }

    // 2. Nạp vào Redis để phục vụ hot-path replay
    try {
      await this.redisStore.createDeviceNX(device);
    } catch {
      // Nếu Redis tạm thời lỗi, bản ghi đã nằm an toàn trong Postgres
    }
    return true;
  }

  async getDevice(deviceId: string): Promise<DeviceRecord | null> {
    // 1. Kiểm tra L2 Cache (Redis)
    let device = await this.redisStore.getDevice(deviceId);
    if (device) return device;

    // 2. Cache Miss trên Redis (ví dụ Redis vừa restart): Truy vấn PostgreSQL
    device = await this.postgresStore.getDevice(deviceId);
    if (!device) return null;

    // 3. Nạp ngược lại vào Redis (Cache-aside) để các request sau đạt tốc độ tối đa
    await this.redisStore.createDeviceNX(device);
    return device;
  }

  async commitSequence(
    deviceId: string,
    expectedPublicKeyPem: string,
    newSequence: string,
    newSignCount?: number
  ): Promise<CommitResult> {
    // CAS nguyên tử siêu tốc trực tiếp trên Redis
    return this.redisStore.commitSequence(deviceId, expectedPublicKeyPem, newSequence, newSignCount);
  }
}
```

---

### 4.2 Tối Ưu Hóa Kết Nối & Chống Bão Reconnect Redis (`src/store/redis.ts`)

1. **Exponential Backoff Reconnect:**
   Thay vì cấu hình `reconnectStrategy: false` làm hủy kết nối và gây lỗi 503 hàng loạt, ta cấu hình reconnect có kiểm soát:
   ```typescript
   socket: {
     connectTimeout: this.connectTimeoutMs,
     reconnectStrategy: (retries) => {
       if (this.closed) return false;
       if (retries > 10) return new Error('REDIS_RETRY_EXHAUSTED');
       return Math.min(retries * 50, 1000); // 50ms, 100ms, ... tối đa 1s
     }
   }
   ```
2. **Khai báo Timestamp Quarantine:**
   Tích hợp cờ nhận diện Redis restart để thực thi cơ chế từ chối gói tin cũ trong 15 giây đầu như đã đặc tả ở Mục 2.3.

---

### 4.3 Thử Thách Ký HMAC Phi Trạng Thái (Stateless HMAC Challenges)

Nhằm xóa bỏ hoàn toàn việc botnet spam `/api/auth/challenge` gây nghẽn RAM Redis:
- Cấu trúc Challenge:
  $$\text{Challenge} = \text{Nonce}_{16\text{B}} \parallel \text{Timestamp}_{8\text{B}} \parallel \text{HMAC-SHA256}_{40\text{B}}(K_{\text{secret}}, \text{Nonce} \parallel \text{Timestamp} \parallel \text{Platform})$$
- Khi client gọi `/api/auth/challenge`: Server chỉ việc sinh chuỗi trên và trả về cho client mà **không cần ghi bất kỳ byte nào vào Redis**.
- Khi client gọi `/api/auth/register-device`:
  1. Server kiểm tra tính toàn vẹn của chữ ký HMAC và độ lệch thời gian $\le 60\,\text{giây}$.
  2. Để đảm bảo Single-Use (dùng 1 lần duy nhất): Server thực thi lệnh Redis `SET sec:consumed:<challenge> 1 EX 60 NX`. Nếu key đã tồn tại $\rightarrow$ Từ chối với lỗi `INVALID_CHALLENGE`.
- **Kết quả:** Giảm 99% số thao tác ghi vào Redis ở endpoint challenge, triệt tiêu hoàn toàn nguy cơ DDoS cạn kiệt RAM.

---

### 4.4 Định Tuyến Nhất Quán NGINX (`docker/nginx.conf`)

Cấu hình bộ cân bằng tải NGINX thực hiện Consistent Hashing theo `X-Device-Id`:
```nginx
worker_processes auto;
events { worker_connections 4096; }

http {
    limit_req_zone $binary_remote_addr zone=challenge_limit:10m rate=20r/s;

    upstream api_cluster {
        # Định tuyến nhất quán: Cùng X-Device-Id luôn vào cùng 1 API replica
        hash $http_x_device_id consistent;
        server api:3000 max_fails=3 fail_timeout=10s;
        keepalive 64;
    }

    server {
        listen 80;

        # Rate limit bảo vệ endpoint xin challenge
        location = /api/auth/challenge {
            limit_req zone=challenge_limit burst=30 nodelay;
            proxy_pass http://api_cluster;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }

        # Định tuyến tất cả API request
        location / {
            proxy_pass http://api_cluster;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_connect_timeout 2s;
            proxy_read_timeout 5s;
        }
    }
}
```

---

### 4.5 Cấu Hình Docker Compose Toàn Diện (`compose.yaml`)

```yaml
services:
  gateway:
    image: nginx:alpine
    ports:
      - "${API_PORT:-3000}:80"
    volumes:
      - ./docker/nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - api
    restart: unless-stopped

  api:
    image: node-secure-api:${IMAGE_TAG:-local}
    build:
      context: .
      target: runtime
    deploy:
      replicas: ${API_REPLICAS:-4}
    environment:
      HOST: 0.0.0.0
      PORT: "3000"
      NODE_ENV: production
      REDIS_URL: redis://redis:6379
      DATABASE_URL: postgres://postgres:securepass@postgres:5432/secure_api
      CACHE_MAX_ENTRIES: "32768"
    depends_on:
      redis:
        condition: service_healthy
      postgres:
        condition: service_healthy
    restart: unless-stopped

  redis:
    image: redis:8-alpine
    command: [
      "redis-server",
      "--appendonly", "yes",
      "--appendfsync", "everysec",
      "--auto-aof-rewrite-percentage", "100",
      "--auto-aof-rewrite-min-size", "64mb",
      "--maxmemory", "2gb",
      "--maxmemory-policy", "volatile-lru"
    ]
    volumes:
      - redis-data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 3s
      timeout: 2s
      retries: 5
    restart: unless-stopped

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: secure_api
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: securepass
    volumes:
      - pg-data:/var/lib/postgresql/data
      - ./src/store/durable/schema.sql:/docker-entrypoint-initdb.d/init.sql:ro
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 3s
      timeout: 2s
      retries: 5
    restart: unless-stopped

volumes:
  redis-data:
  pg-data:
```

---

## 5. Kế Hoạch Kiểm Thử & Đo Lường (Verification Plan)

### 5.1 Kiểm thử tự động phục hồi khi xoá sạch dữ liệu Redis (Redis Wipeout Test)
- **Tập lệnh:** `tsx scripts/verify-hybrid-wipe.ts`
- **Kịch bản thực thi:**
  1. Khởi động PostgreSQL và Redis.
  2. Đăng ký thành công 5 thiết bị Android và 5 thiết bị iOS.
  3. Gửi request nghiệp vụ để sequence tiến lên giá trị 10.
  4. Thực hiện lệnh `FLUSHALL` trên Redis (giả lập trường hợp Redis bị sập và mất trắng dữ liệu RAM/AOF).
  5. Gửi request tiếp theo với `sequence = 11`:
     - Gateway nhận diện Redis bị thiếu dữ liệu $\rightarrow$ Tự động đọc từ PostgreSQL.
     - Tự nạp lại vào Redis và commit thành công `sequence = 11`.
  6. Thử phát lại gói tin `sequence = 10` $\rightarrow$ Hệ thống lập tức từ chối với mã lỗi `REPLAY_DETECTED`.

### 5.2 Kiểm thử phòng vệ Timestamp Quarantine
- **Kịch bản thực thi:**
  1. Gửi request hợp lệ tại thời điểm $t_1$.
  2. Giả lập restart Redis container.
  3. Phát lại request có timestamp $t_1$ trong vòng 15 giây đầu sau restart.
  4. Xác nhận Gateway chặn đứng gói tin với lỗi `RETRY_WITH_FRESH_TIMESTAMP`.
  5. Gửi request mới với timestamp hiện tại $\rightarrow$ Thành công 200 OK.

### 5.3 Benchmark đo đạc hiệu năng Scale Ngang
- **Tập lệnh:** `API_REPLICAS=4 npm run benchmark:capacity`
- **Chỉ số nghiệm thu:**
  - Throughput xác nhận 60s đạt **$\ge 16.000$ RPS** với 4 replicas (tăng trưởng tối thiểu 75% so với tuyến tính lý thuyết).
  - Độ trễ HTTP p95 $< 10\,\text{ms}$, p99 $< 25\,\text{ms}$.
  - Tỷ lệ lỗi HTTP $< 0.1\%$, số lượng dropped iterations $= 0$.
  - Tỷ lệ L1 Cache Hit trên từng tiến trình API đạt **$> 95\%$**.

---

## 6. Lộ Trình Triển Khai 3 Giai Đoạn (Execution Roadmap)

```mermaid
flowchart LR
    P1["Giai đoạn 1: Quick Wins\n(appendfsync everysec,\nReconnect Backoff, L1 Cache 32k)"] --> P2["Giai đoạn 2: Bền Vững Hóa\n(Tích hợp PostgreSQL,\nHybrid Store, Wipeout Test)"]
    P2 --> P3["Giai đoạn 3: Scale Cực Đại\n(NGINX Consistent Hash,\nStateless Challenge, 4 Replicas)"]
```

1. **Giai đoạn 1 (Quick Wins - 1 ngày):**
   - Đổi tham số Redis sang `--appendfsync everysec` và `--maxmemory-policy volatile-lru`.
   - Cập nhật `reconnectStrategy` và giới hạn L1 cache lên 32.768 entries.
2. **Giai đoạn 2 (Bền Vững Hóa Trạng Thái - 2-3 ngày):**
   - Viết schema PostgreSQL và module `PostgresDeviceStore`.
   - Xây dựng `HybridSecurityStore` và kịch bản `verify-hybrid-wipe.ts`.
   - Chạy toàn bộ integration test suite đảm bảo không phá vỡ bất kỳ test hiện hữu nào.
3. **Giai đoạn 3 (Scale Cực Đại & Đo Lường - 2 ngày):**
   - Bổ sung cấu hình NGINX Ingress và multi-replica trong `compose.yaml`.
   - Triển khai Stateless HMAC Challenge.
   - Chạy benchmark k6 chứng minh năng lực phục vụ >16.000 RPS mà không nghẽn Redis.
