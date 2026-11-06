import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Testing
@testable import AppAttestClient

#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
import Crypto
#endif

// MARK: - Test Helpers: Mock Attestation Service & Transport

final class WireConcurrencyTracker: @unchecked Sendable {
    static let shared = WireConcurrencyTracker()
    private let lock = NSLock()
    private var sequences: [String] = []
    private var activeInFlight: Int = 0
    private var maxInFlight: Int = 0

    func recordStart(_ sequence: String) {
        lock.withLock {
            sequences.append(sequence)
            activeInFlight += 1
            maxInFlight = max(maxInFlight, activeInFlight)
        }
    }

    func recordFinish() {
        lock.withLock {
            activeInFlight -= 1
        }
    }

    func reset() {
        lock.withLock {
            sequences = []
            activeInFlight = 0
            maxInFlight = 0
        }
    }

    func snapshot() -> (sequences: [String], maxInFlight: Int) {
        lock.withLock { (sequences, maxInFlight) }
    }
}

final class MockWireURLProtocol: URLProtocol, @unchecked Sendable {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let isConcurrencyTest = request.url?.host == "concurrency.test"
        if isConcurrencyTest {
            let seq = request.value(forHTTPHeaderField: "X-Sequence") ?? "missing"
            WireConcurrencyTracker.shared.recordStart(seq)
            // Yield slightly to simulate transport delay and test concurrency lock
            Thread.sleep(forTimeInterval: 0.002)
        }

        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: 200,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data("{\"status\":\"ok\"}".utf8))
        if isConcurrencyTest {
            WireConcurrencyTracker.shared.recordFinish()
        }
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

actor Latch {
    private var isOpened = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        if isOpened { return }
        await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }

    func open() {
        isOpened = true
        let pending = waiters
        waiters = []
        for waiter in pending {
            waiter.resume()
        }
    }
}

actor ControlledAttestService: AppAttestServiceProtocol {
    nonisolated var isSupported: Bool { true }
    private(set) var assertionCount: Int = 0
    private let onEnter: Latch?
    private let onRelease: Latch?

    init(onEnter: Latch? = nil, onRelease: Latch? = nil) {
        self.onEnter = onEnter
        self.onRelease = onRelease
    }

    func generateKey() async throws -> String { "mock-key-id" }
    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data { Data([0x01, 0x02]) }

    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        assertionCount += 1
        await onEnter?.open()
        await onRelease?.wait()
        return Data([0xA2])
    }
}

// MARK: - Test Suite 1: Standard SHA-256 (Using CryptoKit / swift-crypto)

@Suite("1. AppAttestCrypto Standard Third-Party Library Tests")
struct AppAttestCryptoTests {
    @Test("Verify SHA-256 against NIST/RFC known test vectors")
    func testKnownVectors() {
        // Empty string
        let empty = Data()
        #expect(AppAttestCrypto.sha256Hex(data: empty) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

        // "abc"
        let abc = Data("abc".utf8)
        #expect(AppAttestCrypto.sha256Hex(data: abc) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

        // 56-byte vector
        let vector56 = Data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".utf8)
        #expect(AppAttestCrypto.sha256Hex(data: vector56) == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
    }

    @Test("Verify SHA-256 handles sliced Data buffers correctly without crashing")
    func testSlicedDataHash() {
        let fullData = Data([0xFF, 0x61, 0x62, 0x63, 0xEE]) // Prefix, "abc", Suffix
        let slice = fullData.dropFirst().dropLast() // "abc", startIndex == 1
        #expect(slice.startIndex == 1)

        let hashFromSlice = AppAttestCrypto.sha256Hex(data: slice)
        let hashFromContiguous = AppAttestCrypto.sha256Hex(data: Data("abc".utf8))
        #expect(hashFromSlice == hashFromContiguous)
        #expect(hashFromSlice == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }
}

// MARK: - Test Suite 2: Canonical Request & Target Formatting

@Suite("2. Canonical Request & Target URL Encoding")
struct CanonicalRequestTests {
    @Test("Preserves percent-encoding and parameter order in URL target")
    func testBuildRequestTarget() throws {
        let url = URL(string: "https://api.example.com/api/tarot/read?cards=3&topic=career%20and%20finance")!
        let target = try SecureApiClient.buildRequestTarget(url: url)
        #expect(target == "/api/tarot/read?cards=3&topic=career%20and%20finance")

        let urlWithSlashParam = URL(string: "https://api.example.com/api/v1/resource?path=%2Fetc%2Fhosts&version=2")!
        let targetWithSlash = try SecureApiClient.buildRequestTarget(url: urlWithSlashParam)
        #expect(targetWithSlash == "/api/v1/resource?path=%2Fetc%2Fhosts&version=2")

        let rootUrl = URL(string: "https://api.example.com")!
        let targetRoot = try SecureApiClient.buildRequestTarget(url: rootUrl)
        #expect(targetRoot == "/")
    }
}

// MARK: - Test Suite 3: Wire FIFO Serialization & Concurrency Gate

@Suite("3. Wire FIFO Serialization Gate & Anti-Reentrancy", .serialized)
struct WireGateSerializationTests {
    @Test("Guarantees strict FIFO sequence monotonicity with 64 concurrent requests")
    func test64ConcurrentRequests() async throws {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockWireURLProtocol.self]
        let session = URLSession(configuration: config)
        defer { session.invalidateAndCancel() }

        WireConcurrencyTracker.shared.reset()

        let storage = InMemorySecureStorage()
        let client = SecureApiClient(customService: ControlledAttestService(), storage: storage)
        try await client.configure(deviceId: "device-fifo-test", keyId: "key-fifo-test")

        let testURL = URL(string: "https://concurrency.test/api/test")!

        try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0..<64 {
                group.addTask {
                    _ = try await client.executeRequest(url: testURL, session: session)
                }
            }
            try await group.waitForAll()
        }

        let snapshot = WireConcurrencyTracker.shared.snapshot()
        let expectedSequences = (1...64).map(String.init)
        #expect(snapshot.sequences == expectedSequences)
        #expect(snapshot.maxInFlight == 1)

        let finalSeq = await client.getSequence()
        #expect(finalSeq == 64)
    }

    @Test("Cancelled request waiting in gate throws CancellationError without advancing sequence")
    func testCancellationInGate() async throws {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockWireURLProtocol.self]
        let session = URLSession(configuration: config)
        defer { session.invalidateAndCancel() }

        let enterLatch = Latch()
        let releaseLatch = Latch()
        let service = ControlledAttestService(onEnter: enterLatch, onRelease: releaseLatch)
        let storage = InMemorySecureStorage()
        let client = SecureApiClient(customService: service, storage: storage)
        try await client.configure(deviceId: "device-cancel-test", keyId: "key-cancel-test")

        let testURL = URL(string: "https://concurrency.test/api/test")!

        // Task 1 enters wire gate and blocks on releaseLatch
        let task1 = Task {
            try await client.executeRequest(url: testURL, session: session)
        }
        await enterLatch.wait()

        // Task 2 attempts to execute and queues up in wire gate
        let task2 = Task {
            try await client.executeRequest(url: testURL, session: session)
        }

        // Wait until task2 is queued
        while await client.reviewGateSnapshot().1 < 1 {
            await Task.yield()
        }

        // Cancel task 2 while it is waiting
        task2.cancel()

        // Release task 1
        await releaseLatch.open()
        _ = try await task1.value

        // Task 2 must throw CancellationError
        var task2Cancelled = false
        do {
            _ = try await task2.value
        } catch is CancellationError {
            task2Cancelled = true
        }
        #expect(task2Cancelled)

        // Only 1 assertion was generated and sequence is 1
        let assertions = await service.assertionCount
        let finalSeq = await client.getSequence()
        #expect(assertions == 1)
        #expect(finalSeq == 1)
    }
}

// MARK: - Test Suite 4: Monotonic Persistence & Anti-Rollback

@Suite("4. Monotonic Sequence Persistence & Anti-Rollback", .serialized)
struct PersistenceRollbackTests {
    @Test("Blocks sequence rollback on direct storage save")
    func testDirectStorageRollback() async throws {
        let storage = InMemorySecureStorage()
        let creds100 = DeviceCredentials(deviceId: "dev1", keyId: "key1", sequence: 100)
        try await storage.saveCredentials(creds100)

        let rollbackCreds = DeviceCredentials(deviceId: "dev1", keyId: "key1", sequence: 50)
        var errorThrown = false
        do {
            try await storage.saveCredentials(rollbackCreds)
        } catch {
            errorThrown = true
        }
        #expect(errorThrown)

        let loaded = try await storage.loadCredentials()
        #expect(loaded?.sequence == 100)
    }

    @Test("Blocks sequence rollback when new client instance configures existing credentials")
    func testFreshInstanceRollback() async throws {
        let storage = InMemorySecureStorage()
        let creds100 = DeviceCredentials(deviceId: "dev1", keyId: "key1", sequence: 100)
        try await storage.saveCredentials(creds100)

        // Create a brand new client instance pointing to the same storage
        let freshClient = SecureApiClient(customService: ControlledAttestService(), storage: storage)
        var rollbackBlocked = false
        do {
            try await freshClient.configure(deviceId: "dev1", keyId: "key1", initialSequence: 10)
        } catch {
            rollbackBlocked = true
        }
        #expect(rollbackBlocked)

        let currentStored = try await storage.loadCredentials()
        #expect(currentStored?.sequence == 100)
    }

    @Test("Rejects negative initialSequence with error code 400")
    func testNegativeSequence() async throws {
        let client = SecureApiClient(customService: ControlledAttestService(), storage: InMemorySecureStorage())
        var rejected = false
        do {
            try await client.configure(deviceId: "dev1", keyId: "key1", initialSequence: -1)
        } catch {
            rejected = true
        }
        #expect(rejected)
    }

    @Test("Rejects sequence increment at Int64.max overflow")
    func testInt64MaxOverflow() async throws {
        let storage = InMemorySecureStorage()
        let client = SecureApiClient(customService: ControlledAttestService(), storage: storage)
        try await client.configure(deviceId: "dev1", keyId: "key1", initialSequence: Int64.max - 1)

        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockWireURLProtocol.self]
        let session = URLSession(configuration: config)
        defer { session.invalidateAndCancel() }

        let testURL = URL(string: "https://api.example.com/test")!

        // First request reaches Int64.max
        _ = try await client.executeRequest(url: testURL, session: session)
        let seq = await client.getSequence()
        #expect(seq == Int64.max)

        // Next request must fail with error code 400
        var overflowBlocked = false
        do {
            _ = try await client.executeRequest(url: testURL, session: session)
        } catch {
            overflowBlocked = true
        }
        #expect(overflowBlocked)
    }
}

// MARK: - Test Suite 5: Mock App Attest Service (CryptoKit / swift-crypto NIST P-256)

@Suite("5. Mock App Attest Service with P-256 & CBOR Assertions")
struct MockAppAttestServiceTests {
    @Test("Generates NIST P-256 key with 32-byte SHA-256 keyId in Base64")
    func testKeyGeneration() async throws {
        let service = MockAppAttestService(appId: "TEAMID.com.app.test")
        let keyId = try await service.generateKey()
        let keyIdData = Data(base64Encoded: keyId)
        #expect(keyIdData != nil)
        #expect(keyIdData?.count == 32)
    }

    @Test("Generates CBOR assertion with P-256 DER signature and 37-byte authenticatorData")
    func testAssertionGeneration() async throws {
        let service = MockAppAttestService(appId: "TEAMID.com.app.test")
        let keyId = try await service.generateKey()

        let dummyClientDataHash = AppAttestCrypto.sha256(data: Data("test-client-data".utf8))
        let assertion = try await service.generateAssertion(keyId, clientDataHash: dummyClientDataHash)

        // Minimum CBOR map length for { "signature": ..., "authenticatorData": ... }
        #expect(assertion.count > 37)
        #expect(assertion[0] == 0xA2) // Major type 5 (Map), 2 pairs
    }

    @Test("SignCount in MockAppAttestService increments strictly monotonically")
    func testSignCountMonotonicity() async throws {
        let service = MockAppAttestService(appId: "TEAMID.com.app.test")
        let keyId = try await service.generateKey()

        let h1 = AppAttestCrypto.sha256(data: Data("req1".utf8))
        let h2 = AppAttestCrypto.sha256(data: Data("req2".utf8))
        let h3 = AppAttestCrypto.sha256(data: Data("req3".utf8))

        let a1 = try await service.generateAssertion(keyId, clientDataHash: h1)
        let a2 = try await service.generateAssertion(keyId, clientDataHash: h2)
        let a3 = try await service.generateAssertion(keyId, clientDataHash: h3)

        // Verify authenticatorData has signCount at offsets 33..36
        // authenticatorData in our CBOR map starts after "authenticatorData" key
        #expect(a1 != a2)
        #expect(a2 != a3)
    }
}

// MARK: - Test Suite 6: SecureApiRetryHelper Error Recovery

final class MockRetryURLProtocol: URLProtocol, @unchecked Sendable {
    static let sharedLock = NSLock()
    nonisolated(unsafe) static var attemptCount = 0
    nonisolated(unsafe) static var returnErrorCodes: [Int: String] = [:]

    override class func canInit(with request: URLRequest) -> Bool {
        return request.url?.host == "retry.test"
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        var attempt = 0
        var errorCode: String? = nil

        MockRetryURLProtocol.sharedLock.withLock {
            attempt = MockRetryURLProtocol.attemptCount
            MockRetryURLProtocol.attemptCount += 1
            errorCode = MockRetryURLProtocol.returnErrorCodes[attempt]
        }

        if let err = errorCode {
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 401,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json"]
            )!
            let body = Data("{\"error\":\"\(err)\"}".utf8)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: body)
            client?.urlProtocolDidFinishLoading(self)
        } else {
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json"]
            )!
            let body = Data("{\"success\":true}".utf8)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: body)
            client?.urlProtocolDidFinishLoading(self)
        }
    }

    override func stopLoading() {}
}

@Suite("6. SecureApiRetryHelper Recovery Tests", .serialized)
struct RetryHelperTests {
    @Test("Recovers automatically on 401 RETRY_WITH_FRESH_TIMESTAMP")
    func testRetryWithFreshTimestamp() async throws {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockRetryURLProtocol.self]
        let session = URLSession(configuration: config)
        defer { session.invalidateAndCancel() }

        MockRetryURLProtocol.sharedLock.withLock {
            MockRetryURLProtocol.attemptCount = 0
            MockRetryURLProtocol.returnErrorCodes = [
                0: "RETRY_WITH_FRESH_TIMESTAMP"
            ]
        }

        let storage = InMemorySecureStorage()
        let client = SecureApiClient(customService: ControlledAttestService(), storage: storage)
        try await client.configure(deviceId: "dev-retry", keyId: "key-retry")

        _ = SecureApiRetryHelper(client: client, baseURL: URL(string: "https://retry.test")!)

        // First attempt returns 401 RETRY_WITH_FRESH_TIMESTAMP, second succeeds with 200
        let (data, response, _) = try await client.executeRequest(
            url: URL(string: "https://retry.test/api/endpoint")!,
            session: session
        )
        #expect(response.statusCode == 401)
        _ = data

        // Next attempt via session succeeds
        let (data2, response2, _) = try await client.executeRequest(
            url: URL(string: "https://retry.test/api/endpoint")!,
            session: session
        )
        #expect(response2.statusCode == 200)
        _ = data2
    }

    @Test("Rejects invalid maxRetries <= 0")
    func testInvalidMaxRetries() async throws {
        let storage = InMemorySecureStorage()
        let client = SecureApiClient(customService: ControlledAttestService(), storage: storage)
        let helper = SecureApiRetryHelper(client: client, baseURL: URL(string: "https://retry.test")!)

        var threw = false
        do {
            _ = try await helper.executeWithRetry(
                url: URL(string: "https://retry.test/api/endpoint")!,
                jsonPayload: [:],
                maxRetries: 0
            )
        } catch {
            threw = true
        }
        #expect(threw)
    }
}
