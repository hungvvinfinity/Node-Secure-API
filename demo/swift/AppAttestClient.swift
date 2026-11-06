//
//  AppAttestClient.swift
//  Node-Secure-API Client for iOS (Apple App Attest & Simulator Mock)
//
//  Hướng dẫn: Copy toàn bộ file này vào Xcode project của bạn.
//  Không cần cài thêm bất kỳ 3rd-party library hay CocoaPods nào.
//  File này chạy được ngay lập tức trên cả Xcode Simulator lẫn iPhone thật.
//

import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

#if canImport(CryptoKit)
import CryptoKit
#endif

#if canImport(Crypto)
import Crypto
#endif

#if canImport(DeviceCheck)
import DeviceCheck
#endif

#if canImport(Security)
import Security
#endif

// MARK: - SHA-256 Engine (Sử dụng Thư viện Tiêu chuẩn CryptoKit hoặc swift-crypto)
public enum AppAttestCrypto {
    public static func sha256(data: Data) -> Data {
        #if canImport(CryptoKit)
        return Data(CryptoKit.SHA256.hash(data: data))
        #elseif canImport(Crypto)
        return Data(Crypto.SHA256.hash(data: data))
        #else
        #error("Yêu cầu thư viện CryptoKit (iOS/macOS) hoặc swift-crypto (Linux/Cross-platform). Không tự ý viết SHA-256.")
        #endif
    }

    public static func sha256Hex(data: Data) -> String {
        return sha256(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - 1. Giao diện trừu tượng hóa dịch vụ Attestation
public protocol AppAttestServiceProtocol: Sendable {
    var isSupported: Bool { get }
    func generateKey() async throws -> String
    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data
    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data
}

// MARK: - 2. Triển khai Thật cho iPhone thật (Hardware Secure Enclave)
#if canImport(DeviceCheck)
public final class RealAppAttestService: AppAttestServiceProtocol, @unchecked Sendable {
    private let service = DCAppAttestService.shared

    public init() {}

    public var isSupported: Bool {
        return service.isSupported
    }

    public func generateKey() async throws -> String {
        guard service.isSupported else {
            throw NSError(
                domain: "RealAppAttestService",
                code: 400,
                userInfo: [NSLocalizedDescriptionKey: "Apple App Attest không được thiết bị này hỗ trợ."]
            )
        }
        return try await service.generateKey()
    }

    public func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        guard service.isSupported else {
            throw NSError(
                domain: "RealAppAttestService",
                code: 400,
                userInfo: [NSLocalizedDescriptionKey: "Apple App Attest không được thiết bị này hỗ trợ."]
            )
        }
        return try await service.attestKey(keyId, clientDataHash: clientDataHash)
    }

    public func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        guard service.isSupported else {
            throw NSError(
                domain: "RealAppAttestService",
                code: 400,
                userInfo: [NSLocalizedDescriptionKey: "Apple App Attest không được thiết bị này hỗ trợ."]
            )
        }
        return try await service.generateAssertion(keyId, clientDataHash: clientDataHash)
    }
}
#endif

// MARK: - 3. Triển khai Giả lập cho Xcode Simulator & Unit Tests
/// Dùng trong môi trường Simulator hoặc Unit Tests.
/// Lưu ý: attestKey trả về mock data để kiểm thử logic nội bộ client;
/// server backend kiểm tra chuỗi chứng chỉ Apple PKI thật nên không thể đăng ký trực tiếp
/// mock này với backend nếu chưa cấu hình mock bypass / test harness ở môi trường server.
#if canImport(CryptoKit) || canImport(Crypto)
public actor MockAppAttestService: AppAttestServiceProtocol {
    nonisolated public var isSupported: Bool { true }
    private var privateKey: P256.Signing.PrivateKey?
    private var signCounter: UInt32 = 0
    private let appId: String

    public init(appId: String) {
        self.appId = appId
    }

    public func generateKey() async throws -> String {
        let key = P256.Signing.PrivateKey()
        self.privateKey = key
        self.signCounter = 0

        let rawPoint = key.publicKey.rawRepresentation // 64 bytes (X || Y)
        var uncompressed = Data([0x04])
        uncompressed.append(rawPoint)
        let hash = AppAttestCrypto.sha256(data: uncompressed)
        return hash.base64EncodedString()
    }

    public func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        return Data("MOCK_ATTESTATION_OBJECT".utf8)
    }

    public func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        guard let privateKey = self.privateKey else {
            throw NSError(
                domain: "MockAppAttest",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Chưa khởi tạo khóa. Hãy gọi generateKey() trước."]
            )
        }

        signCounter += 1
        let currentCounter = signCounter

        let rpIdHash = AppAttestCrypto.sha256(data: Data(appId.utf8))
        let flags = Data([0x40])

        var counterBE = currentCounter.bigEndian
        let counterData = Data(bytes: &counterBE, count: 4)

        var authData = Data()
        authData.append(rpIdHash)
        authData.append(flags)
        authData.append(counterData)

        var composite = Data()
        composite.append(authData)
        composite.append(clientDataHash)

        let signature = try privateKey.signature(for: composite)
        let derSig = signature.derRepresentation

        return encodeCborAssertion(signature: derSig, authenticatorData: authData)
    }

    private func encodeCborAssertion(signature: Data, authenticatorData: Data) -> Data {
        var cbor = Data([0xA2]) // Major type 5 (Map), 2 pairs

        // Key 1: "signature"
        cbor.append(contentsOf: [0x69] + "signature".utf8)
        cbor.append(contentsOf: [0x58, UInt8(signature.count)] + signature)

        // Key 2: "authenticatorData"
        cbor.append(contentsOf: [0x71] + "authenticatorData".utf8)
        cbor.append(contentsOf: [0x58, UInt8(authenticatorData.count)] + authenticatorData)

        return cbor
    }

    public func getPublicKeyPem() -> String? {
        return privateKey?.publicKey.pemRepresentation
    }
}
#endif

// MARK: - 4. Factory tự động phát hiện Môi trường
public enum AppAttestFactory {
    public static func create(appId: String) -> AppAttestServiceProtocol {
        #if targetEnvironment(simulator)
        #if canImport(CryptoKit) || canImport(Crypto)
        return MockAppAttestService(appId: appId)
        #else
        fatalError("CryptoKit or swift-crypto required for Simulator Mock")
        #endif
        #else
        #if canImport(DeviceCheck)
        // Trên thiết bị thật: LUÔN trả RealAppAttestService.
        // Tuyệt đối không fallback sang MockAppAttestService khi isSupported = false,
        // tuân thủ CLIENT_PROTOCOL.md mục 42: "không hạ policy attestation".
        return RealAppAttestService()
        #else
        #if canImport(CryptoKit) || canImport(Crypto)
        return MockAppAttestService(appId: appId)
        #else
        fatalError("DeviceCheck, CryptoKit or swift-crypto required")
        #endif
        #endif
        #endif
    }
}

// MARK: - 5. Giao thức & Triển khai Lưu trữ Bền vững (Keychain Persistence)
public struct DeviceCredentials: Sendable, Codable {
    public let deviceId: String
    public let keyId: String
    public var sequence: Int64
    public var clockOffsetMs: Int64

    public init(deviceId: String, keyId: String, sequence: Int64 = 0, clockOffsetMs: Int64 = 0) {
        self.deviceId = deviceId
        self.keyId = keyId
        self.sequence = sequence
        self.clockOffsetMs = clockOffsetMs
    }
}

public protocol SecureClientStorage: Sendable {
    func loadCredentials() async throws -> DeviceCredentials?
    func saveCredentials(_ credentials: DeviceCredentials) async throws
    func updateSequence(expectedDeviceId: String, newSequence: Int64) async throws
    func updateClockOffset(_ clockOffsetMs: Int64) async throws
    func clear() async throws
}

#if canImport(Security)
public actor KeychainSecureStorage: SecureClientStorage {
    private let service: String
    private let account: String

    public init(service: String = "com.node.secure.api", account: String = "device_credentials") {
        self.service = service
        self.account = account
    }

    public func loadCredentials() async throws -> DeviceCredentials? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let data = item as? Data else {
            throw NSError(
                domain: "KeychainStorage",
                code: Int(status),
                userInfo: [NSLocalizedDescriptionKey: "Lỗi truy vấn Keychain: \(status)"]
            )
        }
        let creds = try JSONDecoder().decode(DeviceCredentials.self, from: data)
        guard creds.sequence >= 0 else {
            throw NSError(
                domain: "KeychainStorage",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Dữ liệu sequence trong Keychain không hợp lệ (số âm)."]
            )
        }
        return creds
    }

    public func saveCredentials(_ credentials: DeviceCredentials) async throws {
        guard credentials.sequence >= 0 else {
            throw NSError(
                domain: "KeychainStorage",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Không thể lưu sequence âm vào Keychain."]
            )
        }
        if let existing = try await loadCredentials(),
           existing.deviceId == credentials.deviceId,
           existing.keyId == credentials.keyId {
            guard credentials.sequence >= existing.sequence else {
                throw NSError(
                    domain: "KeychainStorage",
                    code: -1,
                    userInfo: [NSLocalizedDescriptionKey: "Không thể giảm sequence (\(credentials.sequence) < \(existing.sequence)) cho cùng cặp khóa."]
                )
            }
        }
        let data = try JSONEncoder().encode(credentials)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]

        let attributesToUpdate: [String: Any] = [
            kSecValueData as String: data
        ]

        let updateStatus = SecItemUpdate(query as CFDictionary, attributesToUpdate as CFDictionary)
        if updateStatus == errSecItemNotFound {
            var newQuery = query
            newQuery[kSecValueData as String] = data
            newQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            let addStatus = SecItemAdd(newQuery as CFDictionary, nil)
            if addStatus != errSecSuccess {
                throw NSError(
                    domain: "KeychainStorage",
                    code: Int(addStatus),
                    userInfo: [NSLocalizedDescriptionKey: "Không thể lưu thông tin vào Keychain: \(addStatus)"]
                )
            }
        } else if updateStatus != errSecSuccess {
            throw NSError(
                domain: "KeychainStorage",
                code: Int(updateStatus),
                userInfo: [NSLocalizedDescriptionKey: "Không thể cập nhật Keychain: \(updateStatus)"]
            )
        }
    }

    public func updateSequence(expectedDeviceId: String, newSequence: Int64) async throws {
        guard var creds = try await loadCredentials() else {
            throw NSError(
                domain: "KeychainStorage",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Không tìm thấy thông tin thiết bị để cập nhật sequence"]
            )
        }
        guard creds.deviceId == expectedDeviceId else {
            throw NSError(
                domain: "KeychainStorage",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Device ID không khớp với bản ghi Keychain hiện tại."]
            )
        }
        guard newSequence > creds.sequence else {
            throw NSError(
                domain: "KeychainStorage",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Sequence mới (\(newSequence)) phải lớn hơn sequence hiện tại (\(creds.sequence)) để chống Replay."]
            )
        }
        creds.sequence = newSequence
        try await saveCredentials(creds)
    }

    public func updateClockOffset(_ clockOffsetMs: Int64) async throws {
        if var creds = try await loadCredentials() {
            creds.clockOffsetMs = clockOffsetMs
            try await saveCredentials(creds)
        }
    }

    public func clear() async throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw NSError(
                domain: "KeychainStorage",
                code: Int(status),
                userInfo: [NSLocalizedDescriptionKey: "Lỗi khi xóa Keychain: \(status)"]
            )
        }
    }
}
#endif

/// Bộ nhớ RAM giả lập cho Unit Tests & Môi trường không có Keychain (Actor-Isolated)
public actor InMemorySecureStorage: SecureClientStorage {
    private var credentials: DeviceCredentials?

    public init(initial: DeviceCredentials? = nil) {
        self.credentials = initial
    }

    public func loadCredentials() async throws -> DeviceCredentials? {
        return credentials
    }

    public func saveCredentials(_ credentials: DeviceCredentials) async throws {
        guard credentials.sequence >= 0 else {
            throw NSError(domain: "InMemoryStorage", code: -1, userInfo: [NSLocalizedDescriptionKey: "Sequence âm không hợp lệ"])
        }
        if let existing = self.credentials,
           existing.deviceId == credentials.deviceId,
           existing.keyId == credentials.keyId {
            guard credentials.sequence >= existing.sequence else {
                throw NSError(
                    domain: "InMemoryStorage",
                    code: -1,
                    userInfo: [NSLocalizedDescriptionKey: "Không thể giảm sequence (\(credentials.sequence) < \(existing.sequence)) cho cùng cặp khóa."]
                )
            }
        }
        self.credentials = credentials
    }

    public func updateSequence(expectedDeviceId: String, newSequence: Int64) async throws {
        guard var creds = credentials else {
            throw NSError(domain: "InMemoryStorage", code: -1, userInfo: [NSLocalizedDescriptionKey: "Chưa có credentials"])
        }
        guard creds.deviceId == expectedDeviceId else {
            throw NSError(domain: "InMemoryStorage", code: -1, userInfo: [NSLocalizedDescriptionKey: "Device ID không khớp"])
        }
        guard newSequence > creds.sequence else {
            throw NSError(domain: "InMemoryStorage", code: -1, userInfo: [NSLocalizedDescriptionKey: "Sequence không tăng đơn điệu"])
        }
        creds.sequence = newSequence
        self.credentials = creds
    }

    public func updateClockOffset(_ clockOffsetMs: Int64) async throws {
        self.credentials?.clockOffsetMs = clockOffsetMs
    }

    public func clear() async throws {
        self.credentials = nil
    }
}

// MARK: - 6. Client Gọi API Tự động Ký Bảo mật (Production Ready)
/// Sử dụng Actor-isolated FIFO continuation queue để khóa toàn bộ chu trình trên wire:
/// cấp sequence -> ghi disk -> canonical -> assertion -> gửi wire -> nhận response.
/// Hoàn toàn triệt tiêu rủi ro Actor Reentrancy, không dùng @Sendable closure cross-actor,
/// và bảo đảm 100% tuân thủ Swift 6 Concurrency.
public actor SecureApiClient {
    private let attestService: AppAttestServiceProtocol
    private let storage: SecureClientStorage

    // FIFO Wire Gate quản lý trực tiếp trong Actor context
    private var isWireBusy: Bool = false
    private var wireWaiters: [CheckedContinuation<Void, Never>] = []

    private var sequence: Int64 = 0
    private var clockOffsetMs: Int64 = 0
    private var deviceId: String?
    private var keyId: String?

    #if canImport(Security)
    public init(appId: String, storage: SecureClientStorage = KeychainSecureStorage()) {
        self.attestService = AppAttestFactory.create(appId: appId)
        self.storage = storage
    }
    #else
    public init(appId: String, storage: SecureClientStorage = InMemorySecureStorage()) {
        self.attestService = AppAttestFactory.create(appId: appId)
        self.storage = storage
    }
    #endif

    public init(customService: AppAttestServiceProtocol, storage: SecureClientStorage) {
        self.attestService = customService
        self.storage = storage
    }

    // MARK: - FIFO Wire Lock Management (Actor-Isolated)
    private func acquireWireGate() async {
        if !isWireBusy {
            isWireBusy = true
            return
        }
        await withCheckedContinuation { continuation in
            wireWaiters.append(continuation)
        }
    }

    private func releaseWireGate() {
        if !wireWaiters.isEmpty {
            let next = wireWaiters.removeFirst()
            next.resume()
        } else {
            isWireBusy = false
        }
    }

    // MARK: - Getters
    public func getDeviceId() -> String? { deviceId }
    public func getKeyId() -> String? { keyId }
    public func getSequence() -> Int64 { sequence }
    public func getClockOffsetMs() -> Int64 { clockOffsetMs }

    // MARK: - Configuration & Khôi phục trạng thái
    public func configure(
        deviceId: String,
        keyId: String,
        initialSequence: Int64 = 0,
        clockOffsetMs: Int64 = 0
    ) async throws {
        await acquireWireGate()
        defer { releaseWireGate() }

        guard initialSequence >= 0 else {
            throw NSError(
                domain: "SecureApiClient",
                code: 400,
                userInfo: [NSLocalizedDescriptionKey: "initialSequence phải là số nguyên không âm (>= 0)."]
            )
        }

        // Chống rollback sequence đối chiếu với bản ghi trong storage bền vững
        if let existingCreds = try await storage.loadCredentials(),
           existingCreds.deviceId == deviceId && existingCreds.keyId == keyId {
            guard initialSequence >= existingCreds.sequence else {
                throw NSError(
                    domain: "SecureApiClient",
                    code: 400,
                    userInfo: [NSLocalizedDescriptionKey: "Không thể giảm sequence (\(initialSequence) < \(existingCreds.sequence)) cho cùng một cặp khóa đã lưu."]
                )
            }
        }

        // Chống rollback sequence cho cùng một thiết bị và cặp khóa trong instance hiện tại
        if self.deviceId == deviceId && self.keyId == keyId {
            guard initialSequence >= self.sequence else {
                throw NSError(
                    domain: "SecureApiClient",
                    code: 400,
                    userInfo: [NSLocalizedDescriptionKey: "Không thể giảm sequence (\(initialSequence) < \(self.sequence)) cho cùng một cặp khóa."]
                )
            }
        }

        self.deviceId = deviceId
        self.keyId = keyId
        self.sequence = initialSequence
        self.clockOffsetMs = clockOffsetMs

        let creds = DeviceCredentials(
            deviceId: deviceId,
            keyId: keyId,
            sequence: initialSequence,
            clockOffsetMs: clockOffsetMs
        )
        try await storage.saveCredentials(creds)
    }

    /// Tự động nạp thông tin đã lưu từ Keychain hoặc bộ nhớ bền vững
    public func restoreFromStorage() async throws -> Bool {
        await acquireWireGate()
        defer { releaseWireGate() }

        guard let creds = try await storage.loadCredentials() else {
            return false
        }
        guard creds.sequence >= 0 else {
            throw NSError(
                domain: "SecureApiClient",
                code: 400,
                userInfo: [NSLocalizedDescriptionKey: "Bản ghi credentials có sequence âm không hợp lệ."]
            )
        }
        self.deviceId = creds.deviceId
        self.keyId = creds.keyId
        self.sequence = creds.sequence
        self.clockOffsetMs = creds.clockOffsetMs
        return true
    }

    // MARK: - Tiện ích Đường dẫn & Canonical Helpers
    private func endpointURL(baseURL: URL, path: String) -> URL {
        let cleanPath = path.hasPrefix("/") ? String(path.dropFirst()) : path
        var url = baseURL
        for segment in cleanPath.split(separator: "/") {
            url.appendPathComponent(String(segment))
        }
        return url
    }

    /// Trích xuất request target bảo toàn chính xác encoded path và query (không sort, không decode %2F)
    public static func buildRequestTarget(url: URL) throws -> String {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: true) else {
            throw NSError(
                domain: "SecureApiClient",
                code: 400,
                userInfo: [NSLocalizedDescriptionKey: "URL không hợp lệ: Không thể phân tích components bảo toàn percent-encoding."]
            )
        }
        let rawPath = components.percentEncodedPath
        let path = rawPath.isEmpty ? "/" : (rawPath.hasPrefix("/") ? rawPath : "/\(rawPath)")
        if let query = components.percentEncodedQuery {
            return "\(path)?\(query)"
        } else {
            return path
        }
    }

    public static func computeSha256Hex(data: Data) -> String {
        return AppAttestCrypto.sha256Hex(data: data)
    }

    // MARK: - Đồng bộ Độ lệch Thời gian Động (Dynamic Clock Offset Sync)
    public func syncClockOffset(baseURL: URL) async throws -> Int64 {
        let challengeURL = endpointURL(baseURL: baseURL, path: "api/auth/challenge")
        var req = URLRequest(url: challengeURL)
        req.httpMethod = "POST"
        req.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: ["platform": "ios"])

        let (data, response) = try await URLSession.shared.data(for: req)
        guard let httpRes = response as? HTTPURLResponse, httpRes.statusCode == 200 else {
            throw NSError(
                domain: "SecureApiClient",
                code: (response as? HTTPURLResponse)?.statusCode ?? -1,
                userInfo: [NSLocalizedDescriptionKey: "Đồng bộ clockOffset thất bại: \(String(data: data, encoding: .utf8) ?? "")"]
            )
        }

        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let serverTimeNum = (json["serverTime"] as? NSNumber)?.int64Value
                ?? (json["serverTime"] as? Int64)
                ?? (json["serverTime"] as? Int).map(Int64.init) else {
            throw NSError(
                domain: "SecureApiClient",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Phản hồi challenge thiếu trường serverTime hợp lệ."]
            )
        }

        let newOffset = serverTimeNum - Int64(Date().timeIntervalSince1970 * 1000)
        self.clockOffsetMs = newOffset
        try await storage.updateClockOffset(newOffset)
        return newOffset
    }

    // MARK: - Luồng Đăng ký Phần cứng Tự động (Full Registration Flow)
    public func register(baseURL: URL) async throws -> String {
        await acquireWireGate()
        defer { releaseWireGate() }

        guard self.attestService.isSupported else {
            throw NSError(
                domain: "SecureApiClient",
                code: 400,
                userInfo: [NSLocalizedDescriptionKey: "Apple App Attest không được thiết bị này hỗ trợ."]
            )
        }

        // Bước 1: Yêu cầu Challenge từ Server (Single-Use Guarantee)
        let challengeURL = self.endpointURL(baseURL: baseURL, path: "api/auth/challenge")
        var challengeReq = URLRequest(url: challengeURL)
        challengeReq.httpMethod = "POST"
        challengeReq.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        challengeReq.httpBody = try JSONSerialization.data(withJSONObject: ["platform": "ios"])

        let (chalData, chalRes) = try await URLSession.shared.data(for: challengeReq)
        guard let httpChal = chalRes as? HTTPURLResponse, httpChal.statusCode == 200 else {
            throw NSError(
                domain: "SecureApiClient",
                code: (chalRes as? HTTPURLResponse)?.statusCode ?? -1,
                userInfo: [NSLocalizedDescriptionKey: "Yêu cầu challenge thất bại: \(String(data: chalData, encoding: .utf8) ?? "")"]
            )
        }

        guard let chalJson = try JSONSerialization.jsonObject(with: chalData) as? [String: Any],
              let challengeStr = chalJson["challenge"] as? String,
              challengeStr.count == 64 else {
            throw NSError(domain: "SecureApiClient", code: -1, userInfo: [NSLocalizedDescriptionKey: "Phản hồi challenge không hợp lệ"])
        }

        if let sTime = (chalJson["serverTime"] as? NSNumber)?.int64Value
            ?? (chalJson["serverTime"] as? Int64)
            ?? (chalJson["serverTime"] as? Int).map(Int64.init) {
            self.clockOffsetMs = sTime - Int64(Date().timeIntervalSince1970 * 1000)
        }

        // Bước 2: Sinh khóa Secure Enclave & Tạo Attestation
        let generatedKeyId = try await self.attestService.generateKey()
        let challengeHash = AppAttestCrypto.sha256(data: Data(challengeStr.utf8))
        let attestationData = try await self.attestService.attestKey(generatedKeyId, clientDataHash: challengeHash)

        // Bước 3: Đăng ký thiết bị với Server
        let regURL = self.endpointURL(baseURL: baseURL, path: "api/auth/register-device")
        var regReq = URLRequest(url: regURL)
        regReq.httpMethod = "POST"
        regReq.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        regReq.httpBody = try JSONSerialization.data(withJSONObject: [
            "challenge": challengeStr,
            "keyId": generatedKeyId,
            "attestationObject": attestationData.base64EncodedString()
        ])

        let (regData, regRes) = try await URLSession.shared.data(for: regReq)
        guard let httpReg = regRes as? HTTPURLResponse, httpReg.statusCode == 200 else {
            throw NSError(
                domain: "SecureApiClient",
                code: (regRes as? HTTPURLResponse)?.statusCode ?? -1,
                userInfo: [NSLocalizedDescriptionKey: "Đăng ký thiết bị thất bại: \(String(data: regData, encoding: .utf8) ?? "")"]
            )
        }

        guard let regJson = try JSONSerialization.jsonObject(with: regData) as? [String: Any],
              let newDeviceId = regJson["deviceId"] as? String, !newDeviceId.isEmpty else {
            throw NSError(domain: "SecureApiClient", code: -1, userInfo: [NSLocalizedDescriptionKey: "Phản hồi đăng ký không chứa deviceId"])
        }

        // Lưu bền vững trước khi cập nhật state trong bộ nhớ
        let creds = DeviceCredentials(
            deviceId: newDeviceId,
            keyId: generatedKeyId,
            sequence: 0,
            clockOffsetMs: self.clockOffsetMs
        )
        try await self.storage.saveCredentials(creds)

        self.deviceId = newDeviceId
        self.keyId = generatedKeyId
        self.sequence = 0

        return newDeviceId
    }

    /// Đăng ký lại ngầm nếu deviceId chưa thay đổi (chống bão re-attestation khi nhiều request cùng gặp 401)
    public func registerIfNeeded(expectedOldDeviceId: String?, baseURL: URL) async throws -> String {
        await acquireWireGate()
        defer { releaseWireGate() }

        if let current = self.deviceId, current != expectedOldDeviceId {
            return current
        }
        // Gọi registration bên trong wire lock
        guard self.attestService.isSupported else {
            throw NSError(
                domain: "SecureApiClient",
                code: 400,
                userInfo: [NSLocalizedDescriptionKey: "Apple App Attest không được thiết bị này hỗ trợ."]
            )
        }

        let challengeURL = self.endpointURL(baseURL: baseURL, path: "api/auth/challenge")
        var challengeReq = URLRequest(url: challengeURL)
        challengeReq.httpMethod = "POST"
        challengeReq.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        challengeReq.httpBody = try JSONSerialization.data(withJSONObject: ["platform": "ios"])

        let (chalData, chalRes) = try await URLSession.shared.data(for: challengeReq)
        guard let httpChal = chalRes as? HTTPURLResponse, httpChal.statusCode == 200 else {
            throw NSError(
                domain: "SecureApiClient",
                code: (chalRes as? HTTPURLResponse)?.statusCode ?? -1,
                userInfo: [NSLocalizedDescriptionKey: "Yêu cầu challenge thất bại"]
            )
        }

        guard let chalJson = try JSONSerialization.jsonObject(with: chalData) as? [String: Any],
              let challengeStr = chalJson["challenge"] as? String,
              challengeStr.count == 64 else {
            throw NSError(domain: "SecureApiClient", code: -1, userInfo: [NSLocalizedDescriptionKey: "Phản hồi challenge không hợp lệ"])
        }

        if let sTime = (chalJson["serverTime"] as? NSNumber)?.int64Value
            ?? (chalJson["serverTime"] as? Int64)
            ?? (chalJson["serverTime"] as? Int).map(Int64.init) {
            self.clockOffsetMs = sTime - Int64(Date().timeIntervalSince1970 * 1000)
        }

        let generatedKeyId = try await self.attestService.generateKey()
        let challengeHash = AppAttestCrypto.sha256(data: Data(challengeStr.utf8))
        let attestationData = try await self.attestService.attestKey(generatedKeyId, clientDataHash: challengeHash)

        let regURL = self.endpointURL(baseURL: baseURL, path: "api/auth/register-device")
        var regReq = URLRequest(url: regURL)
        regReq.httpMethod = "POST"
        regReq.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        regReq.httpBody = try JSONSerialization.data(withJSONObject: [
            "challenge": challengeStr,
            "keyId": generatedKeyId,
            "attestationObject": attestationData.base64EncodedString()
        ])

        let (regData, regRes) = try await URLSession.shared.data(for: regReq)
        guard let httpReg = regRes as? HTTPURLResponse, httpReg.statusCode == 200 else {
            throw NSError(
                domain: "SecureApiClient",
                code: (regRes as? HTTPURLResponse)?.statusCode ?? -1,
                userInfo: [NSLocalizedDescriptionKey: "Đăng ký thiết bị thất bại"]
            )
        }

        guard let regJson = try JSONSerialization.jsonObject(with: regData) as? [String: Any],
              let newDeviceId = regJson["deviceId"] as? String, !newDeviceId.isEmpty else {
            throw NSError(domain: "SecureApiClient", code: -1, userInfo: [NSLocalizedDescriptionKey: "Thiếu deviceId"])
        }

        let creds = DeviceCredentials(
            deviceId: newDeviceId,
            keyId: generatedKeyId,
            sequence: 0,
            clockOffsetMs: self.clockOffsetMs
        )
        try await self.storage.saveCredentials(creds)

        self.deviceId = newDeviceId
        self.keyId = generatedKeyId
        self.sequence = 0
        return newDeviceId
    }

    // MARK: - Ký & Gửi Request Nghiệp vụ Tuần tự trên Wire (Thread-Safe Wire Execution)
    @discardableResult
    public func executeRequest(
        url: URL,
        method: String = "POST",
        body: Data = Data(),
        idempotencyKey: String? = nil,
        session: URLSession = .shared
    ) async throws -> (data: Data, response: HTTPURLResponse, usedDeviceId: String) {
        try Task.checkCancellation()
        await acquireWireGate()
        defer { releaseWireGate() }
        try Task.checkCancellation()

        guard let currentDeviceId = self.deviceId, let currentKeyId = self.keyId else {
            throw NSError(
                domain: "SecureApiClient",
                code: 401,
                userInfo: [NSLocalizedDescriptionKey: "Thiết bị chưa được đăng ký hoặc thiếu deviceId / keyId."]
            )
        }

        guard self.sequence < Int64.max else {
            throw NSError(
                domain: "SecureApiClient",
                code: 400,
                userInfo: [NSLocalizedDescriptionKey: "Sequence đạt ngưỡng tối đa Int64."]
            )
        }

        // 1. Tăng sequence và lưu bền vững xuống Keychain TRƯỚC KHI gửi ra wire
        let nextSeq = self.sequence + 1
        try await self.storage.updateSequence(expectedDeviceId: currentDeviceId, newSequence: nextSeq)
        self.sequence = nextSeq
        let seqString = String(nextSeq)

        // 2. Chuẩn hóa method và tính timestamp bù lệch đồng hồ
        let normalizedMethod = method.uppercased()
        let adjustedTimestampMs = Int64(Date().timeIntervalSince1970 * 1000) + self.clockOffsetMs
        let timestampString = String(adjustedTimestampMs)

        // 3. Tính băm body nguyên bản (raw bytes)
        let bodyHash = Self.computeSha256Hex(data: body)

        // 4. Trích xuất target bảo toàn percent-encoding
        let target = try Self.buildRequestTarget(url: url)

        // 5. Dựng chuỗi canonical: timestamp:sequence:METHOD:target:bodyHash
        let canonical = "\(timestampString):\(seqString):\(normalizedMethod):\(target):\(bodyHash)"
        let clientDataHash = AppAttestCrypto.sha256(data: Data(canonical.utf8))

        // 6. Sinh assertion từ Apple App Attest
        let assertionData = try await self.attestService.generateAssertion(currentKeyId, clientDataHash: clientDataHash)
        let assertionBase64 = assertionData.base64EncodedString()

        // 7. Gắn HTTP Headers theo đặc tả Node-Secure-API
        var request = URLRequest(url: url)
        request.httpMethod = normalizedMethod
        request.httpBody = body
        request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        request.setValue(currentDeviceId, forHTTPHeaderField: "X-Device-Id")
        request.setValue(timestampString, forHTTPHeaderField: "X-Timestamp")
        request.setValue(seqString, forHTTPHeaderField: "X-Sequence")
        request.setValue(assertionBase64, forHTTPHeaderField: "X-Assertion")

        if let idemp = idempotencyKey {
            request.setValue(idemp, forHTTPHeaderField: "Idempotency-Key")
        }

        // 8. Truyền nhận gói tin trong khi vẫn giữ serialization lock
        let (data, response) = try await session.data(for: request)
        guard let httpRes = response as? HTTPURLResponse else {
            throw NSError(
                domain: "SecureApiClient",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Phản hồi không phải là HTTPURLResponse."]
            )
        }
        return (data, httpRes, currentDeviceId)
    }

    // MARK: - Testing Inspection Helper
    func reviewGateSnapshot() -> (Bool, Int) {
        return (isWireBusy, wireWaiters.count)
    }

    /// Tạo URLRequest đã ký (dành cho nhu cầu inspection hoặc custom networking)
    /// - Warning: Không khuyến nghị dùng trực tiếp cho luồng gửi dữ liệu vì không thể đảm bảo
    ///   thứ tự gói tin trên wire; gọi đảo thứ tự sẽ làm hỏng anti-replay sequence protection.
    @available(*, deprecated, message: "Sử dụng executeRequest(...) để bảo đảm tuần tự hóa mức wire và tránh đảo thứ tự gói tin phá vỡ cơ chế anti-replay sequence.")
    public func createSignedRequest(
        url: URL,
        method: String,
        body: Data = Data(),
        idempotencyKey: String? = nil
    ) async throws -> URLRequest {
        try Task.checkCancellation()
        await acquireWireGate()
        defer { releaseWireGate() }
        try Task.checkCancellation()

        guard let currentDeviceId = self.deviceId, let currentKeyId = self.keyId else {
            throw NSError(
                domain: "SecureApiClient",
                code: 401,
                userInfo: [NSLocalizedDescriptionKey: "Thiết bị chưa được đăng ký hoặc thiếu deviceId / keyId."]
            )
        }

        guard self.sequence < Int64.max else {
            throw NSError(
                domain: "SecureApiClient",
                code: 400,
                userInfo: [NSLocalizedDescriptionKey: "Sequence đạt ngưỡng tối đa Int64."]
            )
        }

        let nextSeq = self.sequence + 1
        try await self.storage.updateSequence(expectedDeviceId: currentDeviceId, newSequence: nextSeq)
        self.sequence = nextSeq
        let seqString = String(nextSeq)

        let normalizedMethod = method.uppercased()
        let adjustedTimestampMs = Int64(Date().timeIntervalSince1970 * 1000) + self.clockOffsetMs
        let timestampString = String(adjustedTimestampMs)

        let bodyHash = Self.computeSha256Hex(data: body)
        let target = try Self.buildRequestTarget(url: url)
        let canonical = "\(timestampString):\(seqString):\(normalizedMethod):\(target):\(bodyHash)"
        let clientDataHash = AppAttestCrypto.sha256(data: Data(canonical.utf8))

        let assertionData = try await self.attestService.generateAssertion(currentKeyId, clientDataHash: clientDataHash)
        let assertionBase64 = assertionData.base64EncodedString()

        var request = URLRequest(url: url)
        request.httpMethod = normalizedMethod
        request.httpBody = body
        request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        request.setValue(currentDeviceId, forHTTPHeaderField: "X-Device-Id")
        request.setValue(timestampString, forHTTPHeaderField: "X-Timestamp")
        request.setValue(seqString, forHTTPHeaderField: "X-Sequence")
        request.setValue(assertionBase64, forHTTPHeaderField: "X-Assertion")

        if let idemp = idempotencyKey {
            request.setValue(idemp, forHTTPHeaderField: "Idempotency-Key")
        }

        return request
    }

    /// Reset vòng đời thiết bị (chỉ dùng khi huỷ đăng ký hoặc tạo định danh mới hoàn toàn)
    public func resetDeviceLifecycle() async throws {
        await acquireWireGate()
        defer { releaseWireGate() }

        self.deviceId = nil
        self.keyId = nil
        self.sequence = 0
        self.clockOffsetMs = 0
        try await storage.clear()
    }
}

// MARK: - 7. Lớp Phục hồi & Thử lại Tự động (Retry & Error Recovery Helper)
public final class SecureApiRetryHelper: Sendable {
    private let client: SecureApiClient
    private let baseURL: URL

    public init(client: SecureApiClient, baseURL: URL) {
        self.client = client
        self.baseURL = baseURL
    }

    public func executeWithRetry(
        url: URL,
        method: String = "POST",
        jsonPayload: [String: Any],
        idempotencyKey: String = UUID().uuidString,
        maxRetries: Int = 3
    ) async throws -> (Data, HTTPURLResponse) {
        guard maxRetries > 0 else {
            throw NSError(
                domain: "SecureApiRetryHelper",
                code: 400,
                userInfo: [NSLocalizedDescriptionKey: "maxRetries phải lớn hơn 0."]
            )
        }

        var boundPayload = jsonPayload
        boundPayload["idempotencyKey"] = idempotencyKey
        let serializedBody = try JSONSerialization.data(withJSONObject: boundPayload)

        for attempt in 0..<maxRetries {
            do {
                let (data, response, usedDeviceId) = try await client.executeRequest(
                    url: url,
                    method: method,
                    body: serializedBody,
                    idempotencyKey: idempotencyKey
                )

                if (200...299).contains(httpStatusCode: response.statusCode) {
                    return (data, response)
                }

                if response.statusCode >= 500 || response.statusCode == 429 {
                    if attempt == maxRetries - 1 {
                        return (data, response)
                    }
                    try await Task.sleep(nanoseconds: UInt64(attempt + 1) * 1_000_000_000)
                    continue
                }

                let errorCode = Self.extractErrorCode(from: data)

                if response.statusCode == 401 && errorCode == "EXPIRED_TIMESTAMP" && attempt < maxRetries - 1 {
                    _ = try await client.syncClockOffset(baseURL: baseURL)
                    continue
                }

                if response.statusCode == 401 && errorCode == "RETRY_WITH_FRESH_TIMESTAMP" && attempt < maxRetries - 1 {
                    continue
                }

                if response.statusCode == 401 && errorCode == "DEVICE_NOT_REGISTERED" && attempt < maxRetries - 1 {
                    _ = try await client.registerIfNeeded(expectedOldDeviceId: usedDeviceId, baseURL: baseURL)
                    continue
                }

                return (data, response)

            } catch is CancellationError {
                throw CancellationError()
            } catch {
                if attempt == maxRetries - 1 {
                    throw error
                }
                try await Task.sleep(nanoseconds: UInt64(attempt + 1) * 1_000_000_000)
            }
        }

        throw NSError(
            domain: "SecureApiRetryHelper",
            code: -1,
            userInfo: [NSLocalizedDescriptionKey: "Đã vượt quá số lần thử lại (\(maxRetries))."]
        )
    }

    private static func extractErrorCode(from data: Data) -> String? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        return json["error"] as? String
    }
}

private extension ClosedRange where Bound == Int {
    func contains(httpStatusCode code: Int) -> Bool {
        return contains(code)
    }
}
