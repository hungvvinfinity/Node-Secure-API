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
        return try await service.generateKey()
    }

    public func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        return try await service.attestKey(keyId, clientDataHash: clientDataHash)
    }

    public func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        return try await service.generateAssertion(keyId, clientDataHash: clientDataHash)
    }
}
#endif

// MARK: - 3. Triển khai Giả lập cho Xcode Simulator & Unit Tests (Swift Concurrency Actor)
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

        // Apple DCAppAttestService.generateKey trả về chuỗi Base64 đại diện cho 32-byte SHA-256
        // của uncompressed EC point (0x04 || X || Y, 65 bytes ANSI X9.63).
        let rawPoint = key.publicKey.rawRepresentation // 64 bytes (X || Y)
        var uncompressed = Data([0x04])
        uncompressed.append(rawPoint)
        let hash = SHA256.hash(data: uncompressed)
        return Data(hash).base64EncodedString()
    }

    public func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        // Trong môi trường dev giả lập, trả về chuỗi attestationObject mẫu
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

        // A. rpIdHash: SHA-256(appId) = 32 bytes
        let rpIdHash = Data(SHA256.hash(data: Data(appId.utf8)))

        // B. flags: 0x40 (cờ AT chuẩn của iOS) = 1 byte
        let flags = Data([0x40])

        // C. signCount: 4 bytes UInt32 Big-Endian
        var counterBE = currentCounter.bigEndian
        let counterData = Data(bytes: &counterBE, count: 4)

        // D. authenticatorData = 32 + 1 + 4 = 37 bytes
        var authData = Data()
        authData.append(rpIdHash)
        authData.append(flags)
        authData.append(counterData)

        // E. Composite = concat(authenticatorData, clientDataHash)
        var composite = Data()
        composite.append(authData)
        composite.append(clientDataHash)

        // F. Ký chữ ký số ECDSA P-256 DER ASN.1
        let signature = try privateKey.signature(for: composite)
        let derSig = signature.derRepresentation

        // G. Đóng gói CBOR Map 2 phần tử: { "signature": ..., "authenticatorData": ... }
        return encodeCborAssertion(signature: derSig, authenticatorData: authData)
    }

    /// Đóng gói CBOR Map 2 phần tử tối giản theo chuẩn RFC 8949
    private func encodeCborAssertion(signature: Data, authenticatorData: Data) -> Data {
        var cbor = Data([0xA2]) // Major type 5 (Map), 2 pairs

        // Key 1: "signature" (Major 3, length 9 -> 0x69)
        cbor.append(contentsOf: [0x69] + "signature".utf8)
        // Value 1: byte string (Major 2, 1-byte length prefix 0x58)
        cbor.append(contentsOf: [0x58, UInt8(signature.count)] + signature)

        // Key 2: "authenticatorData" (Major 3, length 17 -> 0x71)
        cbor.append(contentsOf: [0x71] + "authenticatorData".utf8)
        // Value 2: byte string (Major 2, 1-byte length prefix 0x58)
        cbor.append(contentsOf: [0x58, UInt8(authenticatorData.count)] + authenticatorData)

        return cbor
    }

    /// Lấy Public Key dạng PEM (dùng khi đăng ký thiết bị ở môi trường Mock/Dev)
    public func getPublicKeyPem() -> String? {
        return privateKey?.publicKey.pemRepresentation
    }
}

// MARK: - 4. Factory tự động phát hiện Môi trường
public enum AppAttestFactory {
    public static func create(appId: String) -> AppAttestServiceProtocol {
        #if targetEnvironment(simulator)
        return MockAppAttestService(appId: appId)
        #else
        #if canImport(DeviceCheck)
        if DCAppAttestService.shared.isSupported {
            return RealAppAttestService()
        }
        #endif
        return MockAppAttestService(appId: appId)
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
    func updateSequence(_ sequence: Int64) async throws
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
        return try JSONDecoder().decode(DeviceCredentials.self, from: data)
    }

    public func saveCredentials(_ credentials: DeviceCredentials) async throws {
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

    public func updateSequence(_ sequence: Int64) async throws {
        guard var creds = try await loadCredentials() else {
            throw NSError(
                domain: "KeychainStorage",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Không tìm thấy thông tin thiết bị để cập nhật sequence"]
            )
        }
        creds.sequence = sequence
        try await saveCredentials(creds)
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
        self.credentials = credentials
    }

    public func updateSequence(_ sequence: Int64) async throws {
        self.credentials?.sequence = sequence
    }

    public func clear() async throws {
        self.credentials = nil
    }
}

// MARK: - 6. Client Gọi API Tự động Ký Bảo mật (Production Ready)
public actor SecureApiClient {
    private let attestService: AppAttestServiceProtocol
    private let storage: SecureClientStorage?
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
    public init(appId: String, storage: SecureClientStorage? = nil) {
        self.attestService = AppAttestFactory.create(appId: appId)
        self.storage = storage
    }
    #endif

    public init(customService: AppAttestServiceProtocol, storage: SecureClientStorage? = nil) {
        self.attestService = customService
        self.storage = storage
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
        self.deviceId = deviceId
        self.keyId = keyId
        self.sequence = initialSequence
        self.clockOffsetMs = clockOffsetMs

        if let storage = self.storage {
            let creds = DeviceCredentials(
                deviceId: deviceId,
                keyId: keyId,
                sequence: initialSequence,
                clockOffsetMs: clockOffsetMs
            )
            try await storage.saveCredentials(creds)
        }
    }

    /// Tự động nạp thông tin đã lưu từ Keychain hoặc bộ nhớ bền vững
    public func restoreFromStorage() async throws -> Bool {
        guard let storage = self.storage, let creds = try await storage.loadCredentials() else {
            return false
        }
        self.deviceId = creds.deviceId
        self.keyId = creds.keyId
        self.sequence = creds.sequence
        self.clockOffsetMs = creds.clockOffsetMs
        return true
    }

    // MARK: - 7. Luồng Đăng ký Phần cứng Tự động (Full Registration Flow)
    private func endpointURL(baseURL: URL, path: String) -> URL {
        let cleanPath = path.hasPrefix("/") ? String(path.dropFirst()) : path
        var url = baseURL
        for segment in cleanPath.split(separator: "/") {
            url.appendPathComponent(String(segment))
        }
        return url
    }

    public func register(baseURL: URL) async throws -> String {
        guard attestService.isSupported else {
            throw NSError(
                domain: "SecureApiClient",
                code: 400,
                userInfo: [NSLocalizedDescriptionKey: "Apple App Attest không được thiết bị này hỗ trợ."]
            )
        }

        // Bước 1: Yêu cầu Challenge từ Server
        let challengeURL = endpointURL(baseURL: baseURL, path: "api/auth/challenge")
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
              let challengeStr = chalJson["challenge"] as? String else {
            throw NSError(domain: "SecureApiClient", code: -1, userInfo: [NSLocalizedDescriptionKey: "Phản hồi challenge không hợp lệ"])
        }

        if let sTime = (chalJson["serverTime"] as? NSNumber)?.int64Value ?? (chalJson["serverTime"] as? Int64) ?? (chalJson["serverTime"] as? Int).map(Int64.init) {
            self.clockOffsetMs = sTime - Int64(Date().timeIntervalSince1970 * 1000)
        }

        // Bước 2: Sinh khóa Secure Enclave & Tạo Attestation
        let generatedKeyId = try await attestService.generateKey()
        let challengeHash = Data(SHA256.hash(data: Data(challengeStr.utf8)))
        let attestationData = try await attestService.attestKey(generatedKeyId, clientDataHash: challengeHash)

        // Bước 3: Đăng ký thiết bị với Server
        // Lưu ý quan trọng: generatedKeyId do Apple sinh ra đã là Base64 của 32 bytes SHA-256 leaf key,
        // sử dụng trực tiếp chuỗi này, KHÔNG được re-encode Base64.
        let regURL = endpointURL(baseURL: baseURL, path: "api/auth/register-device")
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
              let newDeviceId = regJson["deviceId"] as? String else {
            throw NSError(domain: "SecureApiClient", code: -1, userInfo: [NSLocalizedDescriptionKey: "Phản hồi đăng ký không chứa deviceId"])
        }

        self.deviceId = newDeviceId
        self.keyId = generatedKeyId
        self.sequence = 0

        if let storage = self.storage {
            let creds = DeviceCredentials(
                deviceId: newDeviceId,
                keyId: generatedKeyId,
                sequence: 0,
                clockOffsetMs: self.clockOffsetMs
            )
            try await storage.saveCredentials(creds)
        }

        return newDeviceId
    }

    // MARK: - 8. Ký và Tạo URLRequest Hoàn chỉnh (Production Ready)
    public func createSignedRequest(
        url: URL,
        method: String,
        body: Data = Data(),
        idempotencyKey: String? = nil
    ) async throws -> URLRequest {
        guard let deviceId = self.deviceId, let keyId = self.keyId else {
            throw NSError(
                domain: "SecureApiClient",
                code: 401,
                userInfo: [NSLocalizedDescriptionKey: "Thiết bị chưa được đăng ký hoặc cấu hình deviceId / keyId."]
            )
        }

        guard sequence < Int64.max else {
            throw NSError(domain: "SecureApiClient", code: 400, userInfo: [NSLocalizedDescriptionKey: "Sequence đạt ngưỡng tối đa Int64."])
        }

        // Tăng và snapshot sequence trước điểm dừng await để chống race condition giữa các request đồng thời
        sequence += 1
        let currentSeq = sequence
        let seqString = String(currentSeq)

        if let storage = self.storage {
            try await storage.updateSequence(currentSeq)
        }

        // Chuẩn hóa method thành chữ in hoa
        let normalizedMethod = method.uppercased()

        // Tính timestamp đã được bù lệch đồng hồ (Clock Offset Compensation)
        let adjustedTimestampMs = Int64(Date().timeIntervalSince1970 * 1000) + clockOffsetMs
        let timestamp = String(adjustedTimestampMs)

        // 1. Băm body gốc: SHA256(rawBytes) dạng lowercase hex
        let bodyHash = SHA256.hash(data: body).compactMap { String(format: "%02x", $0) }.joined()

        // 2. Request Target: Giữ nguyên vẹn percent-encoded path + query (KHÔNG sort, KHÔNG decode)
        let target: String
        if let components = URLComponents(url: url, resolvingAgainstBaseURL: true) {
            let rawPath = components.percentEncodedPath
            let path = rawPath.isEmpty ? "/" : (rawPath.hasPrefix("/") ? rawPath : "/\(rawPath)")
            if let query = components.percentEncodedQuery {
                target = "\(path)?\(query)"
            } else {
                target = path
            }
        } else {
            let rawPath = url.path
            let fallbackPath = rawPath.isEmpty ? "/" : (rawPath.hasPrefix("/") ? rawPath : "/\(rawPath)")
            if let query = url.query {
                target = "\(fallbackPath)?\(query)"
            } else {
                target = fallbackPath
            }
        }

        // 3. Chuỗi Canonical: timestamp:sequence:METHOD:target:bodyHash
        let canonical = "\(timestamp):\(seqString):\(normalizedMethod):\(target):\(bodyHash)"
        let clientDataHash = Data(SHA256.hash(data: Data(canonical.utf8)))

        // 4. Sinh Assertion (thật từ Secure Enclave hoặc mock từ P256)
        let assertionData = try await attestService.generateAssertion(keyId, clientDataHash: clientDataHash)
        let assertionBase64 = assertionData.base64EncodedString()

        // 5. Gắn HTTP Headers theo chuẩn Node-Secure-API
        var request = URLRequest(url: url)
        request.httpMethod = normalizedMethod
        request.httpBody = body
        request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        request.setValue(deviceId, forHTTPHeaderField: "X-Device-Id")
        request.setValue(timestamp, forHTTPHeaderField: "X-Timestamp")
        request.setValue(seqString, forHTTPHeaderField: "X-Sequence")
        request.setValue(assertionBase64, forHTTPHeaderField: "X-Assertion")

        if let idemp = idempotencyKey {
            request.setValue(idemp, forHTTPHeaderField: "Idempotency-Key")
        }

        return request
    }

    /// Reset sequence về 0 (chỉ dùng khi reset toàn bộ vòng đời thiết bị)
    public func resetSequence(to newSeq: Int64 = 0) async {
        self.sequence = newSeq
        try? await storage?.updateSequence(newSeq)
    }
}
