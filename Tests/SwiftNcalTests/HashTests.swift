import XCTest

@testable import SwiftNcal

class HashTests: XCTestCase {
    let _hash = Hash()
    let message = "The quick brown fox jumps over the lazy dog".data(using: .utf8)!
    let key = Data(repeating: 0, count: 16)  // 16 bytes key
    let salt = Data(repeating: 0, count: 16)  // 16 bytes salt
    let person = Data(repeating: 0, count: 16)  // 16 bytes personalization

    func testSha256() throws {
        let hashedMessage = try _hash.sha256(message: message)
        XCTAssertEqual(hashedMessage.count, 64, "SHA256 hash length mismatch")
    }

    func testSha512() throws {
        let hashedMessage = try _hash.sha512(message: message)
        XCTAssertEqual(hashedMessage.count, 128, "SHA512 hash length mismatch")
    }

    func testBlake2b() throws {
        let hashedMessage = try _hash.blake2b(
            data: message, digestSize: 32, key: key, salt: salt, person: person)
        XCTAssertEqual(hashedMessage.count, 64, "Blake2b hash length mismatch")
    }

    func testBlake2bWithDefaultParameters() throws {
        let hashedMessage = try _hash.blake2b(data: message)
        XCTAssertEqual(
            hashedMessage.count, 64, "Blake2b hash length mismatch with default parameters")
    }

    func testSiphash24() throws {
        let hashedMessage = try _hash.siphash24(
            message: message,
            key: Data(repeating: 0, count: _hash.siphashKeyBytes)
        )
        XCTAssertEqual(hashedMessage.count, _hash.siphashKeyBytes, "Siphash24 hash length mismatch")
    }

    func testSiphashx24() throws {
        let hashedMessage = try _hash.siphashx24(message: message, key: key)
        XCTAssertEqual(hashedMessage.count, 32, "Siphashx24 hash length mismatch")
    }
}
