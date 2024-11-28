import Clibsodium
import XCTest

@testable import SwiftNcal

final class CryptoHashTests: XCTestCase {
    let cryptoHash = Sodium().cryptoHash

    func testHash() throws {
        let message = "Hello, World!".data(using: .utf8)!
        let digest = try cryptoHash.hash(message: message)

        XCTAssertEqual(digest.count, cryptoHash.bytes, "Hash length mismatch")
    }

    func testSha256() throws {
        let message = "Hello, World!".data(using: .utf8)!
        let digest = try cryptoHash.sha256(message: message)

        XCTAssertEqual(digest.count, cryptoHash.sha256Bytes, "SHA-256 hash length mismatch")
    }

    func testSha512() throws {
        let message = "Hello, World!".data(using: .utf8)!
        let digest = try cryptoHash.sha512(message: message)

        XCTAssertEqual(digest.count, cryptoHash.sha512Bytes, "SHA-512 hash length mismatch")
    }
}
