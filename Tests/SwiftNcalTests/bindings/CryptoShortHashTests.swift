import Clibsodium
import XCTest

@testable import SwiftNcal

class CryptoShortHashTests: XCTestCase {
    let sodium = Sodium()

    func testSiphash24() throws {
        let cryptoShortHash = sodium.cryptoShortHash
        
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoShortHash.keyBytes)

        let hash = try cryptoShortHash.siphash24(data: message, key: key)

        XCTAssertEqual(hash.count, cryptoShortHash.bytes, "Hash length mismatch")
    }

    func testSiphash24WithInvalidKey() throws {
        let cryptoShortHash = sodium.cryptoShortHash
        
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoShortHash.keyBytes - 1) // Invalid key length

        XCTAssertThrowsError(try cryptoShortHash.siphash24(data: message, key: key), "Expected error for invalid key length")
    }

    func testSiphashx24() throws {
        let cryptoShortHash = sodium.cryptoShortHash
        
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoShortHash.xKeyBytes)

        let hash = try cryptoShortHash.siphashx24(data: message, key: key)

        XCTAssertEqual(hash.count, cryptoShortHash.xKeyBytes, "Hash length mismatch")
    }

    func testSiphashx24WithInvalidKey() throws {
        let cryptoShortHash = sodium.cryptoShortHash
        
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoShortHash.xKeyBytes - 1) // Invalid key length

        XCTAssertThrowsError(try cryptoShortHash.siphashx24(data: message, key: key), "Expected error for invalid key length")
    }
}
