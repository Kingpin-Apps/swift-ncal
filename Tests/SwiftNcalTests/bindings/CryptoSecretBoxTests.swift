import Clibsodium
import XCTest

@testable import SwiftNcal

class CryptoSecretBoxTests: XCTestCase {
    let cryptoSecretBox = Sodium().cryptoSecretBox
    
    func testBox() throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes)
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes)

        let ciphertext = try cryptoSecretBox.box(message: message, nonce: nonce, key: key)

        XCTAssertEqual(ciphertext.count, message.count + cryptoSecretBox.boxZeroBytes, "Ciphertext length mismatch")
    }

    func testBoxWithInvalidKey() throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes - 1) // Invalid key length
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes)

        XCTAssertThrowsError(try cryptoSecretBox.box(message: message, nonce: nonce, key: key), "Expected error for invalid key length")
    }

    func testBoxWithInvalidNonce() throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes)
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes - 1) // Invalid nonce length

        XCTAssertThrowsError(try cryptoSecretBox.box(message: message, nonce: nonce, key: key), "Expected error for invalid nonce length")
    }
    
    func testOpen() throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes)
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes)

        let ciphertext = try cryptoSecretBox.box(message: message, nonce: nonce, key: key)
        let decryptedMessage = try cryptoSecretBox.open(ciphertext: ciphertext, nonce: nonce, key: key)

        XCTAssertEqual(message, decryptedMessage, "Decrypted message does not match the original message")
    }

    func testOpenWithInvalidKey() throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes)
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes)

        let ciphertext = try cryptoSecretBox.box(message: message, nonce: nonce, key: key)
        let invalidKey = Data(repeating: 0, count: cryptoSecretBox.keyBytes - 1) // Invalid key length

        XCTAssertThrowsError(try cryptoSecretBox.open(ciphertext: ciphertext, nonce: nonce, key: invalidKey), "Expected error for invalid key length")
    }

    func testOpenWithInvalidNonce() throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes)
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes)

        let ciphertext = try cryptoSecretBox.box(message: message, nonce: nonce, key: key)
        let invalidNonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes - 1) // Invalid nonce length

        XCTAssertThrowsError(try cryptoSecretBox.open(ciphertext: ciphertext, nonce: invalidNonce, key: key), "Expected error for invalid nonce length")
    }

    func testOpenWithTamperedCiphertext() throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes)
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes)

        var ciphertext = try cryptoSecretBox.box(message: message, nonce: nonce, key: key)
        ciphertext[0] ^= 0xFF // Tamper with the ciphertext

        XCTAssertThrowsError(try cryptoSecretBox.open(ciphertext: ciphertext, nonce: nonce, key: key), "Expected error for tampered ciphertext")
    }
    
    func testEasy() throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes)
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes)

        let ciphertext = try cryptoSecretBox.easy(message: message, nonce: nonce, key: key)

        XCTAssertEqual(ciphertext.count, cryptoSecretBox.macBytes + message.count, "Ciphertext length mismatch")
    }

    func testEasyWithInvalidKey() throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes - 1) // Invalid key length
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes)

        XCTAssertThrowsError(try cryptoSecretBox.easy(message: message, nonce: nonce, key: key), "Expected error for invalid key length")
    }

    func testEasyWithInvalidNonce() throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes)
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes - 1) // Invalid nonce length

        XCTAssertThrowsError(try cryptoSecretBox.easy(message: message, nonce: nonce, key: key), "Expected error for invalid nonce length")
    }

    func testEasyWithTamperedMessage() throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes)
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes)

        var ciphertext = try cryptoSecretBox.easy(message: message, nonce: nonce, key: key)
        ciphertext[0] ^= 0xFF // Tamper with the ciphertext

        XCTAssertThrowsError(try cryptoSecretBox.open(ciphertext: ciphertext, nonce: nonce, key: key), "Expected error for tampered ciphertext")
    }
    
    func testOpenEasy() throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes)
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes)

        let ciphertext = try cryptoSecretBox.easy(message: message, nonce: nonce, key: key)
        let decryptedMessage = try cryptoSecretBox.openEasy(ciphertext: ciphertext, nonce: nonce, key: key)

        XCTAssertEqual(message, decryptedMessage, "Decrypted message does not match the original message")
    }

    func testOpenEasyWithInvalidKey() throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes)
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes)

        let ciphertext = try cryptoSecretBox.easy(message: message, nonce: nonce, key: key)
        let invalidKey = Data(repeating: 0, count: cryptoSecretBox.keyBytes - 1) // Invalid key length

        XCTAssertThrowsError(try cryptoSecretBox.openEasy(ciphertext: ciphertext, nonce: nonce, key: invalidKey), "Expected error for invalid key length")
    }

    func testOpenEasyWithInvalidNonce() throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes)
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes)

        let ciphertext = try cryptoSecretBox.easy(message: message, nonce: nonce, key: key)
        let invalidNonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes - 1) // Invalid nonce length

        XCTAssertThrowsError(try cryptoSecretBox.openEasy(ciphertext: ciphertext, nonce: invalidNonce, key: key), "Expected error for invalid nonce length")
    }

    func testOpenEasyWithTamperedCiphertext() throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes)
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes)

        var ciphertext = try cryptoSecretBox.easy(message: message, nonce: nonce, key: key)
        ciphertext[0] ^= 0xFF // Tamper with the ciphertext

        XCTAssertThrowsError(try cryptoSecretBox.openEasy(ciphertext: ciphertext, nonce: nonce, key: key), "Expected error for tampered ciphertext")
    }
}
