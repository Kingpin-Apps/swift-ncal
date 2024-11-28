import Clibsodium
import XCTest

@testable import SwiftNcal

final class CryptoAEADTests: XCTestCase {
    let cryptoAead = Sodium().cryptoAead

    func testCryptoAeadChacha20poly1305Ietf() throws {
        let key = Data(repeating: 0x01, count: cryptoAead.chacha20poly1305IetfKeyBytes)
        let nonce = Data(repeating: 0x02, count: cryptoAead.chacha20poly1305IetfNpubBytes)
        let message = "Hello, secure world!".data(using: .utf8)!
        let aad = "Additional Data".data(using: .utf8)

        // Encrypt
        let ciphertext = try cryptoAead.chacha20poly1305IetfEncrypt(
            message: message, aad: aad, nonce: nonce, key: key)
        XCTAssertFalse(ciphertext.isEmpty, "Ciphertext should not be empty.")

        // Decrypt
        let decryptedMessage = try cryptoAead.chacha20poly1305IetfDecrypt(
            ciphertext: ciphertext, aad: aad, nonce: nonce, key: key)
        XCTAssertEqual(decryptedMessage, message, "Decrypted message should match the original.")
    }

    func testCryptoAeadChacha20poly1305() throws {
        let key = Data(repeating: 0x01, count: cryptoAead.chacha20poly1305KeyBytes)
        let nonce = Data(repeating: 0x02, count: cryptoAead.chacha20poly1305NpubBytes)
        let message = "Hello, secure world!".data(using: .utf8)!
        let aad = "Additional Data".data(using: .utf8)

        // Encrypt
        let ciphertext = try cryptoAead.chacha20poly1305Encrypt(
            message: message, aad: aad, nonce: nonce, key: key)
        XCTAssertFalse(ciphertext.isEmpty, "Ciphertext should not be empty.")

        // Decrypt
        let decryptedMessage = try cryptoAead.chacha20poly1305Decrypt(
            ciphertext: ciphertext, aad: aad, nonce: nonce, key: key)
        XCTAssertEqual(decryptedMessage, message, "Decrypted message should match the original.")
    }

    func testCryptoAeadXchacha20poly1305Ietf() throws {
        let key = Data(repeating: 0x01, count: cryptoAead.xchacha20poly1305IetfKeyBytes)
        let nonce = Data(repeating: 0x03, count: cryptoAead.xchacha20poly1305IetfNpubBytes)
        let message = "Hello, extended nonce!".data(using: .utf8)!
        let aad = "Extended Additional Data".data(using: .utf8)

        // Encrypt
        let ciphertext = try cryptoAead.xchacha20poly1305IetfEncrypt(
            message: message, aad: aad, nonce: nonce, key: key)
        XCTAssertFalse(ciphertext.isEmpty, "Ciphertext should not be empty.")

        // Decrypt
        let decryptedMessage = try cryptoAead.xchacha20poly1305IetfDecrypt(
            ciphertext: ciphertext, aad: aad, nonce: nonce, key: key)
        XCTAssertEqual(decryptedMessage, message, "Decrypted message should match the original.")
    }

    func testInvalidKeyLength() {
        let key = Data(repeating: 0x01, count: 10)  // Invalid key length
        let nonce = Data(repeating: 0x02, count: cryptoAead.chacha20poly1305IetfNpubBytes)
        let message = "Short key test".data(using: .utf8)!

        XCTAssertThrowsError(
            try cryptoAead.chacha20poly1305IetfEncrypt(
                message: message, aad: nil, nonce: nonce, key: key)
        ) { error in
            XCTAssertTrue(error is SodiumError, "Error should be of type SodiumError.")
        }

        XCTAssertThrowsError(
            try cryptoAead.chacha20poly1305Encrypt(
                message: message, aad: nil, nonce: nonce, key: key)
        ) { error in
            XCTAssertTrue(error is SodiumError, "Error should be of type SodiumError.")
        }

        XCTAssertThrowsError(
            try cryptoAead.xchacha20poly1305IetfEncrypt(
                message: message, aad: nil, nonce: nonce, key: key)
        ) { error in
            XCTAssertTrue(error is SodiumError, "Error should be of type SodiumError.")
        }
    }

    func testInvalidNonceLength() {
        let key = Data(repeating: 0x01, count: cryptoAead.chacha20poly1305IetfKeyBytes)
        let nonce = Data(repeating: 0x02, count: 5)  // Invalid nonce length
        let message = "Short nonce test".data(using: .utf8)!

        XCTAssertThrowsError(
            try cryptoAead.chacha20poly1305IetfEncrypt(
                message: message, aad: nil, nonce: nonce, key: key)
        ) { error in
            XCTAssertTrue(error is SodiumError, "Error should be of type SodiumError.")
        }

        XCTAssertThrowsError(
            try cryptoAead.chacha20poly1305Encrypt(
                message: message, aad: nil, nonce: nonce, key: key)
        ) { error in
            XCTAssertTrue(error is SodiumError, "Error should be of type SodiumError.")
        }

        XCTAssertThrowsError(
            try cryptoAead.xchacha20poly1305IetfEncrypt(
                message: message, aad: nil, nonce: nonce, key: key)
        ) { error in
            XCTAssertTrue(error is SodiumError, "Error should be of type SodiumError.")
        }
    }
}
