import XCTest

@testable import SwiftNcal

class SecretBoxTests: XCTestCase {
    let sodium = Sodium()
    let message = "The quick brown fox jumps over the lazy dog".data(using: .utf8)!

    func testSecretBoxInit() throws {
        let secretBox = try SecretBox(key: Data(repeating: 0, count: sodium.cryptoSecretBox.keyBytes))
        XCTAssertEqual(
            secretBox.keySize, sodium.cryptoSecretBox.keyBytes, "SecretBox key size mismatch")
    }

    func testSecretBoxInvalidKeySize() {
        let invalidKey = Data(repeating: 0, count: sodium.cryptoSecretBox.keyBytes - 1)
        XCTAssertThrowsError(try SecretBox(key: invalidKey), "Expected error for invalid key size")
    }

    func testSecretBoxEncryptDecrypt() throws {
        let secretBox = try SecretBox(key: Data(repeating: 0, count: sodium.cryptoSecretBox.keyBytes))
        let encryptedMessage = try secretBox.encrypt(plaintext: message)
        let decryptedMessage = try secretBox.decrypt(
            ciphertext: encryptedMessage.getMessage
        )
        XCTAssertEqual(decryptedMessage, message, "SecretBox encrypt/decrypt failed")
    }

    func testSecretBoxEncryptWithNonce() throws {
        let secretBox = try SecretBox(key: Data(repeating: 0, count: sodium.cryptoSecretBox.keyBytes))
        let nonce = Data(repeating: 0, count: sodium.cryptoSecretBox.nonceBytes)
        let encryptedMessage = try secretBox.encrypt(plaintext: message, nonce: nonce)
        let decryptedMessage = try secretBox.decrypt(
            ciphertext: encryptedMessage.getMessage, nonce: nonce)
        XCTAssertEqual(decryptedMessage, message, "SecretBox encrypt/decrypt with nonce failed")
    }

    func testSecretBoxDecryptWithInvalidNonce() throws {
        let secretBox = try SecretBox(key: Data(repeating: 0, count: sodium.cryptoSecretBox.keyBytes))
        let encryptedMessage = try secretBox.encrypt(plaintext: message)
        let invalidNonce = Data(repeating: 0, count: sodium.cryptoSecretBox.nonceBytes - 1)
        XCTAssertThrowsError(
            try secretBox.decrypt(ciphertext: encryptedMessage.getMessage, nonce: invalidNonce),
            "Expected error for invalid nonce size")
    }
}

class AeadTests: XCTestCase {
    let sodium = Sodium()
    let message = "The quick brown fox jumps over the lazy dog".data(using: .utf8)!
    let aad = "Additional authenticated data".data(using: .utf8)!

    func testAeadInit() throws {
        let aead = try Aead(key: Data(repeating: 0, count: sodium.cryptoAead.xchacha20poly1305IetfKeyBytes))
        XCTAssertEqual(
            aead.keySize, sodium.cryptoAead.xchacha20poly1305IetfKeyBytes, "Aead key size mismatch")
    }

    func testAeadInvalidKeySize() {
        let invalidKey = Data(
            repeating: 0, count: sodium.cryptoAead.xchacha20poly1305IetfKeyBytes - 1)
        XCTAssertThrowsError(try Aead(key: invalidKey), "Expected error for invalid key size")
    }

    func testAeadEncryptDecrypt() throws {
        let aead = try Aead(key: Data(repeating: 0, count: sodium.cryptoAead.xchacha20poly1305IetfKeyBytes))
        let encryptedMessage = try aead.encrypt(plaintext: message, aad: aad)
        let decryptedMessage = try aead.decrypt(ciphertext: encryptedMessage.getMessage, aad: aad)
        XCTAssertEqual(decryptedMessage, message, "Aead encrypt/decrypt failed")
    }

    func testAeadEncryptWithNonce() throws {
        let aead = try Aead(key: Data(repeating: 0, count: sodium.cryptoAead.xchacha20poly1305IetfKeyBytes))
        let nonce = Data(repeating: 0, count: sodium.cryptoAead.xchacha20poly1305IetfNpubBytes)
        let encryptedMessage = try aead.encrypt(plaintext: message, aad: aad, nonce: nonce)
        let decryptedMessage = try aead.decrypt(
            ciphertext: encryptedMessage.getMessage, aad: aad, nonce: nonce)
        XCTAssertEqual(decryptedMessage, message, "Aead encrypt/decrypt with nonce failed")
    }

    func testAeadDecryptWithInvalidNonce() throws {
        let aead = try Aead(key: Data(repeating: 0, count: sodium.cryptoAead.xchacha20poly1305IetfKeyBytes))
        let encryptedMessage = try aead.encrypt(plaintext: message, aad: aad)
        let invalidNonce = Data(
            repeating: 0, count: sodium.cryptoAead.xchacha20poly1305IetfNpubBytes - 1)
        XCTAssertThrowsError(
            try aead.decrypt(ciphertext: encryptedMessage.getMessage, aad: aad, nonce: invalidNonce),
            "Expected error for invalid nonce size")
    }
}
