import XCTest

@testable import SwiftNcal

class PublicKeyTests: XCTestCase {
    let sodium = Sodium()
    let publicKeyData = Data(repeating: 0, count: PublicKey.SIZE)

    func testPublicKeyInit() throws {
        let publicKey = try PublicKey(publicKey: publicKeyData)
        XCTAssertEqual(publicKey.toBytes(), publicKeyData, "PublicKey initialization failed")
    }

    func testPublicKeyInvalidSize() {
        let invalidPublicKeyData = Data(repeating: 0, count: PublicKey.SIZE - 1)
        XCTAssertThrowsError(
            try PublicKey(publicKey: invalidPublicKeyData),
            "Expected error for invalid public key size")
    }

    func testPublicKeyEquality() throws {
        let publicKey1 = try PublicKey(publicKey: publicKeyData)
        let publicKey2 = try PublicKey(publicKey: publicKeyData)
        XCTAssertEqual(publicKey1, publicKey2, "PublicKey equality failed")
    }
}

class PrivateKeyTests: XCTestCase {
    let sodium = Sodium()
    let privateKeyData = Data(repeating: 0, count: PrivateKey.SIZE)

    func testPrivateKeyInit() throws {
        let privateKey = try PrivateKey(privateKey: privateKeyData)
        XCTAssertEqual(privateKey.toBytes(), privateKeyData, "PrivateKey initialization failed")
    }

    func testPrivateKeyInvalidSize() {
        let invalidPrivateKeyData = Data(repeating: 0, count: PrivateKey.SIZE - 1)
        XCTAssertThrowsError(
            try PrivateKey(privateKey: invalidPrivateKeyData),
            "Expected error for invalid private key size")
    }

    func testPrivateKeyFromSeed() throws {
        let seed = Data(repeating: 0, count: PrivateKey.SEED_SIZE)
        let privateKey = try PrivateKey.fromSeed(seed: seed)
        XCTAssertEqual(privateKey.toBytes().count, PrivateKey.SIZE, "PrivateKey from seed failed")
    }

    func testPrivateKeyEquality() throws {
        let privateKey1 = try PrivateKey(privateKey: privateKeyData)
        let privateKey2 = try PrivateKey(privateKey: privateKeyData)
        XCTAssertEqual(privateKey1, privateKey2, "PrivateKey equality failed")
    }
}

class BoxTests: XCTestCase {
    let sodium = Sodium()
    let message = "The quick brown fox jumps over the lazy dog".data(using: .utf8)!
    let privateKey = PrivateKey.generate()

    func testBoxInit() throws {
        let box = try Box(privateKey: privateKey, publicKey: privateKey.publicKey)
        XCTAssertNotNil(box, "Box initialization failed")
    }

    func testBoxEncryptDecrypt() throws {
        let box = try Box(privateKey: privateKey, publicKey: privateKey.publicKey)
        let encryptedMessage = try box.encrypt(plaintext: message)
        let decryptedMessage = try box.decrypt(ciphertext: encryptedMessage.getMessage)
        XCTAssertEqual(decryptedMessage, message, "Box encrypt/decrypt failed")
    }

    func testBoxEncryptWithNonce() throws {
        let box = try Box(privateKey: privateKey, publicKey: privateKey.publicKey)
        let nonce = Data(repeating: 0, count: Box.NONCE_SIZE)
        let encryptedMessage = try box.encrypt(plaintext: message, nonce: nonce)
        let decryptedMessage = try box.decrypt(
            ciphertext: encryptedMessage.getCiphertext, nonce: nonce)
        XCTAssertEqual(decryptedMessage, message, "Box encrypt/decrypt with nonce failed")
    }

    func testBoxDecryptWithInvalidNonce() throws {
        let box = try Box(privateKey: privateKey, publicKey: privateKey.publicKey)
        let encryptedMessage = try box.encrypt(plaintext: message)
        let invalidNonce = Data(repeating: 0, count: Box.NONCE_SIZE - 1)
        XCTAssertThrowsError(
            try box.decrypt(ciphertext: encryptedMessage.getCiphertext, nonce: invalidNonce),
            "Expected error for invalid nonce size")
    }
}

class SealedBoxTests: XCTestCase {
    let sodium = Sodium()
    let message = "The quick brown fox jumps over the lazy dog".data(using: .utf8)!
    let privateKey =  PrivateKey.generate()

    func testSealedBoxInitWithPublicKey() {
        let sealedBox = SealedBox(recipientKey: privateKey.publicKey)
        XCTAssertNotNil(sealedBox, "SealedBox initialization with public key failed")
    }

    func testSealedBoxInitWithPrivateKey() {
        let sealedBox = SealedBox(recipientKey: privateKey)
        XCTAssertNotNil(sealedBox, "SealedBox initialization with private key failed")
    }

    func testSealedBoxEncryptDecrypt() throws {
        let sealedBox = SealedBox(recipientKey: privateKey)
        let encryptedMessage = try sealedBox.encrypt(plaintext: message)
        let decryptedMessage = try sealedBox.decrypt(ciphertext: encryptedMessage)
        XCTAssertEqual(decryptedMessage, message, "SealedBox encrypt/decrypt failed")
    }

    func testSealedBoxDecryptWithPublicKey() {
        let sealedBox = SealedBox(recipientKey: privateKey.publicKey)
        let encryptedMessage = try! sealedBox.encrypt(plaintext: message)
        XCTAssertThrowsError(
            try sealedBox.decrypt(ciphertext: encryptedMessage),
            "Expected error for decrypting with public key")
    }
}
