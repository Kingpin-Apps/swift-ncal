import XCTest

@testable import SwiftNcal

class SignedMessageTests: XCTestCase {
    let signature = Data(repeating: 0, count: 64)
    let message = "The quick brown fox jumps over the lazy dog".data(using: .utf8)!
    let combined = Data(repeating: 0, count: 128)

    func testSignedMessageInit() {
        let signedMessage = SignedMessage(
            signature: signature, message: message, combined: combined)
        XCTAssertEqual(signedMessage.getSignature, signature, "SignedMessage signature mismatch")
        XCTAssertEqual(signedMessage.getMessage, message, "SignedMessage message mismatch")
        XCTAssertEqual(signedMessage.getCombined, combined, "SignedMessage combined mismatch")
    }

    func testSignedMessageFromParts() {
        let signedMessage = SignedMessage.fromParts(
            signature: signature, message: message, combined: combined)
        XCTAssertEqual(signedMessage.getSignature, signature, "SignedMessage signature mismatch")
        XCTAssertEqual(signedMessage.getMessage, message, "SignedMessage message mismatch")
        XCTAssertEqual(signedMessage.getCombined, combined, "SignedMessage combined mismatch")
    }
}

class VerifyKeyTests: XCTestCase {
    let sodium = Sodium()

    func testVerifyKeyInit() throws {
        let verifyKey = try VerifyKey(key: Data(repeating: 0, count: sodium.cryptoSign.publicKeyBytes))
        XCTAssertEqual(verifyKey.bytes, Data(repeating: 0, count: sodium.cryptoSign.publicKeyBytes), "VerifyKey initialization failed")
    }

    func testVerifyKeyHash() throws {
        let verifyKey = try VerifyKey(key: Data(repeating: 0, count: sodium.cryptoSign.publicKeyBytes))
        XCTAssertNotNil(verifyKey.hashValue, "VerifyKey hash failed")
    }

    func testVerifyKeyInvalidSize() {
        let invalidPublicKeyData = Data(repeating: 0, count: sodium.cryptoSign.publicKeyBytes - 1)
        XCTAssertThrowsError(
            try VerifyKey(key: invalidPublicKeyData), "Expected error for invalid public key size")
    }

    func testVerifyKeyEquality() throws {
        let verifyKey1 = try VerifyKey(key: Data(repeating: 0, count: sodium.cryptoSign.publicKeyBytes))
        let verifyKey2 = try VerifyKey(key: Data(repeating: 0, count: sodium.cryptoSign.publicKeyBytes))
        XCTAssertEqual(verifyKey1, verifyKey2, "VerifyKey equality failed")
        XCTAssertTrue(verifyKey1 == verifyKey2, "VerifyKey equality failed")
    }

    func testVerifyKeyVerify() throws {
        let verifyKey = try VerifyKey(key: Data(repeating: 0, count: sodium.cryptoSign.publicKeyBytes))
        let signedMessage = Data(repeating: 0, count: sodium.cryptoSign.bytes + 32)
        XCTAssertThrowsError(
            try verifyKey.verify(smessage: signedMessage), "Expected error for invalid signature")
    }
    
    func testVerifyKeyVerifyInvalidSignature() throws {
        let verifyKey = try VerifyKey(key: Data(repeating: 0, count: sodium.cryptoSign.publicKeyBytes))
        let signedMessage = Data(repeating: 0, count: sodium.cryptoSign.bytes + 32)
        let invalidSignature = Data(repeating: 0, count: 32)
        XCTAssertThrowsError(
            try verifyKey
                .verify(
                    smessage: signedMessage,
                    signature: invalidSignature
                ),
            "Expected error for invalid signature size"
        )
    }

    func testVerifyKeyToCurve25519PublicKey() throws {
        let keypair = try sodium.cryptoSign.keypair()
        let verifyKey = try VerifyKey(key:keypair.publicKey)
        let curve25519PublicKey = try verifyKey.toCurve25519PublicKey()
        XCTAssertNotNil(curve25519PublicKey, "VerifyKey toCurve25519PublicKey failed")
    }
}

class SigningKeyTests: XCTestCase {
    let sodium = Sodium()
    
    
    func testSigningKeyInit() throws {
        let signingKey = try SigningKey(seed: Data(repeating: 0, count: sodium.cryptoSign.seedBytes))
        XCTAssertEqual(signingKey.bytes, Data(repeating: 0, count: sodium.cryptoSign.seedBytes), "SigningKey initialization failed")
    }
    
    func testSigningKeyHash() throws {
        let signingKey = try SigningKey(seed: Data(repeating: 0, count: sodium.cryptoSign.seedBytes))
        XCTAssertNotNil(signingKey.hashValue, "VerifyKey hash failed")
    }
    
    func testSigningKeyEquality() throws {
        let signingKey1 = try SigningKey(seed: Data(repeating: 0, count: sodium.cryptoSign.seedBytes))
        let signingKey2 = try SigningKey(seed: Data(repeating: 0, count: sodium.cryptoSign.seedBytes))
        XCTAssertEqual(signingKey1, signingKey2, "SigningKey equality failed")
        XCTAssertTrue(signingKey1 == signingKey2, "SigningKey equality failed")
    }

    func testSigningKeyInvalidSize() {
        let invalidSeed = Data(repeating: 0, count: sodium.cryptoSign.seedBytes - 1)
        XCTAssertThrowsError(
            try SigningKey(seed: invalidSeed), "Expected error for invalid seed size")
    }

    func testSigningKeyGenerate() throws {
        let signingKey = try SigningKey.generate()
        XCTAssertEqual(
            signingKey.bytes.count, sodium.cryptoSign.seedBytes, "SigningKey generate failed")
    }

    func testSigningKeySign() throws {
        let signingKey = try SigningKey(seed: Data(repeating: 0, count: sodium.cryptoSign.seedBytes))
        let message = "The quick brown fox jumps over the lazy dog".data(using: .utf8)!
        let signedMessage = try signingKey.sign(message: message)
        XCTAssertEqual(signedMessage.getMessage, message, "SigningKey sign message mismatch")
    }

    func testSigningKeyToCurve25519PrivateKey() throws {
        let signingKey = try SigningKey(seed: Data(repeating: 0, count: sodium.cryptoSign.seedBytes))
        let curve25519PrivateKey = try signingKey.toCurve25519PrivateKey()
        XCTAssertNotNil(curve25519PrivateKey, "SigningKey toCurve25519PrivateKey failed")
    }
}
