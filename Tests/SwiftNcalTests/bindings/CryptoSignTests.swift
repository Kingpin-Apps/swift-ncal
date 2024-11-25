import XCTest
@testable import SwiftNcal

class CryptoSignTests: XCTestCase {
    let cryptoSign = SwiftNcal().cryptoSign
    
    // Test keypair generation
    func testCryptoSignKeypair() throws {
        let keypair = try cryptoSign.keypair()
        XCTAssertEqual(keypair.publicKey.count, cryptoSign.publicKeyBytes, "Public key length mismatch")
        XCTAssertEqual(keypair.secretKey.count, cryptoSign.secretKeyBytes, "Secret key length mismatch")
    }
    
    // Test seed-based keypair generation
    func testCryptoSignSeedKeypair() throws {
        let seed = Data(repeating: 0x01, count: cryptoSign.seedBytes)
        let keypair = try cryptoSign.seedKeypair(seed: seed)
        XCTAssertEqual(keypair.publicKey.count, cryptoSign.publicKeyBytes, "Public key length mismatch")
        XCTAssertEqual(keypair.secretKey.count, cryptoSign.secretKeyBytes, "Secret key length mismatch")
    }
    
    // Test message signing and verification
    func testCryptoSignAndOpen() throws {
        let keypair = try cryptoSign.keypair()
        let message = "Hello, Sodium!".data(using: .utf8)!
        
        let signedMessage = try cryptoSign.sign(message: message, sk: keypair.secretKey)
        XCTAssertEqual(
            signedMessage.count,
            message.count + cryptoSign.bytes,
            "Unsigned message does not match the original message"
        )
        
        let unsignedMessage = try cryptoSign.open(signed: signedMessage, pk: keypair.publicKey)
        
        XCTAssertEqual(
            unsignedMessage.count,
            message.count,
            "Unsigned message does not match the original message"
        )
    }
    
    // Test Ed25519 public key conversion to Curve25519
    func testCryptoSignEd25519PkToCurve25519() throws {
        let keypair = try cryptoSign.keypair()
        let curve25519PublicKey = try cryptoSign.ed25519PkToCurve25519(publicKeyBytes: keypair.publicKey)
        XCTAssertEqual(curve25519PublicKey.count, cryptoSign.curve25519Bytes, "Curve25519 public key length mismatch")
    }
    
    // Test Ed25519 secret key conversion to Curve25519
    func testCryptoSignEd25519SkToCurve25519() throws {
        let keypair = try cryptoSign.keypair()
        let curve25519SecretKey = try cryptoSign.ed25519SkToCurve25519(secretKeyBytes: keypair.secretKey)
        XCTAssertEqual(curve25519SecretKey.count, cryptoSign.curve25519Bytes, "Curve25519 secret key length mismatch")
    }
    
    // Test extracting public key from secret key
    func testCryptoSignEd25519SkToPk() throws {
        let keypair = try cryptoSign.keypair()
        let extractedPublicKey = try cryptoSign.ed25519SkToPk(secretKeyBytes: keypair.secretKey)
        XCTAssertEqual(extractedPublicKey, keypair.publicKey, "Extracted public key does not match original")
    }
    
    // Test extracting seed from secret key
    func testCryptoSignEd25519SkToSeed() throws {
        let seed = Data(repeating: 0x01, count: cryptoSign.seedBytes)
        let keypair = try cryptoSign.seedKeypair(seed: seed)
        let extractedSeed = try cryptoSign.ed25519SkToSeed(secretKeyBytes: keypair.secretKey)
        XCTAssertEqual(extractedSeed, seed, "Extracted seed does not match the original")
    }
    
    // Test prehashed signing and verification
    func testCryptoSignEd25519ph() throws {
        let keypair = try cryptoSign.keypair()
        let message = "Prehashed test message".data(using: .utf8)!
        
        let edph = try CryptoSignEd25519phState()
        try cryptoSign.ed25519phUpdate(edph: edph, pmsg: message)
        
        let signature = try cryptoSign.ed25519phFinalCreate(edph: edph, sk: keypair.secretKey)
        XCTAssertEqual(signature.count, cryptoSign.bytes, "Signature length mismatch")
        
        let isValid = try cryptoSign.ed25519phFinalVerify(edph: edph, signature: signature, pk: keypair.publicKey)
        XCTAssertTrue(isValid, "Signature verification failed")
    }
}
