import XCTest
@testable import SwiftNcal

final class VRFTests: XCTestCase {
    
    // MARK: - Test Constants
    
    func testVRFConstants() {
        XCTAssertEqual(VRF.seedBytes, 32, "VRF seed should be 32 bytes")
        XCTAssertEqual(VRF.secretKeyBytes, 64, "VRF secret key should be 64 bytes")
        XCTAssertEqual(VRF.publicKeyBytes, 32, "VRF public key should be 32 bytes")
        XCTAssertEqual(VRF.proofBytes, 80, "VRF proof should be 80 bytes")
        XCTAssertEqual(VRF.outputBytes, 64, "VRF output should be 64 bytes")
    }
    
    // MARK: - VRF Seed Tests
    
    func testVRFSeedGeneration() {
        let seed1 = VRFSeed.generate()
        let seed2 = VRFSeed.generate()
        
        XCTAssertEqual(seed1.bytes.count, VRF.seedBytes)
        XCTAssertEqual(seed2.bytes.count, VRF.seedBytes)
        XCTAssertNotEqual(seed1, seed2, "Generated seeds should be different")
    }
    
    func testVRFSeedFromBytes() throws {
        let randomBytes = Data(repeating: 0x42, count: VRF.seedBytes)
        let seed = try VRFSeed(bytes: randomBytes)
        
        XCTAssertEqual(seed.bytes, randomBytes)
    }
    
    func testVRFSeedFromBytesInvalidSize() {
        let invalidBytes = Data(repeating: 0x42, count: VRF.seedBytes - 1)
        
        XCTAssertThrowsError(try VRFSeed(bytes: invalidBytes)) { error in
            XCTAssertEqual(error as? VRFError, VRFError.invalidInputSize)
        }
    }
    
    func testVRFSeedFromHexString() throws {
        let hexString = String(repeating: "42", count: VRF.seedBytes)
        let seed = try VRFSeed(hexString: hexString)
        let expectedBytes = Data(repeating: 0x42, count: VRF.seedBytes)
        
        XCTAssertEqual(seed.bytes, expectedBytes)
        XCTAssertEqual(seed.hexEncodedString(), hexString)
    }
    
    func testVRFSeedFromInvalidHexString() {
        let invalidHex = "invalidhex"
        
        XCTAssertThrowsError(try VRFSeed(hexString: invalidHex)) { error in
            XCTAssertEqual(error as? VRFError, VRFError.invalidInputSize)
        }
    }
    
    func testVRFSeedEquality() throws {
        let bytes = Data(repeating: 0x42, count: VRF.seedBytes)
        let seed1 = try VRFSeed(bytes: bytes)
        let seed2 = try VRFSeed(bytes: bytes)
        let differentSeed = VRFSeed.generate()
        
        XCTAssertEqual(seed1, seed2)
        XCTAssertNotEqual(seed1, differentSeed)
    }
    
    // Codable tests removed - project uses custom Encoder protocol
    
    // MARK: - VRF Key Pair Tests
    
    func testVRFKeyPairGeneration() {
        let keyPair = VRFKeyPair.generate()
        
        XCTAssertEqual(keyPair.signingKey.bytes.count, VRF.secretKeyBytes)
        XCTAssertEqual(keyPair.verifyingKey.bytes.count, VRF.publicKeyBytes)
    }
    
    func testVRFKeyPairFromSeed() throws {
        let seed = VRFSeed.generate()
        let keyPair = try VRFKeyPair.from(seed: seed)
        
        XCTAssertEqual(keyPair.signingKey.bytes.count, VRF.secretKeyBytes)
        XCTAssertEqual(keyPair.verifyingKey.bytes.count, VRF.publicKeyBytes)
        
        // Test deterministic generation
        let keyPair2 = try VRFKeyPair.from(seed: seed)
        XCTAssertEqual(keyPair.signingKey, keyPair2.signingKey)
        XCTAssertEqual(keyPair.verifyingKey, keyPair2.verifyingKey)
    }
    
    func testVRFSigningKeyToVerifyingKey() throws {
        let keyPair = VRFKeyPair.generate()
        let derivedVerifyingKey = keyPair.signingKey.verifyingKey
        
        XCTAssertEqual(keyPair.verifyingKey, derivedVerifyingKey)
    }
    
    func testVRFSigningKeyToSeed() throws {
        let seed = VRFSeed.generate()
        let keyPair = try VRFKeyPair.from(seed: seed)
        let derivedSeed = keyPair.signingKey.seed
        
        XCTAssertEqual(seed, derivedSeed)
    }
    
    // MARK: - VRF Signing Key Tests
    
    func testVRFSigningKeyFromBytes() throws {
        let randomBytes = Data((0..<VRF.secretKeyBytes).map { _ in UInt8.random(in: 0...255) })
        let signingKey = try VRFSigningKey(bytes: randomBytes)
        
        XCTAssertEqual(signingKey.bytes, randomBytes)
    }
    
    func testVRFSigningKeyFromBytesInvalidSize() {
        let invalidBytes = Data(repeating: 0x42, count: VRF.secretKeyBytes - 1)
        
        XCTAssertThrowsError(try VRFSigningKey(bytes: invalidBytes)) { error in
            XCTAssertEqual(error as? VRFError, VRFError.invalidInputSize)
        }
    }
    
    func testVRFSigningKeyFingerprint() throws {
        let keyPair = VRFKeyPair.generate()
        let fingerprint = keyPair.signingKey.fingerprint()
        
        XCTAssertTrue(fingerprint.hasSuffix("..."))
        XCTAssertEqual(fingerprint.count, 19) // 16 hex chars + "..."
    }
    
    // Codable tests removed - project uses custom Encoder protocol
    
    // MARK: - VRF Verifying Key Tests
    
    func testVRFVerifyingKeyFromBytes() throws {
        let keyPair = VRFKeyPair.generate()
        let verifyingKey = try VRFVerifyingKey(bytes: keyPair.verifyingKey.bytes)
        
        XCTAssertEqual(verifyingKey, keyPair.verifyingKey)
    }
    
    func testVRFVerifyingKeyFromBytesInvalidSize() {
        let invalidBytes = Data(repeating: 0x42, count: VRF.publicKeyBytes - 1)
        
        XCTAssertThrowsError(try VRFVerifyingKey(bytes: invalidBytes)) { error in
            XCTAssertEqual(error as? VRFError, VRFError.invalidInputSize)
        }
    }
    
    func testVRFVerifyingKeyFromHexString() throws {
        let keyPair = VRFKeyPair.generate()
        let hexString = keyPair.verifyingKey.hexEncodedString()
        let verifyingKey = try VRFVerifyingKey(hexString: hexString)
        
        XCTAssertEqual(verifyingKey, keyPair.verifyingKey)
    }
    
    // Codable tests removed - project uses custom Encoder protocol
    
    // MARK: - VRF Proof Tests
    
    func testVRFProofGeneration() throws {
        let keyPair = VRFKeyPair.generate()
        let message = "Hello, VRF!".data(using: .utf8)!
        
        let proof = try keyPair.signingKey.prove(message: message)
        
        XCTAssertEqual(proof.bytes.count, VRF.proofBytes)
    }
    
    func testVRFProofFromBytes() throws {
        let keyPair = VRFKeyPair.generate()
        let message = "Hello, VRF!".data(using: .utf8)!
        let originalProof = try keyPair.signingKey.prove(message: message)
        
        let proof = try VRFProof(bytes: originalProof.bytes)
        
        XCTAssertEqual(proof, originalProof)
    }
    
    func testVRFProofFromBytesInvalidSize() {
        let invalidBytes = Data(repeating: 0x42, count: VRF.proofBytes - 1)
        
        XCTAssertThrowsError(try VRFProof(bytes: invalidBytes)) { error in
            XCTAssertEqual(error as? VRFError, VRFError.invalidInputSize)
        }
    }
    
    func testVRFProofFromHexString() throws {
        let keyPair = VRFKeyPair.generate()
        let message = "Hello, VRF!".data(using: .utf8)!
        let originalProof = try keyPair.signingKey.prove(message: message)
        
        let hexString = originalProof.hexEncodedString()
        let proof = try VRFProof(hexString: hexString)
        
        XCTAssertEqual(proof, originalProof)
    }
    
    func testVRFProofHash() throws {
        let keyPair = VRFKeyPair.generate()
        let message = "Hello, VRF!".data(using: .utf8)!
        let proof = try keyPair.signingKey.prove(message: message)
        
        let output = try proof.hash()
        
        XCTAssertEqual(output.bytes.count, VRF.outputBytes)
    }
    
    // Codable tests removed - project uses custom Encoder protocol
    
    // MARK: - VRF Output Tests
    
    func testVRFOutputFromBytes() throws {
        let keyPair = VRFKeyPair.generate()
        let message = "Hello, VRF!".data(using: .utf8)!
        let proof = try keyPair.signingKey.prove(message: message)
        let originalOutput = try keyPair.verifyingKey.verify(message: message, proof: proof)
        
        let output = try VRFOutput(bytes: originalOutput.bytes)
        
        XCTAssertEqual(output, originalOutput)
    }
    
    func testVRFOutputFromBytesInvalidSize() {
        let invalidBytes = Data(repeating: 0x42, count: VRF.outputBytes - 1)
        
        XCTAssertThrowsError(try VRFOutput(bytes: invalidBytes)) { error in
            XCTAssertEqual(error as? VRFError, VRFError.invalidInputSize)
        }
    }
    
    // Codable tests removed - project uses custom Encoder protocol
    
    // MARK: - VRF Full Workflow Tests
    
    func testVRFFullWorkflow() throws {
        // Generate a key pair
        let keyPair = VRFKeyPair.generate()
        let message = "Hello, VRF World!".data(using: .utf8)!
        
        // Create a proof
        let proof = try keyPair.signingKey.prove(message: message)
        
        // Verify the proof and get output
        let output = try keyPair.verifyingKey.verify(message: message, proof: proof)
        
        // Extract output from proof directly
        let directOutput = try proof.hash()
        
        // Both methods should produce the same output
        XCTAssertEqual(output, directOutput)
        
        // The output should be deterministic
        let proof2 = try keyPair.signingKey.prove(message: message)
        let output2 = try keyPair.verifyingKey.verify(message: message, proof: proof2)
        
        XCTAssertEqual(output, output2)
        XCTAssertEqual(proof, proof2)
    }
    
    func testVRFDeterministicOutput() throws {
        // Same seed should produce same keys
        let seed = VRFSeed.generate()
        let keyPair1 = try VRFKeyPair.from(seed: seed)
        let keyPair2 = try VRFKeyPair.from(seed: seed)
        
        XCTAssertEqual(keyPair1.signingKey, keyPair2.signingKey)
        XCTAssertEqual(keyPair1.verifyingKey, keyPair2.verifyingKey)
        
        // Same key and message should produce same proof and output
        let message = "Deterministic test".data(using: .utf8)!
        let proof1 = try keyPair1.signingKey.prove(message: message)
        let proof2 = try keyPair2.signingKey.prove(message: message)
        
        XCTAssertEqual(proof1, proof2)
        
        let output1 = try keyPair1.verifyingKey.verify(message: message, proof: proof1)
        let output2 = try keyPair2.verifyingKey.verify(message: message, proof: proof2)
        
        XCTAssertEqual(output1, output2)
    }
    
    func testVRFDifferentMessagesProduceDifferentOutputs() throws {
        let keyPair = VRFKeyPair.generate()
        let message1 = "Message 1".data(using: .utf8)!
        let message2 = "Message 2".data(using: .utf8)!
        
        let proof1 = try keyPair.signingKey.prove(message: message1)
        let proof2 = try keyPair.signingKey.prove(message: message2)
        
        let output1 = try keyPair.verifyingKey.verify(message: message1, proof: proof1)
        let output2 = try keyPair.verifyingKey.verify(message: message2, proof: proof2)
        
        XCTAssertNotEqual(proof1, proof2)
        XCTAssertNotEqual(output1, output2)
    }
    
    func testVRFDifferentKeysProduceDifferentOutputs() throws {
        let keyPair1 = VRFKeyPair.generate()
        let keyPair2 = VRFKeyPair.generate()
        let message = "Same message".data(using: .utf8)!
        
        let proof1 = try keyPair1.signingKey.prove(message: message)
        let proof2 = try keyPair2.signingKey.prove(message: message)
        
        let output1 = try keyPair1.verifyingKey.verify(message: message, proof: proof1)
        let output2 = try keyPair2.verifyingKey.verify(message: message, proof: proof2)
        
        XCTAssertNotEqual(proof1, proof2)
        XCTAssertNotEqual(output1, output2)
    }
    
    // MARK: - VRF Error Tests
    
    func testVRFVerificationFailureWithWrongKey() throws {
        let keyPair1 = VRFKeyPair.generate()
        let keyPair2 = VRFKeyPair.generate()
        let message = "Test message".data(using: .utf8)!
        
        let proof = try keyPair1.signingKey.prove(message: message)
        
        // Try to verify with wrong key
        XCTAssertThrowsError(try keyPair2.verifyingKey.verify(message: message, proof: proof)) { error in
            XCTAssertEqual(error as? VRFError, VRFError.verificationFailed)
        }
    }
    
    func testVRFVerificationFailureWithWrongMessage() throws {
        let keyPair = VRFKeyPair.generate()
        let message1 = "Original message".data(using: .utf8)!
        let message2 = "Different message".data(using: .utf8)!
        
        let proof = try keyPair.signingKey.prove(message: message1)
        
        // Try to verify with wrong message
        XCTAssertThrowsError(try keyPair.verifyingKey.verify(message: message2, proof: proof)) { error in
            XCTAssertEqual(error as? VRFError, VRFError.verificationFailed)
        }
    }
    
    func testVRFInvalidPublicKey() {
        let invalidBytes = Data(repeating: 0x00, count: VRF.publicKeyBytes)
        
        XCTAssertThrowsError(try VRFVerifyingKey(bytes: invalidBytes)) { error in
            XCTAssertEqual(error as? VRFError, VRFError.invalidPublicKey)
        }
    }
    
    // MARK: - Performance Tests
    
    func testVRFPerformance() throws {
        let keyPair = VRFKeyPair.generate()
        let message = "Performance test message".data(using: .utf8)!
        
        measure {
            do {
                let proof = try keyPair.signingKey.prove(message: message)
                _ = try keyPair.verifyingKey.verify(message: message, proof: proof)
            } catch {
                XCTFail("VRF operations should not fail: \\(error)")
            }
        }
    }
    
    func testVRFKeyGenerationPerformance() {
        measure {
            _ = VRFKeyPair.generate()
        }
    }
    
    // MARK: - Known Test Vectors
    
    func testVRFWithKnownVector() throws {
        // Using a known seed for deterministic testing
        let seedHex = "0000000000000000000000000000000000000000000000000000000000000000"
        let seed = try VRFSeed(hexString: seedHex)
        let keyPair = try VRFKeyPair.from(seed: seed)
        
        let message = "test".data(using: .utf8)!
        let proof = try keyPair.signingKey.prove(message: message)
        let output = try keyPair.verifyingKey.verify(message: message, proof: proof)
        
        // Verify that we get consistent results
        XCTAssertEqual(proof.bytes.count, VRF.proofBytes)
        XCTAssertEqual(output.bytes.count, VRF.outputBytes)
        
        // Test that the same input produces the same output
        let proof2 = try keyPair.signingKey.prove(message: message)
        let output2 = try keyPair.verifyingKey.verify(message: message, proof: proof2)
        
        XCTAssertEqual(proof, proof2)
        XCTAssertEqual(output, output2)
    }
    
    // MARK: - Edge Cases
    
    func testVRFWithEmptyMessage() throws {
        let keyPair = VRFKeyPair.generate()
        let emptyMessage = Data()
        
        let proof = try keyPair.signingKey.prove(message: emptyMessage)
        let output = try keyPair.verifyingKey.verify(message: emptyMessage, proof: proof)
        
        XCTAssertEqual(proof.bytes.count, VRF.proofBytes)
        XCTAssertEqual(output.bytes.count, VRF.outputBytes)
    }
    
    func testVRFWithLargeMessage() throws {
        let keyPair = VRFKeyPair.generate()
        let largeMessage = Data(repeating: 0x42, count: 10000)
        
        let proof = try keyPair.signingKey.prove(message: largeMessage)
        let output = try keyPair.verifyingKey.verify(message: largeMessage, proof: proof)
        
        XCTAssertEqual(proof.bytes.count, VRF.proofBytes)
        XCTAssertEqual(output.bytes.count, VRF.outputBytes)
    }
}