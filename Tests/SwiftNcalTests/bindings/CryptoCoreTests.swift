import XCTest
@testable import SwiftNcal

final class CryptoCoreEd25519Tests: XCTestCase {
    let swiftNcal = SwiftNcal()

    func testCryptoCoreEd25519IsValidPoint() throws {
        /// Verify crypto_core_ed25519_is_valid_point correctly rejects the all-zeros "point"

        // Generate a valid point (mocked or generated using libsodium)
        let zeroPoint = Data(repeating: 0, count: swiftNcal.cryptoCore.ed25519Bytes)
        
        let result = try swiftNcal.cryptoCore.ed25519IsValidPoint(zeroPoint)
        
        XCTAssertFalse(result, "The all-zeros point should not be valid on the edwards25519 curve.")
    }

    func testCryptoCoreEd25519FromUniform() throws {
        /// Verify `cryptoCoreEd25519FromUniform` maps 32-byte inputs to valid points.

       var isValid = true

       // Test 500 random inputs
       for _ in 0..<500 {
           let randomInput = Data((0..<swiftNcal.cryptoCore.ed25519Bytes).map { _ in UInt8.random(in: 0...255) })
           let point = try swiftNcal.cryptoCore.ed25519FromUniform(randomInput)
           let isValidPoint = try swiftNcal.cryptoCore.ed25519IsValidPoint(point)
           isValid = isValid && isValidPoint
       }
       
       XCTAssertTrue(isValid, "All generated points should be valid.")

       // Test with specific input and expected output from libsodium discussion
       let randomDataInput = Data([
           0x7f, 0x3e, 0x7f, 0xb9, 0x42, 0x81, 0x03, 0xad, 0x7f, 0x52, 0xdb, 0x32, 0xf9, 0xdf, 0x32, 0x50,
           0x5d, 0x7b, 0x42, 0x7d, 0x89, 0x4c, 0x50, 0x93, 0xf7, 0xa0, 0xf0, 0x37, 0x4a, 0x30, 0x64, 0x1d
       ])
       let expectedOutput = Data([
           0x44, 0xb2, 0xfa, 0x2a, 0x6b, 0xb0, 0xb2, 0xad, 0xea, 0xce, 0x69, 0x0a, 0x5a, 0x83, 0xb7, 0xfb,
           0xe5, 0xbb, 0x48, 0x7c, 0x34, 0xe6, 0x4d, 0xc1, 0x09, 0xb9, 0x0b, 0xc4, 0xe0, 0x0f, 0x67, 0x0b
       ])

       // Verify invalid input
       XCTAssertFalse(try swiftNcal.cryptoCore.ed25519IsValidPoint(randomDataInput),
                      "The input should not initially be a valid point.")

       // Convert to point
       let randomDataToCurve = try swiftNcal.cryptoCore.ed25519FromUniform(randomDataInput)

       // Verify valid output and match the expected output
       XCTAssertTrue(try swiftNcal.cryptoCore.ed25519IsValidPoint(randomDataToCurve),
                     "The output should be a valid point.")
       XCTAssertEqual(randomDataToCurve, expectedOutput,
                      "The output should match the expected output.")
    }
    
    func testEd25519AddAndSub() throws {
        /// The public component of a ed25519 keypair is a point on the ed25519 curve
        // Generate two key pairs
        let (p1, _) = try swiftNcal.cryptoSign.keypair()
        let (p2, _) = try swiftNcal.cryptoSign.keypair()
        
        // Add the two points
        let p3 = try swiftNcal.cryptoCore.ed25519Add(p1, p2)
        
        // Verify that the resulting point is valid
        XCTAssertTrue(try swiftNcal.cryptoCore.ed25519IsValidPoint(p3))
        
        // Subtract p1 from p3 and ensure the result is p2
        XCTAssertEqual(try swiftNcal.cryptoCore.ed25519Sub(p3, p1), p2)
        
        // Subtract p2 from p3 and ensure the result is p1
        XCTAssertEqual(try swiftNcal.cryptoCore.ed25519Sub(p3, p2), p1)
    }
    
    func testEd25519ScalarInvertNegateComplement() throws {
        // Define zero and one scalars
        let zero = Data(repeating: 0, count: swiftNcal.cryptoCore.ed25519ScalarBytes)
        var one = Data(repeating: 0, count: swiftNcal.cryptoCore.ed25519ScalarBytes)
        one[0] = 1
        
        // Generate a random scalar
        var sclr = swiftNcal.randomBytes.randomBytes(size: swiftNcal.cryptoCore.ed25519ScalarBytes)
        sclr = try swiftNcal.cryptoCore.ed25519ScalarAdd(sclr, zero)
        
        // Test scalar inversion
        let i = try swiftNcal.cryptoCore.ed25519ScalarInvert(sclr)
        let sclrMulI = try swiftNcal.cryptoCore.ed25519ScalarMul(sclr, i)
        XCTAssertEqual(sclrMulI, one)
        
        // Test scalar negation
        let n = try swiftNcal.cryptoCore.ed25519ScalarNegate(sclr)
        let sclrPlusN = try swiftNcal.cryptoCore.ed25519ScalarAdd(sclr, n)
        XCTAssertEqual(sclrPlusN, zero)
        
        // Test scalar complement
        let cp = try swiftNcal.cryptoCore.ed25519ScalarComplement(sclr)
        let sclrPlusCp = try swiftNcal.cryptoCore.ed25519ScalarAdd(sclr, cp)
        XCTAssertEqual(sclrPlusCp, one)
    }

    func testEd25519ScalarReduce() throws {
        // Define zero scalar
        let zero = Data(repeating: 0, count: swiftNcal.cryptoCore.ed25519ScalarBytes)
        
        // Define l65536: 65536 times the order of the main subgroup, padded to 64 bytes
        let l65536 = Data(
            [
                0x00, 0x00, // Padding
                0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58,
                0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
            ] + Array(repeating: 0x00, count: 30) // Padding
        )
        
        // Generate a random scalar
        let randomScalar = swiftNcal.randomBytes.randomBytes(size: swiftNcal.cryptoCore.ed25519ScalarBytes)
        
        // Add the random scalar to zero
        let p = try swiftNcal.cryptoCore.ed25519ScalarAdd(randomScalar, zero)
        
        // Create "big" by adding l65536 and p padded to 64 bytes
        var paddedP = Data(repeating: 0, count: 64)
        paddedP.replaceSubrange(0..<p.count, with: p)
        let big = swiftNcal.utils.sodiumAdd(l65536, paddedP)
        
        // Reduce "big" modulo l
        let r = try swiftNcal.cryptoCore.ed25519ScalarReduce(big)
        
        // Assert that the reduced value equals the original scalar p
        XCTAssertEqual(r, p)
    }
}
