import XCTest
import Foundation
@testable import SwiftNcal

class RandomBytesTests: XCTestCase {
    let randomBytes = SwiftNcal().randomBytes

    func testRandomBytesGeneratesCorrectSize() {
        let size = 32
        let randomData = randomBytes.randomBytes(size: size)
        
        XCTAssertEqual(randomData.count, size, "randomBytes did not generate the correct number of bytes")
    }
    
    func testRandomBytesGeneratesUniqueValues() {
        let size = 32
        let randomData1 = randomBytes.randomBytes(size: size)
        let randomData2 = randomBytes.randomBytes(size: size)
        
        XCTAssertNotEqual(randomData1, randomData2, "randomBytes generated identical values for different calls")
    }

    func testRandomBytesBufDeterministicGeneratesCorrectSize() throws {
        let size = 32
        let seed = [UInt8](repeating: 0, count: randomBytes.seedBytes)
        
        let deterministicData = try randomBytes.bufDeterministic(size: size, seed: seed)
        
        XCTAssertEqual(deterministicData.count, size, "randomBytesBufDeterministic did not generate the correct number of bytes")
    }
    
    func testRandomBytesBufDeterministicWithSameSeedProducesSameOutput() throws {
        let size = 32
        let seed = [UInt8](repeating: 1, count: randomBytes.seedBytes)
        
        let deterministicData1 = try randomBytes.bufDeterministic(size: size, seed: seed)
        let deterministicData2 = try randomBytes.bufDeterministic(size: size, seed: seed)
        
        XCTAssertEqual(deterministicData1, deterministicData2, "randomBytesBufDeterministic with the same seed produced different outputs")
    }

    func testRandomBytesBufDeterministicWithDifferentSeedsProducesDifferentOutput() throws {
        let size = 32
        let seed1 = [UInt8](repeating: 1, count: randomBytes.seedBytes)
        let seed2 = [UInt8](repeating: 2, count: randomBytes.seedBytes)
        
        let deterministicData1 = try randomBytes.bufDeterministic(size: size, seed: seed1)
        let deterministicData2 = try randomBytes.bufDeterministic(size: size, seed: seed2)
        
        XCTAssertNotEqual(deterministicData1, deterministicData2, "randomBytesBufDeterministic with different seeds produced the same output")
    }

    func testRandomBytesBufDeterministicThrowsErrorForInvalidSeedLength() {
        let size = 32
        let invalidSeed = [UInt8](repeating: 1, count: randomBytes.seedBytes - 1) // Invalid seed length
        
        XCTAssertThrowsError(try randomBytes.bufDeterministic(size: size, seed: invalidSeed)) { error in
            if let sodiumError = error as? SodiumError {
                XCTAssertEqual(sodiumError, .invalidSeedLength("Seed must be \(randomBytes.seedBytes) bytes long"), "Incorrect error for invalid seed length")
            } else {
                XCTFail("Unexpected error type")
            }
        }
    }
}
