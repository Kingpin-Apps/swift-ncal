import Foundation
import XCTest

@testable import SwiftNcal

class RandomBytesTests: XCTestCase {
    let randomBytes = Sodium().randomBytes

    func testRandomBytesGeneratesCorrectSize() {
        let size = 32
        let randomData = randomBytes.randomBytes(size: size)

        XCTAssertEqual(
            randomData.count, size, "randomBytes did not generate the correct number of bytes")
    }

    func testRandomBytesGeneratesUniqueValues() {
        let size = 32
        let randomData1 = randomBytes.randomBytes(size: size)
        let randomData2 = randomBytes.randomBytes(size: size)

        XCTAssertNotEqual(
            randomData1, randomData2, "randomBytes generated identical values for different calls")
    }

    func testRandomBytesBufDeterministicGeneratesCorrectSize() throws {
        let size = 32
        let seed = Data(repeating: 1, count: randomBytes.seedBytes)

        let deterministicData = try randomBytes.bufDeterministic(size: size, seed: seed)

        XCTAssertEqual(
            deterministicData.count, size,
            "randomBytesBufDeterministic did not generate the correct number of bytes")
    }

    func testRandomBytesBufDeterministicWithSameSeedProducesSameOutput() throws {
        let size = 32
        let seed = Data(repeating: 1, count: randomBytes.seedBytes)

        let deterministicData1 = try randomBytes.bufDeterministic(size: size, seed: seed)
        let deterministicData2 = try randomBytes.bufDeterministic(size: size, seed: seed)

        XCTAssertEqual(
            deterministicData1, deterministicData2,
            "randomBytesBufDeterministic with the same seed produced different outputs")
    }

    func testRandomBytesBufDeterministicWithDifferentSeedsProducesDifferentOutput() throws {
        let size = 32
        let seed1 = Data(repeating: 1, count: randomBytes.seedBytes)
        let seed2 = Data(repeating: 2, count: randomBytes.seedBytes)

        let deterministicData1 = try randomBytes.bufDeterministic(size: size, seed: seed1)
        let deterministicData2 = try randomBytes.bufDeterministic(size: size, seed: seed2)

        XCTAssertNotEqual(
            deterministicData1, deterministicData2,
            "randomBytesBufDeterministic with different seeds produced the same output")
    }

    func testRandomBytesBufDeterministicThrowsErrorForInvalidSeedLength() {
        let size = 32
        let invalidSeed = Data(repeating: 1, count: randomBytes.seedBytes - 1)  // Invalid seed length

        XCTAssertThrowsError(try randomBytes.bufDeterministic(size: size, seed: invalidSeed)) {
            error in
            if let sodiumError = error as? SodiumError {
                XCTAssertEqual(
                    sodiumError,
                    .invalidSeedLength("Seed must be \(randomBytes.seedBytes) bytes long"),
                    "Incorrect error for invalid seed length")
            } else {
                XCTFail("Unexpected error type")
            }
        }
    }

    func testRandom() {
        let randomValue = randomBytes.random()
        XCTAssertTrue(randomValue >= 0 && randomValue <= 0xffff_ffff, "Random value out of bounds")
    }

    func testUniform() {
        let upperBound: UInt32 = 100
        let uniformValue = randomBytes.uniform(upperBound: upperBound)
        XCTAssertTrue(uniformValue >= 0 && uniformValue < upperBound, "Uniform value out of bounds")
    }

    func testUniformWithPowerOfTwoUpperBound() {
        let upperBound: UInt32 = 128
        let uniformValue = randomBytes.uniform(upperBound: upperBound)
        XCTAssertTrue(
            uniformValue >= 0 && uniformValue < upperBound,
            "Uniform value out of bounds for power of two upper bound")
    }

    func testUniformWithNonPowerOfTwoUpperBound() {
        let upperBound: UInt32 = 150
        let uniformValue = randomBytes.uniform(upperBound: upperBound)
        XCTAssertTrue(
            uniformValue >= 0 && uniformValue < upperBound,
            "Uniform value out of bounds for non-power of two upper bound")
    }
}
