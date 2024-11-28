import XCTest
import Foundation
@testable import SwiftNcal

final class CryptoUtilityTests: XCTestCase {
    let utils = Sodium().utils

    // MARK: - sodiumMemcmp Tests
    
    func testSodiumMemcmpIdenticalData() {
        let data1 = Data([0x01, 0x02, 0x03])
        let data2 = Data([0x01, 0x02, 0x03])
        
        XCTAssertTrue(utils.sodiumMemcmp(data1, data2), "sodiumMemcmp failed to recognize identical data")
    }
    
    func testSodiumMemcmpDifferentData() {
        let data1 = Data([0x01, 0x02, 0x03])
        let data2 = Data([0x01, 0x02, 0x04])
        
        XCTAssertFalse(utils.sodiumMemcmp(data1, data2), "sodiumMemcmp failed to distinguish different data")
    }
    
    func testSodiumMemcmpDifferentLengths() {
        let data1 = Data([0x01, 0x02])
        let data2 = Data([0x01, 0x02, 0x03])
        
        XCTAssertFalse(utils.sodiumMemcmp(data1, data2), "sodiumMemcmp failed to handle inputs of different lengths")
    }
    
    // MARK: - sodiumPad Tests
    
    func testSodiumPad() throws {
        let input = Data([0x01, 0x02, 0x03])
        let blocksize = 8
        let padded = try utils.sodiumPad(input, blocksize: blocksize)
        
        XCTAssertEqual(padded.count % blocksize, 0, "Padded data is not a multiple of the block size")
        XCTAssertTrue(padded.starts(with: input), "Padded data does not start with the input data")
    }
    
    func testSodiumPadInvalidBlocksize() {
        let input = Data([0x01, 0x02, 0x03])
        
        XCTAssertThrowsError(try utils.sodiumPad(input, blocksize: 0), "sodiumPad did not throw error for invalid block size")
    }
    
    // MARK: - sodiumUnpad Tests
    
    func testSodiumUnpad() throws {
        let input = Data([0x01, 0x02, 0x03, 0x80, 0x00, 0x00, 0x00, 0x00])
        let blocksize = 8
        let unpadded = try utils.sodiumUnpad(input, blocksize: blocksize)
        
        XCTAssertEqual(unpadded, Data([0x01, 0x02, 0x03]), "sodiumUnpad did not correctly remove padding")
    }
    
    func testSodiumUnpadInvalidPadding() {
        let input = Data([0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00])
        let blocksize = 8
        
        XCTAssertThrowsError(try utils.sodiumUnpad(input, blocksize: blocksize), "sodiumUnpad did not throw error for invalid padding")
    }
    
    // MARK: - sodiumIncrement Tests
    
    func testSodiumIncrement() {
        let input = Data([0xFF, 0x00, 0x01])
        let incremented = utils.sodiumIncrement(input)
        
        XCTAssertEqual(incremented, Data([0x00, 0x01, 0x01]), "sodiumIncrement did not produce the expected result")
    }
    
    // MARK: - sodiumAdd Tests
    
    func testSodiumAdd() {
        let data1 = Data([0x01, 0x02, 0x03])
        let data2 = Data([0x04, 0x05, 0x06])
        let result = utils.sodiumAdd(data1, data2)
        
        XCTAssertEqual(result, Data([0x05, 0x07, 0x09]), "sodiumAdd did not produce the expected result")
    }
    
    func testSodiumAddWithCarry() {
        let data1 = Data([0xFF, 0xFF, 0xFF])
        let data2 = Data([0x01, 0x00, 0x00])
        let result = utils.sodiumAdd(data1, data2)
        
        XCTAssertEqual(result, Data([0x00, 0x00, 0x00]), "sodiumAdd did not correctly handle carry-over")
    }
}
