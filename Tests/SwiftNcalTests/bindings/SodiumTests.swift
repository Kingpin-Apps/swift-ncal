import XCTest

@testable import SwiftNcal

class SodiumTests: XCTestCase {
    func testSodiumInit() {
        let sodium = Sodium()
        XCTAssertNotNil(sodium, "Sodium init failed")
    }
}
