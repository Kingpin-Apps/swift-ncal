import XCTest

@testable import SwiftNcal

class SodiumErrorTests: XCTestCase {

    func testSodiumErrorEquatable() {
        XCTAssertEqual(
            SodiumError.badSignatureError("error"), SodiumError.badSignatureError("error"))
        XCTAssertNotEqual(
            SodiumError.badSignatureError("error1"), SodiumError.badSignatureError("error2"))

        XCTAssertEqual(SodiumError.cryptoError("error"), SodiumError.cryptoError("error"))
        XCTAssertNotEqual(SodiumError.cryptoError("error1"), SodiumError.cryptoError("error2"))

        XCTAssertEqual(SodiumError.cryptPrefixError("error"), SodiumError.cryptPrefixError("error"))
        XCTAssertNotEqual(
            SodiumError.cryptPrefixError("error1"), SodiumError.cryptPrefixError("error2"))

        XCTAssertEqual(SodiumError.invalidKeyError("error"), SodiumError.invalidKeyError("error"))
        XCTAssertNotEqual(
            SodiumError.invalidKeyError("error1"), SodiumError.invalidKeyError("error2"))

        XCTAssertEqual(
            SodiumError.invalidSeedLength("error"), SodiumError.invalidSeedLength("error"))
        XCTAssertNotEqual(
            SodiumError.invalidSeedLength("error1"), SodiumError.invalidSeedLength("error2"))

        XCTAssertEqual(SodiumError.runtimeError("error"), SodiumError.runtimeError("error"))
        XCTAssertNotEqual(SodiumError.runtimeError("error1"), SodiumError.runtimeError("error2"))

        XCTAssertEqual(SodiumError.typeError("error"), SodiumError.typeError("error"))
        XCTAssertNotEqual(SodiumError.typeError("error1"), SodiumError.typeError("error2"))

        XCTAssertEqual(SodiumError.unavailableError("error"), SodiumError.unavailableError("error"))
        XCTAssertNotEqual(
            SodiumError.unavailableError("error1"), SodiumError.unavailableError("error2"))

        XCTAssertEqual(SodiumError.valueError("error"), SodiumError.valueError("error"))
        XCTAssertNotEqual(SodiumError.valueError("error1"), SodiumError.valueError("error2"))
    }

    func testEnsureFunction() {
        XCTAssertNoThrow(try ensure(true, raising: .runtimeError("This should not throw")))

        XCTAssertThrowsError(try ensure(false, raising: .runtimeError("This should throw"))) {
            error in
            XCTAssertEqual(error as? SodiumError, SodiumError.runtimeError("This should throw"))
        }

        XCTAssertThrowsError(try ensure(false, raising: .valueError("Value error"))) { error in
            XCTAssertEqual(error as? SodiumError, SodiumError.valueError("Value error"))
        }

        XCTAssertThrowsError(try ensure(false, raising: .cryptoError("Crypto error"))) { error in
            XCTAssertEqual(error as? SodiumError, SodiumError.cryptoError("Crypto error"))
        }
    }
}
