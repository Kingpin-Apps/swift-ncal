import XCTest

@testable import SwiftNcal

class CryptoGenericHashTests: XCTestCase {
    let sodium = Sodium()
    func testBlake2bSaltPersonal() throws {
        let cryptoGenericHash = sodium.cryptoGenericHash

        let message = "Hello, World!".data(using: .utf8)!
        let salt = "somesalt".data(using: .utf8)!
        let person = "someperson".data(using: .utf8)!
        let digestSize = cryptoGenericHash.bytes

        let hash = try cryptoGenericHash.blake2bSaltPersonal(
            data: message, digestSize: digestSize, salt: salt, person: person)

        XCTAssertEqual(hash.count, digestSize, "Hash length mismatch")
    }

    func testBlake2bInit() throws {
        let cryptoGenericHash = sodium.cryptoGenericHash

        let key = "supersecretkey".data(using: .utf8)!
        let salt = "somesalt".data(using: .utf8)!
        let person = "someperson".data(using: .utf8)!
        let digestSize = cryptoGenericHash.bytes

        let state = try cryptoGenericHash.blake2bInit(
            key: key, salt: salt, person: person, digestSize: digestSize)

        XCTAssertEqual(state.digestSize, digestSize, "Digest size mismatch")
    }

    func testBlake2bUpdate() throws {
        let cryptoGenericHash = sodium.cryptoGenericHash

        let key = "supersecretkey".data(using: .utf8)!
        let salt = "somesalt".data(using: .utf8)!
        let person = "someperson".data(using: .utf8)!
        let digestSize = cryptoGenericHash.bytes
        let message = "Hello, World!".data(using: .utf8)!

        let state = try cryptoGenericHash.blake2bInit(
            key: key, salt: salt, person: person, digestSize: digestSize)
        try cryptoGenericHash.blake2bUpdate(state: state, data: message)

        XCTAssertEqual(
            state.statebuf.count,
            cryptoGenericHash.stateBytes,
            "Hash length mismatch"
        )
    }

    func testBlake2bFinal() throws {
        let cryptoGenericHash = sodium.cryptoGenericHash

        let key = "supersecretkey".data(using: .utf8)!
        let salt = "somesalt".data(using: .utf8)!
        let person = "someperson".data(using: .utf8)!
        let digestSize = cryptoGenericHash.bytes
        let message = "Hello, World!".data(using: .utf8)!

        let state = try cryptoGenericHash.blake2bInit(
            key: key, salt: salt, person: person, digestSize: digestSize)
        try cryptoGenericHash.blake2bUpdate(state: state, data: message)

        let hash = try cryptoGenericHash.blake2bFinal(state: state)

        XCTAssertEqual(hash.count, cryptoGenericHash.bytesMax, "Hash length mismatch")
    }
}
