import XCTest

@testable import SwiftNcal

class Argon2iTests: XCTestCase {
    let argon2i = Argon2i()
    let sodium = Sodium()
    let password = "password".data(using: .utf8)!
    let salt = Data(repeating: 0, count: 16)  // 16 bytes salt
    let opsLimit = 3
    let memLimit = 1 << 12  // 4 MB

    func testArgon2iVerify() throws {
        let passwordHash = try sodium.cryptoPwHash.strAlg(
            passwd: password,
            opslimit: sodium.cryptoPwHash.argon2iOpslimitMin,
            memlimit: sodium.cryptoPwHash.argon2iMemlimitMin,
            alg: argon2i.alg
        )
        let isValid = try argon2i.verify(passwordHash: passwordHash, password: password)
        XCTAssertTrue(isValid, "Password verification failed")
    }

    func testArgon2iVerifyWithInvalidPassword() throws {
        let passwordHash = try sodium.cryptoPwHash.strAlg(
            passwd: password,
            opslimit: sodium.cryptoPwHash.argon2iOpslimitMin,
            memlimit: sodium.cryptoPwHash.argon2iMemlimitMin,
            alg: argon2i.alg
        )
        let invalidPassword = "wrongpassword".data(using: .utf8)!
        let isValid = try argon2i.verify(passwordHash: passwordHash, password: invalidPassword)
        XCTAssertFalse(isValid, "Password verification should fail for invalid password")
    }

    func testArgon2iVerifyWithInvalidHash() throws {
        let invalidHash = Data(repeating: 0, count: 129)  // Invalid hash length
        XCTAssertThrowsError(
            try argon2i.verify(passwordHash: invalidHash, password: password),
            "Expected error for invalid hash")
    }

    func testArgon2iKdf() throws {
        let derivedKey = try argon2i.kdf(
            size: 32, password: password, salt: salt)
        XCTAssertEqual(derivedKey.count, 32, "Derived key length mismatch")
    }

    func testArgon2iKdfWithInvalidSalt() throws {
        let invalidSalt = Data(repeating: 0, count: argon2i.saltBytes - 1)  // Invalid salt length
        XCTAssertThrowsError(
            try argon2i.kdf(
                size: 32, password: password, salt: invalidSalt, opsLimit: opsLimit,
                memLimit: memLimit), "Expected error for invalid salt length")
    }

    func testArgon2iKdfWithInvalidOpsLimit() throws {
        let invalidOpsLimit = 0  // Invalid ops limit
        XCTAssertThrowsError(
            try argon2i.kdf(
                size: 32, password: password, salt: salt, opsLimit: invalidOpsLimit,
                memLimit: memLimit), "Expected error for invalid ops limit")
    }

    func testArgon2iKdfWithInvalidMemLimit() throws {
        let invalidMemLimit = 0  // Invalid memory limit
        XCTAssertThrowsError(
            try argon2i.kdf(
                size: 32, password: password, salt: salt, opsLimit: opsLimit,
                memLimit: invalidMemLimit), "Expected error for invalid memory limit")
    }
}
