import XCTest

@testable import SwiftNcal

class Argon2idTests: XCTestCase {
    let argon2id = Argon2id()
    let sodium = Sodium()
    let password = "password".data(using: .utf8)!
    let salt = Data(repeating: 0, count: 16)  // 16 bytes salt
    let opsLimit = 3
    let memLimit = 1 << 12  // 4 MB

    func testArgon2idVerify() throws {
        let passwordHash = try sodium.cryptoPwHash.strAlg(
            passwd: password,
            opslimit: sodium.cryptoPwHash.argon2idOpslimitMin,
            memlimit: sodium.cryptoPwHash.argon2idMemlimitMin,
            alg: argon2id.alg
        )
        let isValid = try argon2id.verify(passwordHash: passwordHash, password: password)
        XCTAssertTrue(isValid, "Password verification failed")
    }

    func testArgon2idVerifyWithInvalidPassword() throws {
        let passwordHash = try sodium.cryptoPwHash.strAlg(
            passwd: password,
            opslimit: sodium.cryptoPwHash.argon2idOpslimitMin,
            memlimit: sodium.cryptoPwHash.argon2idMemlimitMin,
            alg: argon2id.alg
        )
        let invalidPassword = "wrongpassword".data(using: .utf8)!
        let isValid = try argon2id.verify(passwordHash: passwordHash, password: invalidPassword)
        XCTAssertFalse(isValid, "Password verification should fail for invalid password")
    }

    func testArgon2idVerifyWithInvalidHash() throws {
        let invalidHash = Data(repeating: 0, count: 129)  // Invalid hash length
        XCTAssertThrowsError(
            try argon2id.verify(passwordHash: invalidHash, password: password),
            "Expected error for invalid hash")
    }

    func testArgon2idKdf() throws {
        let derivedKey = try argon2id.kdf(
            size: 32,
            password: password,
            salt: salt,
            opsLimit: sodium.cryptoPwHash.argon2idOpslimitMin,
            memLimit: sodium.cryptoPwHash.argon2idMemlimitMin
        )
        XCTAssertEqual(derivedKey.count, 32, "Derived key length mismatch")
    }

    func testArgon2idKdfWithInvalidSalt() throws {
        let invalidSalt = Data(repeating: 0, count: argon2id.saltBytes - 1)  // Invalid salt length
        XCTAssertThrowsError(
            try argon2id.kdf(
                size: 32,
                password: password,
                salt: invalidSalt,
                opsLimit: sodium.cryptoPwHash.argon2idOpslimitMin,
                memLimit: sodium.cryptoPwHash.argon2idMemlimitMin), "Expected error for invalid salt length")
    }

    func testArgon2idKdfWithInvalidOpsLimit() throws {
        let invalidOpsLimit = 0  // Invalid ops limit
        XCTAssertThrowsError(
            try argon2id.kdf(
                size: 32,
                password: password,
                salt: salt,
                opsLimit: invalidOpsLimit,
                memLimit: sodium.cryptoPwHash.argon2idMemlimitMin), "Expected error for invalid ops limit")
    }

    func testArgon2idKdfWithInvalidMemLimit() throws {
        let invalidMemLimit = 0  // Invalid memory limit
        XCTAssertThrowsError(
            try argon2id.kdf(
                size: 32,
                password: password,
                salt: salt,
                opsLimit: sodium.cryptoPwHash.argon2idOpslimitMin,
                memLimit: invalidMemLimit), "Expected error for invalid memory limit")
    }
}
