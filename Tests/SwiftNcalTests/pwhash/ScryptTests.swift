import XCTest

@testable import SwiftNcal

class ScryptTests: XCTestCase {
    let scrypt = Scrypt()
    let sodium = Sodium()
    let password = "password".data(using: .utf8)!
    let salt = Data(repeating: 0, count: 16)  // 16 bytes salt
    let opsLimit = 3
    let memLimit = 1 << 12  // 4 MB

    func testScryptKdf() throws {
        let derivedKey = try scrypt.kdf(
            size: 32,
            password: password,
            salt: Data(repeating: 0, count: scrypt.saltBytes),
            opsLimit: scrypt.opsLimitMin,
            memLimit: scrypt.memLimitMin
        )
        XCTAssertEqual(derivedKey.count, 32, "Derived key length mismatch")
    }

    func testScryptKdfWithInvalidSalt() throws {
        let invalidSalt = Data(repeating: 0, count: scrypt.saltBytes - 1)  // Invalid salt length
        XCTAssertThrowsError(
            try scrypt.kdf(
                size: 32, password: password, salt: invalidSalt, opsLimit: opsLimit,
                memLimit: memLimit), "Expected error for invalid salt length")
    }

    func testScryptKdfWithInvalidOpsLimit() throws {
        let invalidOpsLimit = 0  // Invalid ops limit
        XCTAssertThrowsError(
            try scrypt.kdf(
                size: 32,
                password: password,
                salt: Data(repeating: 0, count: scrypt.saltBytes),
                opsLimit: invalidOpsLimit,
                memLimit: memLimit), "Expected error for invalid ops limit")
    }

    func testScryptKdfWithInvalidMemLimit() throws {
        let invalidMemLimit = 0  // Invalid memory limit
        XCTAssertThrowsError(
            try scrypt.kdf(
                size: 32,
                password: password,
                salt: Data(repeating: 0, count: scrypt.saltBytes),
                opsLimit: opsLimit,
                memLimit: invalidMemLimit), "Expected error for invalid memory limit")
    }

    func testScryptStr() throws {
        let passwordHash = try scrypt.str(
            password: password, opsLimit: opsLimit, memLimit: memLimit)
        XCTAssertEqual(
            String(passwordHash.prefix(scrypt.strPrefix.count)), scrypt.strPrefix,
            "Password hash prefix mismatch")
    }

    func testScryptVerify() throws {
        let passwordHash = try scrypt.str(
            password: password, opsLimit: opsLimit, memLimit: memLimit
        ).data(using: .utf8)!
        let isValid = try scrypt.verify(passwordHash: passwordHash, password: password)
        XCTAssertTrue(isValid, "Password verification failed")
    }

    func testScryptVerifyWithInvalidPassword() throws {
        let passwordHash = try scrypt.str(
            password: password,
            opsLimit: scrypt.opsLimitMin,
            memLimit: scrypt.memLimitMin
        ).data(using: .utf8)!
        let invalidPassword = "wrongpassword".data(using: .utf8)!
        let isValid = try scrypt.verify(passwordHash: passwordHash, password: invalidPassword)
        XCTAssertFalse(isValid, "Password verification should fail for invalid password")
    }

    func testScryptVerifyWithInvalidHash() throws {
        let invalidHash = "invalidhash".data(using: .utf8)!
        XCTAssertThrowsError(
            try scrypt.verify(passwordHash: invalidHash, password: password),
            "Expected error for invalid hash")
    }
}
