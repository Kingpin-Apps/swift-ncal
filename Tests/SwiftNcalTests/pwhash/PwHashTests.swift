import XCTest

@testable import SwiftNcal

class PwHashTests: XCTestCase {
    let pwHash = PwHash()
    let password = "password".data(using: .utf8)!
    let salt = Data(repeating: 0, count: 16)  // 16 bytes salt
    let opsLimit = 3
    let memLimit = 1 << 12  // 4 MB

    func testKdfScryptsalsa208sha256() throws {
        let derivedKey = try pwHash.kdfScryptsalsa208sha256(
            size: 32,
            password: password,
            salt: Data(repeating: 0, count: pwHash.scrypt.saltBytes))
        XCTAssertEqual(derivedKey.count, 32, "Derived key length mismatch")
    }

    func testScryptsalsa208sha256Str() throws {
        let passwordHash = try pwHash.scryptsalsa208sha256Str(
            password: password, opsLimit: opsLimit, memLimit: memLimit)
        XCTAssertEqual(
            String(passwordHash.prefix(pwHash.scrypt.strPrefix.count)), pwHash.scrypt.strPrefix,
            "Password hash prefix mismatch")
    }

    func testVerifyScryptsalsa208sha256() throws {
        let passwordHash = try pwHash.scryptsalsa208sha256Str(
            password: password
        ).data(using: .utf8)!
        let isValid = try pwHash.verifyScryptsalsa208sha256(
            passwordHash: passwordHash, password: password)
        XCTAssertTrue(isValid, "Password verification failed")
    }

    func testVerify() throws {
        let passwordHash = try pwHash.scryptsalsa208sha256Str(
            password: password, opsLimit: opsLimit, memLimit: memLimit
        ).data(using: .utf8)!
        let isValid = try pwHash.verify(passwordHash: passwordHash, password: password)
        XCTAssertTrue(isValid, "Password verification failed")
    }

    func testVerifyWithInvalidPassword() throws {
        let passwordHash = try pwHash.scryptsalsa208sha256Str(
            password: password, opsLimit: opsLimit, memLimit: memLimit
        ).data(using: .utf8)!
        let invalidPassword = "wrongpassword".data(using: .utf8)!
        let isValid = try pwHash.verify(passwordHash: passwordHash, password: invalidPassword)
        XCTAssertFalse(isValid, "Password verification should fail for invalid password")
    }

    func testVerifyWithInvalidHash() throws {
        let invalidHash = "invalidhash".data(using: .utf8)!
        XCTAssertThrowsError(
            try pwHash.verify(passwordHash: invalidHash, password: password),
            "Expected error for invalid hash")
    }

    func testVerifyWithArgon2idPrefix() throws {
        let passwordHash = try pwHash.argon2id.str(password: password)
        let isValid = try pwHash.verify(passwordHash: passwordHash, password: password)
        XCTAssertTrue(isValid, "Password verification failed for Argon2id prefix")
    }

    func testVerifyWithArgon2iPrefix() throws {
        let passwordHash = try pwHash.argon2i.str(password: password)
        let isValid = try pwHash.verify(passwordHash: passwordHash, password: password)
        XCTAssertTrue(isValid, "Password verification failed for Argon2i prefix")
    }

    func testVerifyWithScryptPrefix() throws {
        let passwordHash = try pwHash.scrypt.str(password: password).data(using: .utf8)!
        let isValid = try pwHash.verify(passwordHash: passwordHash, password: password)
        XCTAssertTrue(isValid, "Password verification failed for Scrypt prefix")
    }

    func testVerifyWithUnsupportedPrefix() throws {
        let unsupportedHash = "unsupported$hash".data(using: .utf8)!
        XCTAssertThrowsError(
            try pwHash.verify(passwordHash: unsupportedHash, password: password),
            "Expected error for unsupported hash prefix")
    }
}
