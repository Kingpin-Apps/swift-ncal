import XCTest
@testable import SwiftNcal

class Argon2Tests: XCTestCase {
    let argon2 = Argon2()
    let sodium = Sodium()
    let password = "password".data(using: .utf8)!
    let salt = Data(repeating: 0, count: 16) // 16 bytes salt
    let opsLimit = 3
    let memLimit = 1 << 12 // 4 MB

    func testArgon2Verify() throws {
        let passwordHash = try sodium.cryptoPwHash.strAlg(
            passwd: password,
            opslimit: sodium.cryptoPwHash.argon2iOpslimitMin,
            memlimit: sodium.cryptoPwHash.argon2iMemlimitMin,
            alg: argon2.algArgon2i13
        )
        let isValid = try argon2.verify(passwordHash: passwordHash, password: password)
        XCTAssertTrue(isValid, "Password verification failed")
    }

    func testArgon2VerifyWithInvalidPassword() throws {
        let passwordHash = try sodium.cryptoPwHash.strAlg(
            passwd: password,
            opslimit: sodium.cryptoPwHash.argon2iOpslimitMin,
            memlimit: sodium.cryptoPwHash.argon2iMemlimitMin,
            alg: argon2.algArgon2i13
        )
        let invalidPassword = "wrongpassword".data(using: .utf8)!
        let isValid = try argon2.verify(passwordHash: passwordHash, password: invalidPassword)
        XCTAssertFalse(isValid, "Password verification should fail for invalid password")
    }

    func testArgon2VerifyWithInvalidHash() throws {
        let invalidHash = Data(repeating: 0, count: 129)
        XCTAssertThrowsError(try argon2.verify(passwordHash: invalidHash, password: password), "Expected error for invalid hash")
    }
}
