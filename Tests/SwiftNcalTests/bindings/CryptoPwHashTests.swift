import Clibsodium
import XCTest

@testable import SwiftNcal

class CryptoPwHashTests: XCTestCase {
    let cryptoPwHash = Sodium().cryptoPwHash

    func testScryptsalsa208sha256LL() throws {
        let passwd = "password".data(using: .utf8)!
        let salt = Data(repeating: 0, count: cryptoPwHash.scryptsalsa208sha256Saltbytes)
        let n = 16384
        let r = 8
        let p = 1
        let dklen = 64

        let derivedKey = try cryptoPwHash.scryptsalsa208sha256LL(
            passwd: passwd, salt: salt, n: n, r: r, p: p, dklen: dklen)

        XCTAssertEqual(derivedKey.count, dklen, "Derived key length mismatch")
    }

    func testScryptsalsa208sha256Str() throws {
        let passwd = "password".data(using: .utf8)!
        let opslimit = cryptoPwHash.scryptOpslimitInteractive
        let memlimit = cryptoPwHash.scryptMemlimitInteractive

        let hashStr = try cryptoPwHash.scryptsalsa208sha256Str(
            passwd: passwd, opsLimit: opslimit, memLimit: memlimit)

        XCTAssertEqual(
            hashStr.count, cryptoPwHash.scryptStrbytes - 1, "Hash string length mismatch")
    }

    func testScryptsalsa208sha256StrVerify() throws {
        let passwd = "password".data(using: .utf8)!
        let opslimit = cryptoPwHash.scryptOpslimitInteractive
        let memlimit = cryptoPwHash.scryptMemlimitInteractive

        let hashStr = try cryptoPwHash.scryptsalsa208sha256Str(
            passwd: passwd, opsLimit: opslimit, memLimit: memlimit)
        let hashData = hashStr.data(using: .utf8)!

        let isValid = try cryptoPwHash.scryptsalsa208sha256StrVerify(
            passwd_hash: hashData, passwd: passwd)

        XCTAssertTrue(isValid, "Password verification failed")
    }

    func testCryptoPwhashAlg() throws {
        let passwd = "password".data(using: .utf8)!
        let salt = Data(repeating: 0, count: cryptoPwHash.saltBytes)
        let opslimit = cryptoPwHash.argon2iOpslimitInteractive
        let memlimit = cryptoPwHash.argon2iMemlimitInteractive
        let alg = cryptoPwHash.algArgon2i13
        let outlen = 64

        let derivedKey = try cryptoPwHash.alg(
            outlen: outlen, passwd: passwd, salt: salt, opslimit: opslimit, memlimit: memlimit,
            alg: alg)

        XCTAssertEqual(derivedKey.count, outlen, "Derived key length mismatch")
    }

    func testStrAlg() throws {
        let passwd = "password".data(using: .utf8)!
        let opslimit = cryptoPwHash.argon2iOpslimitInteractive
        let memlimit = cryptoPwHash.argon2iMemlimitInteractive
        let alg = cryptoPwHash.algArgon2i13

        let hashData = try cryptoPwHash.strAlg(
            passwd: passwd, opslimit: opslimit, memlimit: memlimit, alg: alg)

        XCTAssertEqual(hashData.count, 128, "Hash data length mismatch")
    }

    func testStrVerify() throws {
        let passwd = "password".data(using: .utf8)!
        let opslimit = cryptoPwHash.argon2iOpslimitInteractive
        let memlimit = cryptoPwHash.argon2iMemlimitInteractive
        let alg = cryptoPwHash.algArgon2i13

        let hashData = try cryptoPwHash.strAlg(
            passwd: passwd, opslimit: opslimit, memlimit: memlimit, alg: alg)

        let isValid = try cryptoPwHash.strVerify(passwd_hash: hashData, passwd: passwd)

        XCTAssertTrue(isValid, "Password verification failed")
    }
}
