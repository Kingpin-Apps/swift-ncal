import XCTest

@testable import SwiftNcal

class Blake2bTests: XCTestCase {
    let sodium = Sodium()
    let message = "The quick brown fox jumps over the lazy dog".data(using: .utf8)!
    let key = Data(repeating: 0, count: 16)  // 16 bytes key
    let salt = Data(repeating: 0, count: 16)  // 16 bytes salt
    let person = Data(repeating: 0, count: 16)  // 16 bytes personalization
    let hashlib = Hashlib()
    let password = "password".data(using: .utf8)!
    let n = 16
    let r = 8
    let p = 1
    let maxmem = 1 << 25
    let dklen = 64
    
    func testBlake2bInit() throws {
        let blake2b = try Blake2b(
            data: message,
            key: key,
            salt: salt,
            person: person
        )
        XCTAssertNotNil(blake2b, "Blake2b initialization failed")
    }

    func testBlake2bUpdate() throws {
        let blake2b = try Blake2b(digestSize: sodium.cryptoGenericHash.bytes)
        try blake2b.update(data: message)
        let digest = try blake2b.digest()
        XCTAssertEqual(digest.count, 64, "Blake2b update digest size mismatch")
    }

    func testBlake2bDigest() throws {
        let blake2b = try Blake2b(
            data: message,
            digestSize: sodium.cryptoGenericHash.bytes,
            key: key,
            salt: salt,
            person: person
        )
        let digest = try blake2b.digest()
        XCTAssertEqual(digest.count, 64, "Blake2b digest size mismatch")
    }

    func testBlake2bHexdigest() throws {
        let blake2b = try Blake2b(
            data: message,
            digestSize: sodium.cryptoGenericHash.bytes,
            key: key,
            salt: salt,
            person: person
        )
        
        let hexdigest = try blake2b.hexdigest()
        XCTAssertNotNil(hexdigest, "Blake2b hexdigest failed")
    }

    func testBlake2bCopy() throws {
        let blake2b = try Blake2b(
            data: message, digestSize: 32, key: key, salt: salt, person: person)
        let blake2bCopy = try blake2b.copy()
        XCTAssertEqual(try blake2b.hexdigest(), try blake2bCopy.hexdigest(), "Blake2b copy digest mismatch")
    }

    func testBlake2bReduce() {
        let blake2b = try! Blake2b(
            data: message, digestSize: 32, key: key, salt: salt, person: person)
        XCTAssertThrowsError(try blake2b.reduce(), "Expected fatalError for reduce method")
    }
    
    func testScrypt() throws {
        let derivedKey = try hashlib.scrypt(
            password: password,
            salt: salt,
            n: n,
            r: r,
            p: p,
            maxmem: sodium.cryptoPwHash.scryptMaxMem,
            dklen: dklen)
        XCTAssertEqual(derivedKey.count, dklen, "Scrypt derived key length mismatch")
    }

    func testScryptWithDefaultParameters() throws {
        let derivedKey = try hashlib.scrypt(password: password)
        XCTAssertEqual(derivedKey.count, dklen, "Scrypt derived key length mismatch with default parameters")
    }

    func testScryptWithInvalidN() throws {
        let invalidN = 0 // Invalid n parameter
        XCTAssertThrowsError(try hashlib.scrypt(password: password, salt: salt, n: invalidN, r: r, p: p, maxmem: maxmem, dklen: dklen), "Expected error for invalid n parameter")
    }

    func testScryptWithInvalidR() throws {
        let invalidR = 0 // Invalid r parameter
        XCTAssertThrowsError(try hashlib.scrypt(password: password, salt: salt, n: n, r: invalidR, p: p, maxmem: maxmem, dklen: dklen), "Expected error for invalid r parameter")
    }

    func testScryptWithInvalidP() throws {
        let invalidP = 0 // Invalid p parameter
        XCTAssertThrowsError(try hashlib.scrypt(password: password, salt: salt, n: n, r: r, p: invalidP, maxmem: maxmem, dklen: dklen), "Expected error for invalid p parameter")
    }

    func testScryptWithInvalidMaxmem() throws {
        let invalidMaxmem = 0 // Invalid maxmem parameter
        XCTAssertThrowsError(try hashlib.scrypt(password: password, salt: salt, n: n, r: r, p: p, maxmem: invalidMaxmem, dklen: dklen), "Expected error for invalid maxmem parameter")
    }
}
