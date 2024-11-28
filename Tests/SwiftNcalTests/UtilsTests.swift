import XCTest

@testable import SwiftNcal

class EncryptedMessageTests: XCTestCase {
    let nonce = Data(repeating: 0, count: 24)  // 24 bytes nonce
    let ciphertext = Data(repeating: 1, count: 64)  // 64 bytes ciphertext

    func testEncryptedMessageInit() {
        let combined = nonce + ciphertext
        let encryptedMessage = EncryptedMessage(
            nonce: nonce, ciphertext: ciphertext, combined: combined)
        XCTAssertEqual(encryptedMessage.getNonce, nonce, "EncryptedMessage nonce mismatch")
        XCTAssertEqual(
            encryptedMessage.getCiphertext, ciphertext, "EncryptedMessage ciphertext mismatch")
        XCTAssertEqual(encryptedMessage.getMessage, combined, "EncryptedMessage combined mismatch")
    }

    func testEncryptedMessageFromParts() {
        let combined = nonce + ciphertext
        let encryptedMessage = EncryptedMessage.fromParts(
            nonce: nonce, ciphertext: ciphertext, combined: combined)
        XCTAssertEqual(encryptedMessage.getNonce, nonce, "EncryptedMessage nonce mismatch")
        XCTAssertEqual(
            encryptedMessage.getCiphertext, ciphertext, "EncryptedMessage ciphertext mismatch")
        XCTAssertEqual(encryptedMessage.getMessage, combined, "EncryptedMessage combined mismatch")
    }
}

class StringFixerTests: XCTestCase {
    func testToString() {
        let data = "Hello, World!".data(using: .utf8)!
        let stringFixer = StringFixer()
        let result = stringFixer.toString(data: data)
        XCTAssertEqual(result, "Hello, World!", "StringFixer toString failed")
    }
}

class UtilsTests: XCTestCase {
    func testBytesAsString() {
        let data = Data([0x00, 0x01, 0x02, 0x03])
        let result = bytesAsString(bytesIn: data)
        XCTAssertEqual(result, "00010203", "bytesAsString failed")
    }

    func testRandom() {
        let size = 32
        let randomData = random(size: size)
        XCTAssertEqual(randomData.count, size, "Random data size mismatch")
    }

    func testRandomBytesDeterministic() throws {
        let size = 32
        let seed = Data(repeating: 0, count: 32)
        let deterministicData = try randomBytesDeterministic(size: size, seed: seed)
        XCTAssertEqual(deterministicData.count, size, "Deterministic random data size mismatch")
    }
}
