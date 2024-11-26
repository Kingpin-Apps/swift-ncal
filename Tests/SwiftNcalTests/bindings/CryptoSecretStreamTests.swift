import Clibsodium
import XCTest

@testable import SwiftNcal

class CryptoSecretStreamTests: XCTestCase {
    let cryptoSecretStream = SwiftNcal().cryptoSecretStream

    func testKeygen() {
        let key = cryptoSecretStream.xchacha20poly1305Keygen()
        XCTAssertEqual(key.count, cryptoSecretStream.xchacha20poly1305Keybytes, "Generated key length mismatch")
    }

    func testInitPushAndPull() throws {
        let key = cryptoSecretStream.xchacha20poly1305Keygen()
        let statePush = CryptoSecretstreamXchacha20poly1305State()
        let statePull = CryptoSecretstreamXchacha20poly1305State()

        let header = try cryptoSecretStream.xchacha20poly1305InitPush(state: statePush, key: key)
        XCTAssertEqual(header.count, cryptoSecretStream.xchacha20poly1305Headerbytes, "Header length mismatch")

        try cryptoSecretStream.xchacha20poly1305InitPull(state: statePull, header: header, key: key)
    }

    func testPushAndPull() throws {
        let key = cryptoSecretStream.xchacha20poly1305Keygen()
        let statePush = CryptoSecretstreamXchacha20poly1305State()
        let statePull = CryptoSecretstreamXchacha20poly1305State()

        let header = try cryptoSecretStream.xchacha20poly1305InitPush(state: statePush, key: key)
        try cryptoSecretStream.xchacha20poly1305InitPull(state: statePull, header: header, key: key)

        let message = "Hello, World!".data(using: .utf8)!
        let additionalData = "Additional data".data(using: .utf8)
        let tag: UInt8 = cryptoSecretStream.xchacha20poly1305TagMessage

        let ciphertext = try cryptoSecretStream.xchacha20poly1305Push(state: statePush, message: message, additionalData: additionalData, tag: tag)
        let (decryptedMessage, decryptedTag) = try cryptoSecretStream.xchacha20poly1305Pull(state: statePull, ciphertext: ciphertext, additionalData: additionalData)

        XCTAssertEqual(message, decryptedMessage, "Decrypted message does not match the original message")
        XCTAssertEqual(tag, UInt8(decryptedTag), "Decrypted tag does not match the original tag")
    }

    func testRekey() throws {
        let key = cryptoSecretStream.xchacha20poly1305Keygen()
        let statePush = CryptoSecretstreamXchacha20poly1305State()

        _ = try cryptoSecretStream.xchacha20poly1305InitPush(state: statePush, key: key)
        cryptoSecretStream.xchacha20poly1305Rekey(state: statePush)
    }

    func testInitPushWithInvalidKey() throws {
        let key = Data(repeating: 0, count: cryptoSecretStream.xchacha20poly1305Keybytes - 1) // Invalid key length
        let statePush = CryptoSecretstreamXchacha20poly1305State()

        XCTAssertThrowsError(try cryptoSecretStream.xchacha20poly1305InitPush(state: statePush, key: key), "Expected error for invalid key length")
    }

    func testInitPullWithInvalidHeader() throws {
        let key = cryptoSecretStream.xchacha20poly1305Keygen()
        let statePull = CryptoSecretstreamXchacha20poly1305State()
        let header = Data(repeating: 0, count: cryptoSecretStream.xchacha20poly1305Headerbytes - 1) // Invalid header length

        XCTAssertThrowsError(try cryptoSecretStream.xchacha20poly1305InitPull(state: statePull, header: header, key: key), "Expected error for invalid header length")
    }
}
