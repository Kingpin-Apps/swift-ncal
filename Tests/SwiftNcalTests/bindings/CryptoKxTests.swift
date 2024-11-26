import Clibsodium
import XCTest

@testable import SwiftNcal

class CryptoKxTests: XCTestCase {
    let cryptoKx = SwiftNcal().cryptoKx

    func testKeypair() throws {
        let (publicKey, secretKey) = try cryptoKx.keypair()

        XCTAssertEqual(publicKey.count, cryptoKx.publicKeyBytes, "Public key length mismatch")
        XCTAssertEqual(secretKey.count, cryptoKx.secretKeyBytes, "Secret key length mismatch")
    }

    func testSeedKeypair() throws {
        let seed = Data(repeating: 0, count: cryptoKx.seedBytes)
        let (publicKey, secretKey) = try cryptoKx.seedKeypair(seed: seed)

        XCTAssertEqual(publicKey.count, cryptoKx.publicKeyBytes, "Public key length mismatch")
        XCTAssertEqual(secretKey.count, cryptoKx.secretKeyBytes, "Secret key length mismatch")
    }

    func testClientSessionKeys() throws {
        let (clientPublicKey, clientSecretKey) = try cryptoKx.keypair()
        let (serverPublicKey, _) = try cryptoKx.keypair()

        let (rxKey, txKey) = try cryptoKx.clientSessionKeys(
            clientPublicKey: clientPublicKey,
            clientSecretKey: clientSecretKey,
            serverPublicKey: serverPublicKey
        )

        XCTAssertEqual(rxKey.count, cryptoKx.sessionKeyBytes, "Receive key length mismatch")
        XCTAssertEqual(txKey.count, cryptoKx.sessionKeyBytes, "Transmit key length mismatch")
    }

    func testServerSessionKeys() throws {
        let (serverPublicKey, serverSecretKey) = try cryptoKx.keypair()
        let (clientPublicKey, _) = try cryptoKx.keypair()

        let (rxKey, txKey) = try cryptoKx.serverSessionKeys(
            serverPublicKey: serverPublicKey,
            serverSecretKey: serverSecretKey,
            clientPublicKey: clientPublicKey
        )

        XCTAssertEqual(rxKey.count, cryptoKx.sessionKeyBytes, "Receive key length mismatch")
        XCTAssertEqual(txKey.count, cryptoKx.sessionKeyBytes, "Transmit key length mismatch")
    }
}
