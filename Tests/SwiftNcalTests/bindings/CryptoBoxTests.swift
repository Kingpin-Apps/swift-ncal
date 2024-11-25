import Clibsodium
import XCTest

@testable import SwiftNcal

class CryptoBoxTests: XCTestCase {
    let swiftNcal = SwiftNcal()

    // Test keypair generation
    func testKeypair() throws {
        let cryptoBox = swiftNcal.cryptoBox
        let keypair = try cryptoBox.keypair()
        XCTAssertEqual(
            keypair.publicKey.count, cryptoBox.publicKeyBytes, "Public key length mismatch")
        XCTAssertEqual(
            keypair.secretKey.count, cryptoBox.secretKeyBytes, "Secret key length mismatch")
    }

    // Test seed-based keypair generation
    func testSeedKeypair() throws {
        let cryptoBox = swiftNcal.cryptoBox
        let seed = Data(repeating: 0x01, count: cryptoBox.seedBytes)
        let keypair = try cryptoBox.seedKeypair(seed: seed)
        XCTAssertEqual(
            keypair.publicKey.count, cryptoBox.publicKeyBytes, "Public key length mismatch")
        XCTAssertEqual(
            keypair.secretKey.count, cryptoBox.secretKeyBytes, "Secret key length mismatch")
    }

    func testBox() throws {
        let cryptoBox = swiftNcal.cryptoBox

        // Generate keypairs
        let A_keypair = try cryptoBox.keypair()
        XCTAssertEqual(A_keypair.publicKey.count, cryptoBox.publicKeyBytes)
        XCTAssertEqual(A_keypair.secretKey.count, cryptoBox.secretKeyBytes)

        let B_keypair = try cryptoBox.keypair()

        // Compute shared keys
        let k1 = try cryptoBox.beforenm(
            publicKey: B_keypair.publicKey, secretKey: A_keypair.secretKey)
        XCTAssertEqual(k1.count, cryptoBox.beforeNmBytes)

        let k2 = try cryptoBox.beforenm(
            publicKey: A_keypair.publicKey, secretKey: B_keypair.secretKey)
        XCTAssertEqual(k1, k2)

        // Encrypt message
        let message = "message".data(using: .utf8)!
        let nonce = Data(repeating: 0x01, count: cryptoBox.nonceBytes)

        let ct1 = try cryptoBox.easyAfternm(message: message, nonce: nonce, sharedKey: k1)
        XCTAssertEqual(ct1.count, message.count + cryptoBox.macBytes)

        let ct2 = try cryptoBox.easy(
            message: message, nonce: nonce, publicKey: B_keypair.publicKey,
            secretKey: A_keypair.secretKey)
        XCTAssertEqual(ct1, ct2)

        // Decrypt message
        let m1 = try cryptoBox.openEasy(
            ciphertext: ct1, nonce: nonce, publicKey: A_keypair.publicKey,
            secretKey: B_keypair.secretKey)
        XCTAssertEqual(m1, message)

        let m2 = try cryptoBox.openEasyAfternm(ciphertext: ct1, nonce: nonce, sharedKey: k1)
        XCTAssertEqual(m2, message)

        // Test decryption failure
        XCTAssertThrowsError(
            try cryptoBox.openEasy(
                ciphertext: message + Data([0x21]), nonce: nonce, publicKey: A_keypair.publicKey,
                secretKey: A_keypair.secretKey)
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }
    }

    func testBoxEasy() throws {
        let cryptoBox = swiftNcal.cryptoBox

        // Generate keypairs
        let A_keypair = try cryptoBox.keypair()
        XCTAssertEqual(A_keypair.publicKey.count, cryptoBox.publicKeyBytes)
        XCTAssertEqual(A_keypair.secretKey.count, cryptoBox.secretKeyBytes)

        let B_keypair = try cryptoBox.keypair()

        // Compute shared keys
        let k1 = try cryptoBox.beforenm(
            publicKey: B_keypair.publicKey, secretKey: A_keypair.secretKey)
        XCTAssertEqual(k1.count, cryptoBox.beforeNmBytes)

        let k2 = try cryptoBox.beforenm(
            publicKey: A_keypair.publicKey, secretKey: B_keypair.secretKey)
        XCTAssertEqual(k1, k2)

        // Encrypt message
        let message = "message".data(using: .utf8)!
        let nonce = Data(repeating: 0x01, count: cryptoBox.nonceBytes)

        let ct1 = try cryptoBox.easyAfternm(message: message, nonce: nonce, sharedKey: k1)
        XCTAssertEqual(ct1.count, message.count + cryptoBox.macBytes)

        let ct2 = try cryptoBox.easy(
            message: message, nonce: nonce, publicKey: B_keypair.publicKey,
            secretKey: A_keypair.secretKey)
        XCTAssertEqual(ct1, ct2)

        // Decrypt message
        let m1 = try cryptoBox.openEasy(
            ciphertext: ct1, nonce: nonce, publicKey: A_keypair.publicKey,
            secretKey: B_keypair.secretKey)
        XCTAssertEqual(m1, message)

        let m2 = try cryptoBox.openEasyAfternm(ciphertext: ct1, nonce: nonce, sharedKey: k1)
        XCTAssertEqual(m2, message)

        // Test decryption failure
        XCTAssertThrowsError(
            try cryptoBox.openEasy(
                ciphertext: message + Data([0x21]), nonce: nonce, publicKey: A_keypair.publicKey,
                secretKey: A_keypair.secretKey)
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }
    }

    func testBoxWrongLengths() throws {
        let cryptoBox = swiftNcal.cryptoBox

        // Generate keypair
        let A_keypair = try cryptoBox.keypair()

        // Test invalid lengths for crypto_box
        XCTAssertThrowsError(
            try cryptoBox.easy(
                message: Data("abc".utf8), nonce: Data([0x00]), publicKey: A_keypair.publicKey,
                secretKey: A_keypair.secretKey)
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }
        XCTAssertThrowsError(
            try cryptoBox.easy(
                message: Data("abc".utf8),
                nonce: Data(repeating: 0x00, count: cryptoBox.nonceBytes), publicKey: Data(),
                secretKey: A_keypair.secretKey)
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }
        XCTAssertThrowsError(
            try cryptoBox.easy(
                message: Data("abc".utf8),
                nonce: Data(repeating: 0x00, count: cryptoBox.nonceBytes),
                publicKey: A_keypair.publicKey, secretKey: Data())
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }

        // Test invalid lengths for crypto_box_open
        XCTAssertThrowsError(
            try cryptoBox.openEasy(
                ciphertext: Data(), nonce: Data(), publicKey: Data(), secretKey: Data())
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }
        XCTAssertThrowsError(
            try cryptoBox.openEasy(
                ciphertext: Data(), nonce: Data(repeating: 0x00, count: cryptoBox.nonceBytes),
                publicKey: Data(), secretKey: Data())
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }
        XCTAssertThrowsError(
            try cryptoBox.openEasy(
                ciphertext: Data(), nonce: Data(repeating: 0x00, count: cryptoBox.nonceBytes),
                publicKey: A_keypair.publicKey, secretKey: Data())
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }

        // Test invalid lengths for crypto_box_beforenm
        XCTAssertThrowsError(try cryptoBox.beforenm(publicKey: Data(), secretKey: Data())) {
            error in
            XCTAssertTrue(error is SodiumError)
        }
        XCTAssertThrowsError(
            try cryptoBox.beforenm(publicKey: A_keypair.publicKey, secretKey: Data())
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }

        // Test invalid lengths for crypto_box_afternm
        XCTAssertThrowsError(
            try cryptoBox.easyAfternm(message: Data(), nonce: Data(), sharedKey: Data())
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }
        XCTAssertThrowsError(
            try cryptoBox.easyAfternm(
                message: Data(), nonce: Data(repeating: 0x00, count: cryptoBox.nonceBytes),
                sharedKey: Data())
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }

        // Test invalid lengths for crypto_box_open_afternm
        XCTAssertThrowsError(
            try cryptoBox.openEasyAfternm(ciphertext: Data(), nonce: Data(), sharedKey: Data())
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }
        XCTAssertThrowsError(
            try cryptoBox.openEasyAfternm(
                ciphertext: Data(), nonce: Data(repeating: 0x00, count: cryptoBox.nonceBytes),
                sharedKey: Data())
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }
    }

    func testBoxEasyWrongLengths() throws {
        let cryptoBox = swiftNcal.cryptoBox

        // Generate keypair
        let A_keypair = try cryptoBox.keypair()

        // Test invalid lengths for crypto_box_easy
        XCTAssertThrowsError(
            try cryptoBox.easy(
                message: Data("abc".utf8), nonce: Data([0x00]), publicKey: A_keypair.publicKey,
                secretKey: A_keypair.secretKey)
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }
        XCTAssertThrowsError(
            try cryptoBox.easy(
                message: Data("abc".utf8),
                nonce: Data(repeating: 0x00, count: cryptoBox.nonceBytes), publicKey: Data(),
                secretKey: A_keypair.secretKey)
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }
        XCTAssertThrowsError(
            try cryptoBox.easy(
                message: Data("abc".utf8),
                nonce: Data(repeating: 0x00, count: cryptoBox.nonceBytes),
                publicKey: A_keypair.publicKey, secretKey: Data())
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }

        // Test invalid lengths for crypto_box_open_easy
        XCTAssertThrowsError(
            try cryptoBox.openEasy(
                ciphertext: Data(), nonce: Data(), publicKey: Data(), secretKey: Data())
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }
        XCTAssertThrowsError(
            try cryptoBox.openEasy(
                ciphertext: Data(), nonce: Data(repeating: 0x00, count: cryptoBox.nonceBytes),
                publicKey: Data(), secretKey: Data())
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }
        XCTAssertThrowsError(
            try cryptoBox.openEasy(
                ciphertext: Data(), nonce: Data(repeating: 0x00, count: cryptoBox.nonceBytes),
                publicKey: A_keypair.publicKey, secretKey: Data())
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }

        // Test invalid lengths for crypto_box_beforenm
        XCTAssertThrowsError(try cryptoBox.beforenm(publicKey: Data(), secretKey: Data())) {
            error in
            XCTAssertTrue(error is SodiumError)
        }
        XCTAssertThrowsError(
            try cryptoBox.beforenm(publicKey: A_keypair.publicKey, secretKey: Data())
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }

        // Test invalid lengths for crypto_box_easy_afternm
        XCTAssertThrowsError(
            try cryptoBox.easyAfternm(message: Data(), nonce: Data(), sharedKey: Data())
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }
        XCTAssertThrowsError(
            try cryptoBox.easyAfternm(
                message: Data(), nonce: Data(repeating: 0x00, count: cryptoBox.nonceBytes),
                sharedKey: Data())
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }

        // Test invalid lengths for crypto_box_open_easy_afternm
        XCTAssertThrowsError(
            try cryptoBox.openEasyAfternm(ciphertext: Data(), nonce: Data(), sharedKey: Data())
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }
        XCTAssertThrowsError(
            try cryptoBox.openEasyAfternm(
                ciphertext: Data(), nonce: Data(repeating: 0x00, count: cryptoBox.nonceBytes),
                sharedKey: Data())
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }
    }

    func testBoxSealEmpty() throws {
        let cryptoBox = swiftNcal.cryptoBox

        // Generate keypair
        let keypair = try cryptoBox.keypair()

        // Encrypt an empty message
        let emptyMessage = Data()
        let sealedMessage = try cryptoBox.seal(message: emptyMessage, publicKey: keypair.publicKey)

        // Decrypt the sealed message
        let decryptedMessage = try cryptoBox.sealOpen(
            ciphertext: sealedMessage, publicKey: keypair.publicKey, secretKey: keypair.secretKey)

        // Assert that the decrypted message is equal to the empty message
        XCTAssertEqual(decryptedMessage, emptyMessage)
    }

    func testBoxSealEmptyIsVerified() throws {
        let cryptoBox = swiftNcal.cryptoBox

        // Generate keypair
        let keypair = try cryptoBox.keypair()

        // Encrypt an empty message
        let emptyMessage = Data()
        var sealedMessage = try cryptoBox.seal(message: emptyMessage, publicKey: keypair.publicKey)

        // Tamper with the sealed message
        sealedMessage[sealedMessage.count - 1] ^= 1

        // Attempt to decrypt the tampered message and expect a failure
        XCTAssertThrowsError(
            try cryptoBox.sealOpen(
                ciphertext: sealedMessage, publicKey: keypair.publicKey,
                secretKey: keypair.secretKey)
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }
    }

    func testBoxSealWrongLengths() throws {
        let cryptoBox = swiftNcal.cryptoBox

        // Generate keypair
        let keypair = try cryptoBox.keypair()

        // Test invalid lengths for crypto_box_seal
        XCTAssertThrowsError(
            try cryptoBox.seal(message: Data("abc".utf8), publicKey: keypair.publicKey.dropLast())
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }

        // Test invalid lengths for crypto_box_seal_open
        XCTAssertThrowsError(
            try cryptoBox.sealOpen(
                ciphertext: Data("abc".utf8), publicKey: Data(), secretKey: keypair.secretKey)
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }
        XCTAssertThrowsError(
            try cryptoBox.sealOpen(
                ciphertext: Data("abc".utf8), publicKey: keypair.publicKey,
                secretKey: keypair.secretKey.dropLast())
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }

        // Encrypt an empty message
        let emptyMessage = Data()
        let sealedMessage = try cryptoBox.seal(message: emptyMessage, publicKey: keypair.publicKey)

        // Tamper with the sealed message
        let tamperedMessage = sealedMessage.dropLast()

        // Attempt to decrypt the tampered message and expect a failure
        XCTAssertThrowsError(
            try cryptoBox.sealOpen(
                ciphertext: tamperedMessage, publicKey: keypair.publicKey,
                secretKey: keypair.secretKey)
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }
    }

    func testBoxSealWrongTypes() throws {
        let cryptoBox = swiftNcal.cryptoBox

        // Generate keypair
        let keypair = try cryptoBox.keypair()

        // Test invalid types for crypto_box_seal
        XCTAssertThrowsError(try cryptoBox.seal(message: Data("abc".utf8), publicKey: Data())) {
            error in
            XCTAssertTrue(error is SodiumError)
        }

        // Test invalid types for crypto_box_seal_open
        XCTAssertThrowsError(
            try cryptoBox.sealOpen(
                ciphertext: Data("abc".utf8), publicKey: Data(), secretKey: keypair.secretKey)
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }
        XCTAssertThrowsError(
            try cryptoBox.sealOpen(
                ciphertext: Data("abc".utf8), publicKey: keypair.publicKey, secretKey: Data())
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }
        XCTAssertThrowsError(
            try cryptoBox.sealOpen(
                ciphertext: Data(), publicKey: keypair.publicKey, secretKey: keypair.secretKey)
        ) { error in
            XCTAssertTrue(error is SodiumError)
        }
    }

    func testBoxSeedKeypairRandom() throws {
        let cryptoBox = swiftNcal.cryptoBox

        // Generate a random seed
        let seed = swiftNcal.randomBytes.randomBytes(size: cryptoBox.seedBytes)

        // Generate keypair from seed
        let keypair = try cryptoBox.seedKeypair(seed: seed)

        // Compute public key from secret key
        let computedPublicKey = try swiftNcal.cryptoScalarmult.base(
            n: keypair.secretKey
        )

        // Assert that the generated public key matches the computed public key
        XCTAssertEqual(keypair.publicKey, computedPublicKey)
    }

    func testBoxSeedKeypairShortSeed() throws {
        let cryptoBox = swiftNcal.cryptoBox

        // Generate a short seed
        let shortSeed = swiftNcal.randomBytes.randomBytes(
            size: cryptoBox.seedBytes - 1
        )

        // Test invalid seed length for seedKeypair
        XCTAssertThrowsError(try cryptoBox.seedKeypair(seed: shortSeed)) { error in
            XCTAssertTrue(error is SodiumError)
        }
    }

    func testBoxSeedKeypairReference() throws {
        let cryptoBox = swiftNcal.cryptoBox

        // Read test vectors
        let vectors = readCryptoTestVectors(fileName: "box_from_seed", delimiter: "\t")

        for (seed, expectedPublicKey, expectedSecretKey) in vectors {
            // Generate keypair from seed
            let keypair = try cryptoBox.seedKeypair(seed: seed)

            // Assert that the generated keys match the expected keys
            XCTAssertEqual(keypair.publicKey, expectedPublicKey)
            XCTAssertEqual(keypair.secretKey, expectedSecretKey)
        }
    }

    func testCryptoBoxOpenEasy() throws {
        let cryptoBox = swiftNcal.cryptoBox
        
        // Generate keypair
        let keypair = try cryptoBox.keypair()
        let publicKey = keypair.publicKey
        let secretKey = keypair.secretKey
        
        let message = "Hello, World!".data(using: .utf8)!
        let nonce = Data(count: cryptoBox.nonceBytes)

        let ciphertext = try cryptoBox.easy(
            message: message, nonce: nonce, publicKey: publicKey, secretKey: secretKey)
        let decryptedMessage = try cryptoBox.openEasy(
            ciphertext: ciphertext, nonce: nonce, publicKey: publicKey, secretKey: secretKey)
        XCTAssertEqual(message, decryptedMessage)
    }

    func testCryptoBoxSeal() throws {
        let cryptoBox = swiftNcal.cryptoBox
        
        // Generate keypair
        let keypair = try cryptoBox.keypair()
        
        let message = "Hello, World!".data(using: .utf8)!
        let publicKey = keypair.publicKey

        let ciphertext = try cryptoBox.seal(message: message, publicKey: publicKey)
        XCTAssertNotNil(ciphertext)
    }

    func testCryptoBoxSealOpen() throws {
        let cryptoBox = swiftNcal.cryptoBox
        
        // Generate keypair
        let keypair = try cryptoBox.keypair()
        let publicKey = keypair.publicKey
        let secretKey = keypair.secretKey
        
        let message = "Hello, World!".data(using: .utf8)!

        let ciphertext = try cryptoBox.seal(message: message, publicKey: publicKey)
        let decryptedMessage = try cryptoBox.sealOpen(
            ciphertext: ciphertext, publicKey: publicKey, secretKey: secretKey)
        XCTAssertEqual(message, decryptedMessage)
    }

    func testCryptoBoxEasyAfternm() throws {
        let message = "Hello, World!".data(using: .utf8)!
        let nonce = Data(count: Int(crypto_box_noncebytes()))
        let sharedKey = Data(count: Int(crypto_box_beforenmbytes()))

        let cryptoBox = CryptoBox()

        let ciphertext = try cryptoBox.easyAfternm(
            message: message, nonce: nonce, sharedKey: sharedKey)
        XCTAssertNotNil(ciphertext)
    }

    func testCryptoBoxOpenEasyAfternm() throws {
        let message = "Hello, World!".data(using: .utf8)!
        let nonce = Data(count: Int(crypto_box_noncebytes()))
        let sharedKey = Data(count: Int(crypto_box_beforenmbytes()))

        let cryptoBox = CryptoBox()

        let ciphertext = try cryptoBox.easyAfternm(
            message: message, nonce: nonce, sharedKey: sharedKey)
        let decryptedMessage = try cryptoBox.openEasyAfternm(
            ciphertext: ciphertext, nonce: nonce, sharedKey: sharedKey)
        XCTAssertEqual(message, decryptedMessage)
    }
}
