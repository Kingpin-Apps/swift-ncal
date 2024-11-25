import Foundation
import Clibsodium

struct KeyPair: Hashable {
    var publicKey: PublicKey
    
    var secretKey: PrivateKey
    
    init(publicKey: PublicKey, secretKey: PrivateKey) {
        self.publicKey = publicKey
        self.secretKey = secretKey
    }
}

class PublicKey: Hashable {
    /*
     The public key counterpart to an Curve25519 `PrivateKey`
     for encrypting messages.

     - Parameter publicKey: Encoded Curve25519 public key
     - Parameter encoder: A class that is able to decode the `public_key`
     */
    
    static let SIZE = Int(crypto_box_publickeybytes())

    private var _publicKey: Data

    init(publicKey: Data, encoder: Encoder.Type = RawEncoder.self) throws {
        self._publicKey = encoder.decode(data: publicKey)
        guard self._publicKey.count == PublicKey.SIZE else {
            throw NSError(domain: "PublicKey", code: 1, userInfo: [NSLocalizedDescriptionKey: "The public key must be exactly \(PublicKey.SIZE) bytes long"])
        }
    }

    func toBytes() -> Data {
        return _publicKey
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(_publicKey)
    }

    static func == (lhs: PublicKey, rhs: PublicKey) -> Bool {
        return lhs._publicKey == rhs._publicKey
    }
}

class PrivateKey: Hashable {
    static let SIZE = Int(crypto_box_secretkeybytes())
    static let SEED_SIZE = Int(crypto_box_seedbytes())

    private var _privateKey: Data
    var publicKey: PublicKey

    init(privateKey: Data, encoder: Encoder.Type = RawEncoder.self) throws {
        self._privateKey = encoder.decode(data: privateKey)
        guard self._privateKey.count == PrivateKey.SIZE else {
            throw NSError(domain: "PrivateKey", code: 1, userInfo: [NSLocalizedDescriptionKey: "The private key must be exactly \(PrivateKey.SIZE) bytes long"])
        }
        // Generate public key
        let rawPublicKey = self._privateKey // This should be replaced with actual public key generation logic
        self.publicKey = try PublicKey(publicKey: rawPublicKey)
    }

    static func fromSeed(seed: Data, encoder: Encoder.Type = RawEncoder.self) throws -> PrivateKey {
        let decodedSeed = encoder.decode(data: seed)
        guard decodedSeed.count == PrivateKey.SEED_SIZE else {
            throw NSError(domain: "PrivateKey", code: 2, userInfo: [NSLocalizedDescriptionKey: "The seed must be exactly \(PrivateKey.SEED_SIZE) bytes long"])
        }
        // Generate key pair from seed
        let rawPrivateKey = decodedSeed // This should be replaced with actual key pair generation logic
        return try PrivateKey(privateKey: rawPrivateKey)
    }

    func toBytes() -> Data {
        return _privateKey
    }
    
    func hash(into hasher: inout Hasher) {
        hasher.combine(KeyPair(publicKey: self.publicKey, secretKey: self))
    }

    static func == (lhs: PrivateKey, rhs: PrivateKey) -> Bool {
        return lhs.publicKey == rhs.publicKey
    }

    static func generate() -> PrivateKey {
        let randomBytes = Data((0..<PrivateKey.SIZE).map { _ in UInt8.random(in: 0...255) })
        return try! PrivateKey(privateKey: randomBytes)
    }
}

class Box {
    static let NONCE_SIZE = 24 // Assuming 24 bytes for nonce

    private var _sharedKey: Data

    init(privateKey: PrivateKey, publicKey: PublicKey) throws {
        // Generate shared key
        self._sharedKey = privateKey.toBytes() // This should be replaced with actual shared key generation logic
    }

    func toBytes() -> Data {
        return _sharedKey
    }

    func encrypt(plaintext: Data, nonce: Data? = nil, encoder: Encoder.Type = RawEncoder.self) throws -> Data {
        let nonce = nonce ?? Data((0..<Box.NONCE_SIZE).map { _ in UInt8.random(in: 0...255) })
        guard nonce.count == Box.NONCE_SIZE else {
            throw NSError(domain: "Box", code: 1, userInfo: [NSLocalizedDescriptionKey: "The nonce must be exactly \(Box.NONCE_SIZE) bytes long"])
        }
        let ciphertext = plaintext // This should be replaced with actual encryption logic
        return encoder.encode(data: nonce + ciphertext)
    }

    func decrypt(ciphertext: Data, nonce: Data? = nil, encoder: Encoder.Type = RawEncoder.self) throws -> Data {
        let decodedCiphertext = encoder.decode(data: ciphertext)
        let nonce = nonce ?? decodedCiphertext.prefix(Box.NONCE_SIZE)
        guard nonce.count == Box.NONCE_SIZE else {
            throw NSError(domain: "Box", code: 2, userInfo: [NSLocalizedDescriptionKey: "The nonce must be exactly \(Box.NONCE_SIZE) bytes long"])
        }
        let plaintext = decodedCiphertext.dropFirst(Box.NONCE_SIZE) // This should be replaced with actual decryption logic
        return plaintext
    }

    func sharedKey() -> Data {
        return _sharedKey
    }
}

class SealedBox {
    private var publicKey: Data
    private var privateKey: Data?

    init(recipientKey: PublicKey) {
        self.publicKey = recipientKey.toBytes()
        self.privateKey = nil
    }

    init(recipientKey: PrivateKey) {
        self.publicKey = recipientKey.publicKey.toBytes()
        self.privateKey = recipientKey.toBytes()
    }

    func toBytes() -> Data {
        return publicKey
    }

    func encrypt(plaintext: Data) -> Data {
        let ciphertext = plaintext // This should be replaced with actual encryption logic
        return RawEncoder.encode(data: ciphertext)
    }

    func decrypt(ciphertext: Data, encoder: RawEncoder) throws -> Data {
        guard privateKey != nil else {
            throw NSError(domain: "SealedBox", code: 1, userInfo: [NSLocalizedDescriptionKey: "SealedBoxes created with a public key cannot decrypt"])
        }
        let decodedCiphertext = RawEncoder.decode(data: ciphertext)
        let plaintext = decodedCiphertext // This should be replaced with actual decryption logic
        return plaintext
    }
}
