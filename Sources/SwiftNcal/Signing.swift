import Clibsodium
import Foundation

nonisolated(unsafe) private let sodium = Sodium()

/// A Data subclass that holds a message that has been signed by a `SigningKey`.
class SignedMessage {
    
    private var signature: Data
    private var message: Data
    private var combined: Data

    init(signature: Data, message: Data, combined: Data) {
        self.signature = signature
        self.message = message
        self.combined = combined
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    class func fromParts(signature: Data, message: Data, combined: Data) -> SignedMessage {
        return SignedMessage(signature: signature, message: message, combined: combined)
    }

    /// The signature contained within the `SignedMessage`.
    var getSignature: Data {
        return self.signature
    }

    /// The message contained within the `SignedMessage`.
    var getMessage: Data {
        return self.message
    }
    
    /// The combined contained within the `SignedMessage`.
    var getCombined: Data {
        return combined
    }
}

/// The public key counterpart to an Ed25519 SigningKey for producing digital signatures.
///
/// - Parameters:
///    - key: Serialized Ed25519 public key
///    - encoder: The encoder to use for encoding and decoding data
class VerifyKey: Equatable, Hashable {
    private var key: Data

    init(key: Data, encoder: Encoder.Type = RawEncoder.self) throws {
        // Decode the key
        self.key = encoder.decode(data: key)
        
        try ensure(self.key.count == sodium.cryptoSign.publicKeyBytes, raising: .valueError("The key must be exactly \(sodium.cryptoSign.publicKeyBytes) bytes long"))
    }

    var bytes: Data {
        return self.key
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(self.key)
    }

    static func == (lhs: VerifyKey, rhs: VerifyKey) -> Bool {
        return sodium.utils.sodiumMemcmp(lhs.key, rhs.key)
    }

    /// Verifies the signature of a signed message, returning the message if it has not been tampered with else raising `BadSignatureError`.
    ///
    /// - Parameters:
    ///    - smessage: Either the original messaged or a signature and message concated together.
    ///    - signature: If an unsigned message is given for smessage then the detached signature must be provided.
    ///    - encoder: The encoder to use for encoding and decoding data.
    ///  - Returns: The original message if the signature is valid.
    func verify(smessage: Data, signature: Data? = nil, encoder: Encoder.Type = RawEncoder.self) throws -> Data {
        
        var signed: Data
        if let signature = signature {
            try ensure(
                signature.count != sodium.cryptoSign.bytes,
                raising: .valueError("Verification signature must be created from \(sodium.cryptoSign.bytes) bytes")
            )
            signed = signature + encoder.decode(data: smessage)
        } else {
            signed = encoder.decode(data: smessage)
        }
        return try sodium.cryptoSign.open(signed: signed, pk: self.key)
    }

    /// Converts a `VerifyKey` to a `PublicKey`
    func toCurve25519PublicKey() throws -> PublicKey {
        
        let rawPk = try sodium.cryptoSign.ed25519PkToCurve25519(
            publicKeyBytes: self.key
        )
        return try PublicKey(publicKey: rawPk)
    }
}

/// Private key for producing digital signatures using the Ed25519 algorithm.
/// Signing keys are produced from a 32-byte (256-bit) random seed value.
/// This value can be passed into the `SigningKey` as a `Data` whose length is 32.
///
///  - Warning: This **must** be protected and remain secret. Anyone who knows the value of your `SigningKey` or it's seed can masquerade as you.
///
///  - Parameters:
///  - seed: Random 32-byte value (i.e. private key)
///  - encoder: The encoder to use for encoding and decoding data
class SigningKey {
    private var seed: Data
    private var signingKey: Data
    var verifyKey: VerifyKey

    init(seed: Data, encoder: Encoder.Type = RawEncoder.self) throws {
        // Decode the seed
        self.seed = encoder.decode(data: seed)
        
        try ensure(
            self.seed.count == sodium.cryptoSign.seedBytes,
            raising: .valueError("The seed must be exactly \(sodium.cryptoSign.seedBytes) bytes long")
        )
        
        let keyPair = try sodium.cryptoSign.seedKeypair(seed: self.seed)
        self.signingKey = keyPair.secretKey
        self.verifyKey = try VerifyKey(key: keyPair.publicKey)
    }

    var bytes: Data {
        return self.seed
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(self.seed)
    }

    static func == (lhs: SigningKey, rhs: SigningKey) -> Bool {
        return sodium.utils
            .sodiumMemcmp(lhs.seed, rhs.seed)
    }

    /// Generates a random `SigningKey` object.
    class func generate() throws -> SigningKey {
        return try SigningKey(seed: random(size: sodium.cryptoSign.seedBytes))
    }

    /// Sign a message using this key.
    ///
    /// - Parameters:
    ///   - message: The message to sign.
    ///   - encoder: The encoder to use for encoding and decoding data.
    func sign(message: Data, encoder: Encoder.Type = RawEncoder.self) throws -> SignedMessage {
        
        let rawSigned = try sodium.cryptoSign.sign(
            message: message,
            sk: self.signingKey
        )
        let signature = encoder.encode(
            data: rawSigned.prefix(sodium.cryptoSign.bytes)
        )
        let signedMessage = encoder.encode(data: rawSigned)
        return SignedMessage.fromParts(signature: signature, message: message, combined: signedMessage)
    }

    /// Converts a `SigningKey` to a `PrivateKey`
    func toCurve25519PrivateKey() throws -> PrivateKey {
        let rawPrivate = try sodium.cryptoSign.ed25519SkToCurve25519(
            secretKeyBytes: self.signingKey
        )
        return try PrivateKey(privateKey: rawPrivate)
    }
}
