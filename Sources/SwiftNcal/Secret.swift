import Foundation

nonisolated(unsafe) private let sodium = Sodium()

class SecretBox {
    /**
     The SecretBox class encrypts and decrypts messages using the given secret
     key.

     The ciphertexts generated by `SecretBox` include a 16 byte authenticator which is checked as part of the decryption. An invalid authenticator will cause the decrypt function to raise an exception. The authenticator is not a signature. Once you've decrypted the message you've demonstrated the ability to create arbitrary valid message, so messages you send are repudiable. For non-repudiable messages, sign them after encryption.

     Encryption is done using `XSalsa20-Poly1305`, and there are no practical limits on the number or size of messages (up to 2⁶⁴ messages, each up to 2⁶⁴ bytes).

     - parameter key: The secret key used to encrypt and decrypt messages
     - parameter encoder: The encoder class used to decode the given key

     - cvar keySize: The size that the key is required to be.
     - cvar nonceSize: The size that the nonce is required to be.
     - cvar macBytes: The size of the authentication MAC tag in bytes.
     - cvar messageBytesMax: The maximum size of a message which can be safely encrypted with a single key/nonce pair.
     */
    public let keySize: Int
    public let nonceSize: Int
    public let macBytes: Int
    public let messageBytesMax: Int

    private var key: Data

    init(key: Data, encoder: Encoder.Type = RawEncoder.self) throws {
        self.key = encoder.decode(data: key)
        
        keySize = sodium.cryptoSecretBox.keyBytes
        nonceSize = sodium.cryptoSecretBox.nonceBytes
        macBytes = sodium.cryptoSecretBox.keyBytes
        messageBytesMax = sodium.cryptoSecretBox.keyBytes
        
        try ensure(key.count == keySize, raising: .valueError("Invalid key"))
    }

    public func encrypt(plaintext: Data, nonce: Data? = nil, encoder: Encoder.Type = RawEncoder.self) throws -> EncryptedMessage {
        /**
         Encrypts the plaintext message using the given `nonce` (or generates one randomly if omitted) and returns the ciphertext encoded with the encoder.

         - warning: It is **VITALLY** important that the nonce is a nonce, i.e. it is a number used only once for any given key. If you fail to do this, you compromise the privacy of the messages encrypted. Give your nonces a different prefix, or have one side use an odd counter and one an even counter. Just make sure they are different.

         - parameter plaintext: The plaintext message to encrypt
         - parameter nonce: The nonce to use in the encryption
         - parameter encoder: The encoder to use to encode the ciphertext
         - returns: EncryptedMessage
         */
        let nonce = nonce ?? random(size: nonceSize)
        try ensure(nonce.count == nonceSize, raising: .valueError("The nonce must be exactly \(nonceSize) bytes long"))

        let ciphertext = try sodium.cryptoSecretBox.easy(
            message: plaintext,
            nonce: nonce,
            key: key
        )
        let encodedNonce = encoder.encode(data: nonce)
        let encodedCiphertext = encoder.encode(data: ciphertext)

        return EncryptedMessage(nonce: encodedNonce, ciphertext: encodedCiphertext, combined: encoder.encode(data: nonce + ciphertext))
    }

    public func decrypt(ciphertext: Data, nonce: Data? = nil, encoder: Encoder.Type = RawEncoder.self) throws -> Data {
        /**
         Decrypts the ciphertext using the `nonce` (explicitly, when passed as a parameter or implicitly, when omitted, as part of the ciphertext) and returns the plaintext message.

         - parameter ciphertext: The encrypted message to decrypt
         - parameter nonce: The nonce used when encrypting the ciphertext
         - parameter encoder: The encoder used to decode the ciphertext.
         - returns: Data
         */
        let decodedCiphertext = encoder.decode(data: ciphertext)
        let nonce = nonce ?? decodedCiphertext.prefix(nonceSize)
        let ciphertext = decodedCiphertext.dropFirst(nonceSize)
        
        try ensure(nonce.count == nonceSize, raising: .valueError("The nonce must be exactly \(nonceSize) bytes long"))

        return try sodium.cryptoSecretBox.openEasy(ciphertext: ciphertext, nonce: nonce, key: key)
    }
}

class Aead {
    /**
     The AEAD class encrypts and decrypts messages using the given secret key.

     Unlike `SecretBox`, AEAD supports authenticating non-confidential data received alongside the message, such as a length or type tag.

     Like `SecretBox`, this class provides authenticated encryption. An inauthentic message will cause the decrypt function to raise an exception.

     Likewise, the authenticator should not be mistaken for a (public-key) signature: recipients (with the ability to decrypt messages) are capable of creating arbitrary valid message; in particular, this means AEAD messages are repudiable. For non-repudiable messages, sign them after encryption.

     The cryptosystem used is `XChacha20-Poly1305` as specified for standardization. There are no practical limits to how much can safely be encrypted under a given key (up to 2⁶⁴ messages each containing up to 2⁶⁴ bytes).

     - parameter key: The secret key used to encrypt and decrypt messages
     - parameter encoder: The encoder class used to decode the given key

     - cvar keySize: The size that the key is required to be.
     - cvar nonceSize: The size that the nonce is required to be.
     - cvar macBytes: The size of the authentication MAC tag in bytes.
     - cvar messageBytesMax: The maximum size of a message which can be safely encrypted with a single key/nonce pair.
     */
    public let keySize: Int
    public let nonceSize: Int
    public let macBytes: Int
    public let messageBytesMax: UInt64

    private var key: Data

    init(key: Data, encoder: Encoder.Type = RawEncoder.self) throws {
        self.key = encoder.decode(data: key)
        
        keySize = sodium.cryptoAead.xchacha20poly1305IetfKeyBytes
        nonceSize = sodium.cryptoAead.xchacha20poly1305IetfNpubBytes
        macBytes = sodium.cryptoAead.xchacha20poly1305IetfABytes
        messageBytesMax = sodium.cryptoAead.xchacha20poly1305IetfMessageBytesMax
        
        try ensure(key.count == keySize, raising: .valueError("Invalid key"))
    }

    public func encrypt(plaintext: Data, aad: Data = Data(), nonce: Data? = nil, encoder: Encoder.Type = RawEncoder.self) throws -> EncryptedMessage {
        /**
         Encrypts the plaintext message using the given `nonce` (or generates one randomly if omitted) and returns the ciphertext encoded with the encoder.

         - warning: It is vitally important for `nonce` to be unique. By default, it is generated randomly; `Aead` uses XChacha20 for extended (192b) nonce size, so the risk of reusing random nonces is negligible. It is *strongly recommended* to keep this behaviour, as nonce reuse will compromise the privacy of encrypted messages. Should implicit nonces be inadequate for your application, the second best option is using split counters; e.g. if sending messages encrypted under a shared key between 2 users, each user can use the number of messages it sent so far, prefixed or suffixed with a 1bit user id. Note that the counter must **never** be rolled back (due to overflow, on-disk state being rolled back to an earlier backup, ...)

         - parameter plaintext: The plaintext message to encrypt
         - parameter nonce: The nonce to use in the encryption
         - parameter encoder: The encoder to use to encode the ciphertext
         - returns: EncryptedMessage
         */
        
        let nonce = nonce ?? random(size: nonceSize)
        try ensure(nonce.count == nonceSize, raising: .valueError("The nonce must be exactly \(nonceSize) bytes long"))

        let ciphertext = try sodium.cryptoAead.xchacha20poly1305IetfEncrypt(
              message: plaintext, aad: aad, nonce: nonce, key: key)
        let encodedNonce = encoder.encode(data: nonce)
        let encodedCiphertext = encoder.encode(data: ciphertext)

        return EncryptedMessage(nonce: encodedNonce, ciphertext: encodedCiphertext, combined: encoder.encode(data: nonce + ciphertext))
    }

    public func decrypt(ciphertext: Data, aad: Data = Data(), nonce: Data? = nil, encoder: Encoder.Type = RawEncoder.self) throws -> Data {
        /**
         Decrypts the ciphertext using the `nonce` (explicitly, when passed as a parameter or implicitly, when omitted, as part of the ciphertext) and returns the plaintext message.

         - parameter ciphertext: The encrypted message to decrypt
         - parameter nonce: The nonce used when encrypting the ciphertext
         - parameter encoder: The encoder used to decode the ciphertext.
         - returns: Data
         */
        let decodedCiphertext = encoder.decode(data: ciphertext)
        let nonce = nonce ?? decodedCiphertext.prefix(nonceSize)
        let ciphertext = decodedCiphertext.dropFirst(nonceSize)
        
        try ensure(nonce.count == nonceSize, raising: .valueError("The nonce must be exactly \(nonceSize) bytes long"))

        return try sodium.cryptoAead.xchacha20poly1305IetfDecrypt(
            ciphertext: ciphertext, aad: aad, nonce: nonce, key: key)
    }
}

