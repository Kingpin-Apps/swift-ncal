![GitHub Workflow Status](https://github.com/Kingpin-Apps/swift-ncal/actions/workflows/swift.yml/badge.svg)
[![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2FKingpin-Apps%2Fswift-ncal%2Fbadge%3Ftype%3Dswift-versions)](https://swiftpackageindex.com/Kingpin-Apps/swift-ncal)
[![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2FKingpin-Apps%2Fswift-ncal%2Fbadge%3Ftype%3Dplatforms)](https://swiftpackageindex.com/Kingpin-Apps/swift-ncal)

# Swift-NaCL - Swift binding to the libsodium library

Swift-NaCL is a Swift binding to a fork of [libsodium](https://github.com/IntersectMBO/libsodium) library. These libraries have a stated goal of
improving usability, security and speed.

This package provides a modern, idiomatic Swift interface to the libsodium cryptographic library, offering state-of-the-art cryptographic primitives for secure communication, data integrity, and authentication.

## Platform Support

- **iOS** 13.0+
- **macOS** 10.15+
- **tvOS** 13.0+
- **watchOS** 6.0+
- **visionOS** 1.0+
- **Linux** (Ubuntu 18.04+, with system libsodium or bundled binaries)

## Installation

### Swift Package Manager

To add Swift-NaCL as dependency to your Xcode project, select `File` > `Swift Packages` > `Add Package Dependency`, enter its repository URL:

```
https://github.com/Kingpin-Apps/swift-ncal.git
```

Import both `SwiftNcal` and `Clibsodium` in your project.

### Package.swift

Add the following to your `Package.swift` file:

```swift
dependencies: [
    .package(url: "https://github.com/Kingpin-Apps/swift-ncal.git", from: "0.1.4")
],
targets: [
    .target(
        name: "YourTarget",
        dependencies: [
            .product(name: "SwiftNcal", package: "swift-ncal")
        ]
    )
]
```

### Usage

In your Swift files, import the library:

```swift
import SwiftNcal
```

## Key Features

- ✅ **Digital Signatures** - Ed25519 signing and verification
- ✅ **Secret-key Encryption** - XSalsa20-Poly1305 and XChacha20-Poly1305 AEAD
- ✅ **Public-key Encryption** - Curve25519 key exchange with authenticated encryption
- ✅ **Cryptographic Hashing** - SHA-256, SHA-512, BLAKE2b, SipHash variants
- ✅ **Verifiable Random Functions (VRF)** - IETF Draft 03 specification with Ed25519
- ✅ **Message Authentication** - Poly1305 MAC
- ✅ **Key Derivation** - Password-based and deterministic key generation
- ✅ **Cross-platform** - Works on Apple platforms and Linux
- ✅ **Memory Safe** - Secure memory handling with automatic cleanup

## Quick Start Examples

### Digital Signatures (Ed25519)

```swift
import SwiftNcal

// Generate a signing key
let signingKey = try SigningKey.generate()
let verifyKey = signingKey.verifyKey

// Sign a message
let message = "Hello, World!".data(using: .utf8)!
let signedMessage = try signingKey.sign(message: message)

// Verify the signature
let verifiedMessage = try verifyKey.verify(smessage: signedMessage.getCombined)
print(String(data: verifiedMessage, encoding: .utf8)!) // "Hello, World!"
```

### Secret-key Encryption (XSalsa20-Poly1305)

```swift
import SwiftNcal

// Generate a random key
let key = random(size: 32)
let secretBox = try SecretBox(key: key)

// Encrypt a message
let plaintext = "Secret message".data(using: .utf8)!
let encrypted = try secretBox.encrypt(plaintext: plaintext)

// Decrypt the message
let decrypted = try secretBox.decrypt(ciphertext: encrypted.combined)
print(String(data: decrypted, encoding: .utf8)!) // "Secret message"
```

### Public-key Encryption (Curve25519)

```swift
import SwiftNcal

// Generate key pairs
let aliceKeyPair = KeyPair.generate()
let bobKeyPair = KeyPair.generate()

// Alice encrypts a message for Bob
let aliceBox = try Box(privateKey: aliceKeyPair.secretKey, publicKey: bobKeyPair.publicKey)
let message = "Hello Bob!".data(using: .utf8)!
let encrypted = try aliceBox.encrypt(plaintext: message)

// Bob decrypts the message from Alice
let bobBox = try Box(privateKey: bobKeyPair.secretKey, publicKey: aliceKeyPair.publicKey)
let decrypted = try bobBox.decrypt(ciphertext: encrypted.combined)
print(String(data: decrypted, encoding: .utf8)!) // "Hello Bob!"
```

### Cryptographic Hashing

```swift
import SwiftNcal

let hash = Hash()
let message = "Hello, World!".data(using: .utf8)!

// SHA-256
let sha256Hash = try hash.sha256(message: message)
print(sha256Hash.base64EncodedString())

// BLAKE2b with custom parameters
let blake2bHash = try hash.blake2b(
    data: message,
    digestSize: 32,
    key: "secret-key".data(using: .utf8)!,
    salt: "salt1234".data(using: .utf8)!,
    person: "personal".data(using: .utf8)!
)
```

### Verifiable Random Functions (VRF)

```swift
import SwiftNcal

// Generate a VRF key pair
let keyPair = VRFKeyPair.generate()

// Create a proof for a message
let message = "Hello, VRF!".data(using: .utf8)!
let proof = try keyPair.signingKey.prove(message: message)

// Verify the proof and get the deterministic output
let output = try keyPair.verifyingKey.verify(message: message, proof: proof)
print("VRF Output: \(output.hexEncodedString())")

// The same message always produces the same output with the same key
let proof2 = try keyPair.signingKey.prove(message: message)
let output2 = try keyPair.verifyingKey.verify(message: message, proof: proof2)
assert(output == output2) // Always true!
```

## API Reference

### Core Classes

#### Digital Signatures
- `SigningKey` - Ed25519 private key for signing
- `VerifyKey` - Ed25519 public key for verification
- `SignedMessage` - Container for signed messages

#### Public-key Encryption
- `PrivateKey` - Curve25519 private key
- `PublicKey` - Curve25519 public key
- `KeyPair` - Combined public/private key pair
- `Box` - Public-key authenticated encryption

#### Secret-key Encryption
- `SecretBox` - XSalsa20-Poly1305 AEAD encryption
- `Aead` - XChacha20-Poly1305 AEAD encryption with additional data

#### Hashing
- `Hash` - Cryptographic hash functions (SHA-256, SHA-512, BLAKE2b, SipHash)

#### Verifiable Random Functions
- `VRFSeed` - 32-byte cryptographic seed for key generation
- `VRFSigningKey` - Ed25519 private key for creating VRF proofs
- `VRFVerifyingKey` - Ed25519 public key for verifying VRF proofs
- `VRFProof` - 80-byte VRF proof
- `VRFOutput` - 64-byte deterministic VRF output
- `VRFKeyPair` - Convenience wrapper for signing and verifying keys

#### Encoding
- `RawEncoder` - Raw binary data (default)
- `HexEncoder` - Hexadecimal encoding
- `Base64Encoder` - Base64 encoding (via Foundation)

### Error Handling

Swift-NaCL uses Swift's error handling mechanism. All cryptographic operations that can fail throw descriptive errors:

```swift
do {
    let signingKey = try SigningKey(seed: invalidSeed)
} catch {
    print("Failed to create signing key: \(error)")
}
```

### Memory Security

The library automatically handles secure memory cleanup for sensitive data like private keys. However, you should still follow security best practices:

- Don't log sensitive data
- Clear sensitive variables when no longer needed
- Use secure storage for long-term key storage

## Advanced Usage

### Custom Encoders

You can specify different encoders for input/output:

```swift
// Use hex encoding for keys
let hexKey = "0123456789abcdef..."
let signingKey = try SigningKey(seed: Data(hex: hexKey), encoder: HexEncoder.self)

// Sign with hex output
let signedMessage = try signingKey.sign(message: message, encoder: HexEncoder.self)
```

### Key Conversion

Convert between Ed25519 and Curve25519 keys:

```swift
let signingKey = try SigningKey.generate()
let verifyKey = signingKey.verifyKey

// Convert to Curve25519 for encryption
let curve25519Private = try signingKey.toCurve25519PrivateKey()
let curve25519Public = try verifyKey.toCurve25519PublicKey()
```

### VRF Deterministic Key Generation

Generate VRF keys deterministically from a seed:

```swift
// Create a deterministic seed
let seedData = "my-deterministic-seed-32-bytes!".data(using: .utf8)!
let seed = try VRFSeed(bytes: seedData)

// Generate keys from seed - always the same for the same seed
let keyPair = try VRFKeyPair.from(seed: seed)

// Extract the original seed from a signing key
let originalSeed = keyPair.signingKey.seed
assert(originalSeed == seed)
```

### VRF Proof Extraction

Extract VRF output directly from a proof (without verification):

```swift
let keyPair = VRFKeyPair.generate()
let message = "data".data(using: .utf8)!
let proof = try keyPair.signingKey.prove(message: message)

// Extract output directly from proof (unverified)
let directOutput = try proof.hash()

// Verify and extract output (verified)
let verifiedOutput = try keyPair.verifyingKey.verify(message: message, proof: proof)

// Both outputs are identical
assert(directOutput == verifiedOutput)
```

### Environment Configuration

For Linux builds, you can control libsodium usage:

```bash
# Use system libsodium
export SWIFT_NCAL_USE_SYSTEM_LIBSODIUM=1
swift build
```

## Dependencies

- [libsodium](https://github.com/IntersectMBO/libsodium) - Core cryptographic library
- [Base32](https://github.com/norio-nomura/Base32.git) - Base32 encoding support
- [BigInt](https://github.com/attaswift/BigInt.git) - Large integer arithmetic

## Platform-specific Notes

### Apple Platforms
Uses precompiled libsodium framework (Clibsodium.xcframework) for optimal performance.

### Linux
- **Default**: Uses bundled libsodium binaries for x86_64 and arm64
- **System**: Set `SWIFT_NCAL_USE_SYSTEM_LIBSODIUM=1` to use system libsodium
- **Package managers**: Supports apt, yum, and brew for libsodium installation

## Testing

Run the test suite:

```bash
swift test
```

Tests cover:
- All cryptographic operations
- Key generation and validation
- Cross-platform compatibility
- Error conditions
- Memory safety

## Security Considerations

⚠️ **Important Security Notes:**

1. **Private Key Protection**: Private keys and seeds must be kept secret and secure
2. **Nonce Uniqueness**: Never reuse nonces with the same key
3. **Random Generation**: Use cryptographically secure random number generation
4. **Memory Handling**: Sensitive data is automatically cleared from memory
5. **Constant-time Operations**: All comparisons use constant-time algorithms

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This project follows the same license as the underlying libsodium library.

## Acknowledgments

- Based on the [libsodium](https://libsodium.org/) library
- Inspired by the Python [PyNaCl](https://pynacl.readthedocs.io/) library
- Built for the Swift ecosystem with modern Swift best practices
