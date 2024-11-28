import Clibsodium
import Foundation

nonisolated(unsafe) private let sodium = Sodium()

class Blake2b {
    /// Maximum digest size
    static let maxDigestSize = sodium.cryptoGenericHash.bytes
    /// Maximum key size
    static let maxKeySize = sodium.cryptoGenericHash.keyBytes
    /// Personalization size
    static let personSize = sodium.cryptoGenericHash.personalBytes
    /// Salt size
    static let saltSize = sodium.cryptoGenericHash.saltBytes

    private var state: Blake2State
    private var digestSize: Int

    /// Blake2b algorithm initializer
    ///
    /// - Parameters:
    ///   - data: The data to hash.
    ///   - digestSize: The requested digest size; must be at most `maxDigestSize`; the default digest size is `bytes`.
    ///   - key: The key to be set for keyed MAC/PRF usage; if set, the key must be at most `maxKeySize` long.
    ///   - salt: An initialization salt at most `saltSize` long; it will be zero-padded if needed.
    ///   - person: A personalization string at most `personSize` long; it will be zero-padded if needed.
    init(data: Data = Data(), digestSize: Int? = nil, key: Data = Data(), salt: Data = Data(), person: Data = Data()) throws {
        self.state = try sodium.cryptoGenericHash
            .blake2bInit(
                key: key,
                salt: salt,
                person: person,
                digestSize: digestSize ?? Blake2b.maxDigestSize
            )
        self.digestSize = digestSize ?? Blake2b.maxDigestSize

        if !data.isEmpty {
            try self.update(data: data)
        }
    }

    var blockSize: Int {
        return 128
    }

    var name: String {
        return "blake2b"
    }

    func update(data: Data) throws {
        try sodium.cryptoGenericHash.blake2bUpdate(state: self.state, data: data)
    }

    func digest() throws -> Data {
        return try sodium.cryptoGenericHash.blake2bFinal(state: self.state)
    }

    func hexdigest() throws -> String {
        return bytesAsString(bytesIn: try digest())
    }

    func copy() throws -> Blake2b {
        let copy = try Blake2b(
            digestSize: self.digestSize)
        copy.state = self.state.copy()
        return copy
    }

    func reduce() throws -> Never {
        throw SodiumError.unavailableError("can't pickle Blake2b objects")
    }
}

public struct Hashlib {
    let bytes = sodium.cryptoGenericHash.bytes
    /// Default digest size for `blake2b` hash
    let bytesMin = sodium.cryptoGenericHash.bytesMin
    /// Minimum allowed digest size for `blake2b` hash
    let bytesMax = sodium.cryptoGenericHash.bytesMax
    /// Maximum allowed digest size for `blake2b` hash
    let keyBytes = sodium.cryptoGenericHash.keyBytes
    /// Default size of the `key` byte array for `blake2b` hash
    let keyBytesMin = sodium.cryptoGenericHash.keyBytesMin
    /// Minimum allowed size of the `key` byte array for `blake2b` hash
    let keyBytesMax = sodium.cryptoGenericHash.keyBytesMax
    /// Maximum allowed size of the `key` byte array for `blake2b` hash
    let saltBytes = sodium.cryptoGenericHash.saltBytes
    /// Maximum allowed length of the `salt` byte array for `blake2b` hash
    let personalBytes = sodium.cryptoGenericHash.personalBytes
    /// Maximum allowed length of the `personalization` byte array for `blake2b` hash

    func scrypt(password: Data, salt: Data = Data(), n: Int = 1 << 4, r: Int = 8, p: Int = 1, maxmem: Int = 1 << 25, dklen: Int = 64) throws -> Data {
        /// Derive a cryptographic key using the scrypt KDF.
        ///
        /// - Parameters:
        ///   - password: The password to hash.
        ///   - salt: The salt to use.
        ///   - n: CPU/memory cost parameter.
        ///   - r: Block size parameter.
        ///   - p: Parallelization parameter.
        ///   - maxmem: Maximum memory to use.
        ///   - dklen: Desired key length.
        /// - Returns: The derived key.
        /// - Throws: `UnavailableError` if called when using a minimal build of libsodium.
        return try sodium.cryptoPwHash
            .scryptsalsa208sha256LL(
                passwd: password,
                salt: salt,
                n: n,
                r: r,
                p: p,
                dklen: dklen,
                maxmem: maxmem
            )
    }
}
