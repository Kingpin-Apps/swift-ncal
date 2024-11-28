import Clibsodium
import Foundation

nonisolated(unsafe) private let sodium = Sodium()

public struct Scrypt {
    public let strbytesPlusOne = sodium.cryptoPwHash.scryptsalsa208sha256Strbytes
    
    public let strPrefix: String = sodium.cryptoPwHash.scryptsalsa208sha256Strprefix

    public let saltBytes = sodium.cryptoPwHash.scryptsalsa208sha256Saltbytes
    
    public let passwdMin = sodium.cryptoPwHash.scryptsalsa208sha256PasswdMin
    public let passwdMax = sodium.cryptoPwHash.scryptsalsa208sha256PasswdMax

    public let pwhashSize = sodium.cryptoPwHash.scryptsalsa208sha256Strbytes - 1
    
    public let bytesMin = sodium.cryptoPwHash.scryptsalsa208sha256BytesMin
    public let bytesMax = sodium.cryptoPwHash.scryptsalsa208sha256BytesMax
    
    public let memLimitMin = sodium.cryptoPwHash.scryptsalsa208sha256MemlimitMin
    public let memLimitMax = sodium.cryptoPwHash.scryptsalsa208sha256MemlimitMax
    public let opsLimitMin = sodium.cryptoPwHash.scryptsalsa208sha256OpslimitMin
    public let opsLimitMax = sodium.cryptoPwHash.scryptsalsa208sha256OpslimitMax
    public let opsLimitInteractive = sodium.cryptoPwHash.scryptsalsa208sha256OpslimitInteractive
    public let memLimitInteractive = sodium.cryptoPwHash.scryptsalsa208sha256MemlimitInteractive
    public let opsLimitModerate = 8 * sodium.cryptoPwHash.scryptsalsa208sha256OpslimitInteractive
    public let memLimitModerate = 8 * sodium.cryptoPwHash.scryptsalsa208sha256MemlimitInteractive
    public let opsLimitSensitive = sodium.cryptoPwHash.scryptsalsa208sha256OpslimitSensitive
    public let memLimitSensitive = sodium.cryptoPwHash.scryptsalsa208sha256MemlimitSensitive

    /**
     Derive a `size` bytes long key from a caller-supplied
     `password` and `salt` pair using the scryptsalsa208sha256
     memory-hard construct.

     the enclosing module provides the constants

     - `opsLimitInteractive`
     - `memLimitInteractive`
     - `opsLimitSensitive`
     - `memLimitSensitive`
     - `opsLimitModerate`
     - `memLimitModerate`

     as a guidance for correct settings respectively for the
     interactive login and the long term key protecting sensitive data
     use cases.

     - parameter size: derived key size, must be between `bytesMin` and `bytesMax`
     - parameter password: password used to seed the key derivation procedure; it length must be between `passwdMin` and `passwdMax`
     - parameter salt: **RANDOM** salt used in the key derivation procedure; its length must be exactly `saltBytes`
     - parameter opsLimit: the time component (operation count) of the key derivation procedure's computational cost; it must be between `opsLimitMin` and `opsLimitMax`
     - parameter memLimit: the memory occupation component of the key derivation procedure's computational cost; it must be between `memLimitMin` and `memLimitMax`
     - returns: bytes
     - throws: UnavailableError if called when using a minimal build of libsodium

     .. versionadded:: 1.2
     */
    func kdf(size: Int, password: Data, salt: Data, opsLimit: Int? = nil, memLimit: Int? = nil, encoder: (Data) -> Data = { $0 }) throws -> Data {
        let memLim = memLimit ?? memLimitSensitive
        let opsLim = opsLimit ?? opsLimitSensitive
        
        try ensure(
            salt.count == saltBytes,
            raising:
                    .valueError(
                        "The salt must be exactly \(saltBytes), not \(salt.count) bytes long"
                    )
        )

        let (nLog2, r, p) = sodium.cryptoPwHash.naclBindingsPickScryptParams(
            opsLimit: opsLim,
            memLimit: memLim
        )
        let maxMem = memLim + (1 << 16)

        return encoder(
            try sodium.cryptoPwHash
                .scryptsalsa208sha256LL(
                    passwd: password,
                    salt: salt,
                    n: Int(pow(2.0, Double(nLog2))),
                    r: r,
                    p: p,
                    dklen: size,
                    maxmem: maxMem
                )
        )
    }

    /**
     Hashes a password with a random salt, using the memory-hard
     scryptsalsa208sha256 construct and returning an ascii string
     that has all the needed info to check against a future password

     The default settings for opsLimit and memLimit are those deemed
     correct for the interactive user login case.

     - parameter password: bytes
     - parameter opsLimit: int
     - parameter memLimit: int
     - returns: string
     - throws: UnavailableError if called when using a minimal build of libsodium

     .. versionadded:: 1.2
     */
    func str(password: Data, opsLimit: Int? = nil, memLimit: Int? = nil) throws -> String {
        return try sodium.cryptoPwHash.scryptsalsa208sha256Str(
            passwd: password,
            opsLimit: opsLimit,
            memLimit: memLimit
        )
    }

    /**
     Takes the output of scryptsalsa208sha256 and compares it against
     a user provided password to see if they are the same

     - parameter passwordHash: bytes
     - parameter password: bytes
     - returns: boolean
     - throws: UnavailableError if called when using a minimal build of libsodium

     .. versionadded:: 1.2
     */
    func verify(passwordHash: Data, password: Data) throws -> Bool {
        try ensure(
            passwordHash.count == pwhashSize,
            raising: .valueError("The password hash must be exactly \(strbytesPlusOne) bytes long")
        )
        do {
            return try sodium.cryptoPwHash
                .scryptsalsa208sha256StrVerify(
                    passwd_hash: passwordHash,
                    passwd: password
                )
        } catch SodiumError.invalidKeyError {
            return false
        }

        
    }
}
