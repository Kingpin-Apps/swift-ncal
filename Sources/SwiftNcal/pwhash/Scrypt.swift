import Clibsodium
import Foundation

public struct Scrypt {
    public let strbytesPlusOne = Int(crypto_pwhash_scryptsalsa208sha256_strbytes())
    
    public let strPrefix: String = String(cString: crypto_pwhash_scryptsalsa208sha256_strprefix())

    public let saltBytes = Int(crypto_pwhash_scryptsalsa208sha256_saltbytes())
    
    public let passwdMin = Int(crypto_pwhash_scryptsalsa208sha256_passwd_min())
    public let passwdMax = Int(crypto_pwhash_scryptsalsa208sha256_passwd_max())

    public let pwhashSize = Int(crypto_pwhash_scryptsalsa208sha256_strbytes()) - 1
    
    public let bytesMin = Int(crypto_pwhash_scryptsalsa208sha256_bytes_min())
    public let bytesMax = Int(crypto_pwhash_scryptsalsa208sha256_bytes_max())
    
    public let memLimitMin: Int = Int(crypto_pwhash_scryptsalsa208sha256_memlimit_min())
    public let memLimitMax: Int = Int(crypto_pwhash_scryptsalsa208sha256_memlimit_max())
    public let opsLimitMin: Int = Int(crypto_pwhash_scryptsalsa208sha256_opslimit_min())
    public let opsLimitMax: Int = Int(crypto_pwhash_scryptsalsa208sha256_opslimit_max())
    public let opsLimitInteractive: Int = Int(crypto_pwhash_scryptsalsa208sha256_opslimit_interactive())
    public let memLimitInteractive: Int = Int(crypto_pwhash_scryptsalsa208sha256_memlimit_interactive())
    public let opsLimitModerate: Int = 8*Int(crypto_pwhash_scryptsalsa208sha256_opslimit_interactive())
    public let memLimitModerate: Int = 8*Int(crypto_pwhash_scryptsalsa208sha256_memlimit_interactive())
    public let opsLimitSensitive: Int = Int(crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive())
    public let memLimitSensitive: Int = Int(crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive())

    func kdf(size: Int, password: Data, salt: Data, opsLimit: Int? = nil, memLimit: Int? = nil, encoder: (Data) -> Data = { $0 }) throws -> Data {
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
        let memLim = memLimit ?? memLimitSensitive
        let opsLim = opsLimit ?? opsLimitSensitive
        
        try ensure(
            salt.count == saltBytes,
            raising:
                    .valueError(
                        "The salt must be exactly \(saltBytes), not \(salt.count) bytes long"
                    )
        )
        
        let cryptoPwHash = CryptoPwHash()

        let (nLog2, r, p) = cryptoPwHash.naclBindingsPickScryptParams(
            opsLimit: opsLim,
            memLimit: memLim
        )
        let maxMem = memLim + (1 << 16)

        return encoder(
            try cryptoPwHash
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

    func str(password: Data, opsLimit: Int? = nil, memLimit: Int? = nil) throws -> String {
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

        return try CryptoPwHash().scryptsalsa208sha256Str(
            passwd: password,
            opsLimit: opsLimit,
            memLimit: memLimit
        )
    }

    func verify(passwordHash: Data, password: Data) throws -> Bool {
        /**
         Takes the output of scryptsalsa208sha256 and compares it against
         a user provided password to see if they are the same

         - parameter passwordHash: bytes
         - parameter password: bytes
         - returns: boolean
         - throws: UnavailableError if called when using a minimal build of libsodium

         .. versionadded:: 1.2
         */
        
        try ensure(
            passwordHash.count == pwhashSize,
            raising: .valueError("The password hash must be exactly \(strbytesPlusOne) bytes long")
        )

        return try CryptoPwHash()
            .scryptsalsa208sha256StrVerify(
                passwd_hash: passwordHash,
                passwd: password
            )
    }
}
