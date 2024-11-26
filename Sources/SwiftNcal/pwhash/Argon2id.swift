import Clibsodium
import Foundation

public struct Argon2id {
    public let alg = Int(crypto_pwhash_alg_argon2id13())
    public let strPrefix: String = String(cString: crypto_pwhash_argon2id_strprefix())

    public let saltBytes = Int(crypto_pwhash_saltbytes())
    
    public let passwdMin = Int(crypto_pwhash_passwd_min())
    public let passwdMax = Int(crypto_pwhash_passwd_max())

    public let pwhashSize = Int(crypto_pwhash_strbytes()) - 1
    
    public let bytesMin = Int(crypto_pwhash_bytes_min())
    public let bytesMax = Int(crypto_pwhash_bytes_max())
    
    public let memLimitMin: Int = Int(crypto_pwhash_argon2id_memlimit_min())
    public let memLimitMax: Int = Int(crypto_pwhash_argon2id_memlimit_max())
    public let opsLimitMin: Int = Int(crypto_pwhash_argon2id_opslimit_min())
    public let opsLimitMax: Int = Int(crypto_pwhash_argon2id_opslimit_max())
    public let opsLimitInteractive: Int = Int(crypto_pwhash_argon2id_opslimit_interactive())
    public let memLimitInteractive: Int = Int(crypto_pwhash_argon2id_memlimit_interactive())
    public let opsLimitModerate: Int = Int(crypto_pwhash_argon2id_opslimit_moderate())
    public let memLimitModerate: Int = Int(crypto_pwhash_argon2id_memlimit_moderate())
    public let opsLimitSensitive: Int = Int(crypto_pwhash_argon2id_opslimit_sensitive())
    public let memLimitSensitive: Int = Int(crypto_pwhash_argon2id_memlimit_sensitive())

    public func verify(passwordHash: Data, password: Data) throws -> Bool {
        /**
         Takes a modular crypt encoded argon2i or argon2id stored password hash
         and checks if the user provided password will hash to the same string
         when using the stored parameters

         - parameter passwordHash: password hash serialized in modular crypt() format
         - parameter password: user provided password
         - returns: boolean

         .. versionadded:: 1.2
         */
        return try CryptoPwHash().strVerify(passwd_hash: passwordHash, passwd: password)
    }

    func kdf(size: Int, password: Data, salt: Data, opsLimit: Int? = nil, memLimit: Int? = nil, encoder: (Data) -> Data = { $0 }) throws -> Data {
        /**
         Derive a `size` bytes long key from a caller-supplied
         `password` and `salt` pair using the argon2i
         memory-hard construct.

         the enclosing module provides the constants

         - `opsLimitInteractive`
         - `memLimitInteractive`
         - `opsLimitModerate`
         - `memLimitModerate`
         - `opsLimitSensitive`
         - `memLimitSensitive`

         as a guidance for correct settings.

         - parameter size: derived key size, must be between `bytesMin` and `bytesMax`
         - parameter password: password used to seed the key derivation procedure; it length must be between `passwdMin` and `passwdMax`
         - parameter salt: **RANDOM** salt used in the key derivation procedure; its length must be exactly `saltBytes`
         - parameter opsLimit: the time component (operation count) of the key derivation procedure's computational cost; it must be between `opsLimitMin` and `opsLimitMax`
         - parameter memLimit: the memory occupation component of the key derivation procedure's computational cost; it must be between `memLimitMin` and `memLimitMax`
         - returns: bytes

         .. versionadded:: 1.2
         */
        let memLim = memLimit ?? memLimitSensitive
        let opsLim = opsLimit ?? opsLimitSensitive
        return encoder(
            try CryptoPwHash()
                .alg(
                    outlen: size,
                    passwd: password,
                    salt: salt,
                    opslimit: opsLim,
                    memlimit: memLim,
                    alg: alg
                )
        )
    }

    public func str(password: Data, opsLimit: Int? = nil, memLimit: Int? = nil) throws -> Data {
        /**
         Hashes a password with a random salt, using the memory-hard
         argon2i construct and returning an ascii string that has all
         the needed info to check against a future password

         The default settings for opsLimit and memLimit are those deemed
         correct for the interactive user login case.

         - parameter password: bytes
         - parameter opsLimit: int
         - parameter memLimit: int
         - returns: bytes

         .. versionadded:: 1.2
         */
        let memLim = memLimit ?? memLimitInteractive
        let opsLim = opsLimit ?? opsLimitInteractive
        return try CryptoPwHash()
            .strAlg(
                passwd: password,
                opslimit: opsLim,
                memlimit: memLim,
                alg: alg
            )
    }
}
