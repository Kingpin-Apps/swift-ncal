import Clibsodium
import Foundation

public struct Argon2 {
    public let strbytesPlusOne = Int(crypto_pwhash_strbytes())

    public let pwhashSize = Int(crypto_pwhash_strbytes()) - 1
    public let saltBytes = Int(crypto_pwhash_saltbytes())

    public let passwdMin = Int(crypto_pwhash_passwd_min())
    public let passwdMax = Int(crypto_pwhash_passwd_max())

    public let bytesMax = Int(crypto_pwhash_bytes_max())
    public let bytesMin = Int(crypto_pwhash_bytes_min())

    public let algArgon2i13 = Int(crypto_pwhash_alg_argon2i13())
    public let algArgon2id13 = Int(crypto_pwhash_alg_argon2id13())
    public let algArgon2Default = Int(crypto_pwhash_alg_default())

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
}
