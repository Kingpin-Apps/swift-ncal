import Clibsodium
import Foundation

nonisolated(unsafe) private let sodium = Sodium()

public struct Argon2 {
    public let strbytesPlusOne = sodium.cryptoPwHash.strBytes

    public let pwhashSize = sodium.cryptoPwHash.strBytes - 1
    public let saltBytes = sodium.cryptoPwHash.saltBytes

    public let passwdMin = sodium.cryptoPwHash.passwdMin
    public let passwdMax = sodium.cryptoPwHash.passwdMax

    public let bytesMax = sodium.cryptoPwHash.bytesMax
    public let bytesMin = sodium.cryptoPwHash.bytesMin

    public let algArgon2i13 = sodium.cryptoPwHash.algArgon2i13
    public let algArgon2id13 = sodium.cryptoPwHash.algArgon2id13
    public let algArgon2Default = sodium.cryptoPwHash.algDefault

    /**
     Takes a modular crypt encoded argon2i or argon2id stored password hash
     and checks if the user provided password will hash to the same string
     when using the stored parameters

     - parameter passwordHash: password hash serialized in modular crypt() format
     - parameter password: user provided password
     - returns: boolean

     .. versionadded:: 1.2
     */
    public func verify(passwordHash: Data, password: Data) throws -> Bool {
        do {
            return try sodium.cryptoPwHash.strVerify(passwd_hash: passwordHash, passwd: password)
        } catch SodiumError.invalidKeyError {
            return false
        }
    }
}
