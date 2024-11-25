import Clibsodium
import Foundation

// Define UINT64_MAX and SIZE_MAX
let UINT64_MAX: UInt64 = UInt64.max
let SIZE_MAX: UInt64 = {
    if UInt.bitWidth == 64 {
        return UInt64.max
    } else {
        return UInt64(UInt32.max)
    }
}()

let sodiumSizeMax: UInt64 = {
    return min(UINT64_MAX, SIZE_MAX)
}()

public struct SwiftNcal {

    public let cryptoAead = CryptoAead()
    public let cryptoBox = CryptoBox()
    public let cryptoCore = CryptoCore()
    public let cryptoScalarmult = CryptoScalarmult()
    public let cryptoSign = CryptoSign()
    public let randomBytes = RandomBytes()
    public let utils = Utils()
    public let version = Version()
    
    //    public let secretBox = SecretBox()
    //    public let genericHash = GenericHash()
    //    public let pwHash = PWHash()
    //    public let shortHash = ShortHash()
    //    public let sign = Sign()
    //    public let keyExchange = KeyExchange()
    //    public let auth = Auth()
    //    public let stream = Stream()
    //    public let keyDerivation = KeyDerivation()
    //    public let secretStream = SecretStream()
    //    public let aead = Aead()

    public init() {
        _ = SwiftNcal.once
    }
}

extension SwiftNcal {
    private static let once: Void = {
        guard sodium_init() >= 0 else {
            fatalError("Failed to initialize libsodium")
        }
        print("Global initialization of the package")
    }()
}
