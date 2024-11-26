import Clibsodium
import Foundation


public struct CryptoHash {
    
    let bytes = Int(crypto_hash_sha512_bytes())
    let sha256Bytes = Int(crypto_hash_sha256_bytes())
    let sha512Bytes = Int(crypto_hash_sha512_bytes())

    func hash(message: Data) throws -> Data {
        var digest = Data(count: bytes)
        
        let rc = digest.withUnsafeMutableBytes { digestPtr in
            message.withUnsafeBytes { messagPtr in
                guard let digestRawPtr = digestPtr.baseAddress,
                      let messagPtr = messagPtr.baseAddress else {
                    return Int32(-1)
                }
                return crypto_hash(
                    digestRawPtr.assumingMemoryBound(to: UInt8.self),
                    messagPtr.assumingMemoryBound(to: UInt8.self),
                    UInt64(message.count)
                )
            }
        }
            
        try ensure(rc == 0, raising: .runtimeError( "Unexpected library error"))
        return digest
    }

    func sha256(message: Data) throws -> Data {
        var digest = Data(count: sha256Bytes)
        
        let rc = digest.withUnsafeMutableBytes { digestPtr in
            message.withUnsafeBytes { messagPtr in
                guard let digestRawPtr = digestPtr.baseAddress,
                      let messagPtr = messagPtr.baseAddress else {
                    return Int32(-1)
                }
                return crypto_hash_sha256(
                    digestRawPtr.assumingMemoryBound(to: UInt8.self),
                    messagPtr.assumingMemoryBound(to: UInt8.self),
                    UInt64(message.count)
                )
            }
        }
            
        try ensure(rc == 0, raising: .runtimeError( "Unexpected library error"))
        return digest
    }

    func sha512(message: Data) throws -> Data {
        var digest = Data(count: sha512Bytes)
        
        let rc = digest.withUnsafeMutableBytes { digestPtr in
            message.withUnsafeBytes { messagPtr in
                guard let digestRawPtr = digestPtr.baseAddress,
                      let messagPtr = messagPtr.baseAddress else {
                    return Int32(-1)
                }
                return crypto_hash_sha512(
                    digestRawPtr.assumingMemoryBound(to: UInt8.self),
                    messagPtr.assumingMemoryBound(to: UInt8.self),
                    UInt64(message.count)
                )
            }
        }
            
        try ensure(rc == 0, raising: .runtimeError( "Unexpected library error"))
        return digest
    }
}
