import Foundation
import Base32

protocol Encoder {
    static func encode(data: Data) -> Data
    static func decode(data: Data) -> Data
}

class RawEncoder: Encoder {
    static func encode(data: Data) -> Data {
        return data
    }

    static func decode(data: Data) -> Data {
        return data
    }
}

class HexEncoder: Encoder {
    static func encode(data: Data) -> Data {
        return data.map { String(format: "%02hhx", $0) }.joined().data(using: .utf8)!
    }

    static func decode(data: Data) -> Data {
        var bytes = [UInt8]()
        var hexStr = String(data: data, encoding: .utf8)!
        while !hexStr.isEmpty {
            let c = String(hexStr.prefix(2))
            hexStr = String(hexStr.dropFirst(2))
            bytes.append(UInt8(c, radix: 16)!)
        }
        return Data(bytes)
    }
}

class Base16Encoder: Encoder {
    static func encode(data: Data) -> Data {
        return data.base64EncodedString(options: .init(rawValue: 0)).data(using: .utf8)!
    }

    static func decode(data: Data) -> Data {
        return Data(base64Encoded: data, options: .init(rawValue: 0))!
    }
}

class Base32Encoder: Encoder {
    static func encode(data: Data) -> Data {
        return data.base32EncodedString.data(using: .utf8)!
    }

    static func decode(data: Data) -> Data {
        return data.base32DecodedData!
    }
}

class Base64Encoder: Encoder {
    static func encode(data: Data) -> Data {
        return data.base64EncodedData()
    }

    static func decode(data: Data) -> Data {
        return Data(base64Encoded: data)!
    }
}

class URLSafeBase64Encoder: Encoder {
    static func encode(data: Data) -> Data {
        return data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").data(using: .utf8)!
    }

    static func decode(data: Data) -> Data {
        let base64 = String(data: data, encoding: .utf8)!.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        return Data(base64Encoded: base64)!
    }
}

protocol Encodable {
    func encode(encoder: Encoder.Type) -> Data
}

extension Encodable where Self: CustomStringConvertible {
    func encode(encoder: Encoder.Type) -> Data {
        return encoder.encode(data: self.description.data(using: .utf8)!)
    }
}
