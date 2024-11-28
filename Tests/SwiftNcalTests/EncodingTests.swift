import XCTest

@testable import SwiftNcal


class EncoderTests: XCTestCase {
    let text = "The quick brown fox jumps over the lazy dog".data(using: .utf8)!
    let hexEncodedText = "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67".data(using: .utf8)!
    let base16EncodedText = "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==".data(using: .utf8)!
    let base32EncodedText = "KRUGKIDROVUWG2ZAMJZG653OEBTG66BANJ2W24DTEBXXMZLSEB2GQZJANRQXU6JAMRXWO===".data(using: .utf8)!
    let base64EncodedText = "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==".data(using: .utf8)!
    let urlSafeBase64EncodedText = "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==".data(using: .utf8)!

    func testRawEncoder() {
        let encoded = RawEncoder.encode(data: text)
        let decoded = RawEncoder.decode(data: encoded)
        XCTAssertEqual(encoded, text, "RawEncoder encode failed")
        XCTAssertEqual(decoded, text, "RawEncoder decode failed")
    }

    func testHexEncoder() {
        let encoded = HexEncoder.encode(data: text)
        let decoded = HexEncoder.decode(data: encoded)
        XCTAssertEqual(encoded, hexEncodedText, "HexEncoder encode failed")
        XCTAssertEqual(decoded, text, "HexEncoder decode failed")
    }

    func testBase16Encoder() {
        let encoded = Base16Encoder.encode(data: text)
        let decoded = Base16Encoder.decode(data: encoded)
        XCTAssertEqual(encoded, base16EncodedText, "Base16Encoder encode failed")
        XCTAssertEqual(decoded, text, "Base16Encoder decode failed")
    }

    func testBase32Encoder() {
        let encoded = Base32Encoder.encode(data: text)
        let decoded = Base32Encoder.decode(data: encoded)
        XCTAssertEqual(encoded, base32EncodedText, "Base32Encoder encode failed")
        XCTAssertEqual(decoded, text, "Base32Encoder decode failed")
    }

    func testBase64Encoder() {
        let encoded = Base64Encoder.encode(data: text)
        let decoded = Base64Encoder.decode(data: encoded)
        XCTAssertEqual(encoded, base64EncodedText, "Base64Encoder encode failed")
        XCTAssertEqual(decoded, text, "Base64Encoder decode failed")
    }

    func testURLSafeBase64Encoder() {
        let encoded = URLSafeBase64Encoder.encode(data: text)
        let decoded = URLSafeBase64Encoder.decode(data: encoded)
        XCTAssertEqual(encoded, urlSafeBase64EncodedText, "URLSafeBase64Encoder encode failed")
        XCTAssertEqual(decoded, text, "URLSafeBase64Encoder decode failed")
    }
}
