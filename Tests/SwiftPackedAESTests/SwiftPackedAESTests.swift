import XCTest
@testable import SwiftPackedAES

final class SwiftPackedAESTests: XCTestCase {
    
    func testCryptorKeyFail() {
        let invalidKey = Data(repeating: 0, count: 8)
        
        XCTAssertThrowsError(try AES(key: invalidKey))
    }
    
    func testCryptorInvalidIV() throws {
        let key = Data(repeating: 1, count: 16)
        let invalidIV = Data(repeating: 0, count: 8)
        
        XCTAssertNoThrow(try AES(key: Data(key)))
        let cryptor = try AES(key: Data(key))
        
        let message = Data("hello world 1234".utf8)
        
        XCTAssertThrowsError(try cryptor.encrypt(message, iv: invalidIV, options: .noPadding))
    }
    
    func testCryptoOperationFailure() throws {
        let key = Data(repeating: 1, count: 16)
        
        XCTAssertNoThrow(try AES(key: Data(key)))
        let cryptor = try AES(key: Data(key))
        
        // Invalid message size
        let message = Data("hello world 12".utf8)
        
        XCTAssertThrowsError(try cryptor.encrypt(message, iv: AES.nullIV, options: .noPadding))
    }
    
    /*
     AES tests as defined in appendix C:
     https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
     */
    
    func testAES128Encrypt() throws {
        let plainText: [UInt8] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
        ]
        let key: [UInt8] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        ]
        let output: [UInt8] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
            0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
        ]
        
        XCTAssertNoThrow(try AES(key: Data(key)))
        let cryptor = try AES(key: Data(key))
        
        XCTAssertNoThrow(try cryptor.encrypt(Data(plainText), iv: AES.nullIV, options: .noPadding))
        let cipherText = try cryptor.encrypt(Data(plainText), iv: AES.nullIV, options: .noPadding)
        
        XCTAssertEqual(cipherText, Data(output))
        
        XCTAssertNoThrow(try AES.encrypt(Data(plainText), key: Data(key), iv: AES.nullIV, options: .noPadding))
        XCTAssertEqual(try AES.encrypt(Data(plainText), key: Data(key), iv: AES.nullIV, options: .noPadding), Data(output))
        
        XCTAssertNoThrow(try Data(plainText).encrypt(key: Data(key), iv: AES.nullIV, options: .noPadding))
        XCTAssertEqual(try Data(plainText).encrypt(key: Data(key), iv: AES.nullIV, options: .noPadding), Data(output))
    }
    
    func testAES128Decrypt() throws {
        let cipherText: [UInt8] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
            0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
        ]
        let key: [UInt8] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        ]
        let output: [UInt8] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
        ]
        
        XCTAssertNoThrow(try AES(key: Data(key)))
        let cryptor = try AES(key: Data(key))
        
        XCTAssertNoThrow(try cryptor.decrypt(Data(cipherText), iv: AES.nullIV, options: .noPadding))
        let plainText = try cryptor.decrypt(Data(cipherText), iv: AES.nullIV, options: .noPadding)
        
        XCTAssertEqual(plainText, Data(output))
        
        XCTAssertNoThrow(try AES.decrypt(Data(cipherText), key: Data(key), iv: AES.nullIV, options: .noPadding))
        XCTAssertEqual(try AES.decrypt(Data(cipherText), key: Data(key), iv: AES.nullIV, options: .noPadding), Data(output))
        
        XCTAssertNoThrow(try Data(cipherText).decrypt(key: Data(key), iv: AES.nullIV, options: .noPadding))
        XCTAssertEqual(try Data(cipherText).decrypt(key: Data(key), iv: AES.nullIV, options: .noPadding), Data(output))
    }
    
    func testAES192Encrypt() throws {
        let plainText: [UInt8] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
        ]
        let key: [UInt8] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
        ]
        let output: [UInt8] = [
            0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
            0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91
        ]
        
        XCTAssertNoThrow(try AES(key: Data(key)))
        let cryptor = try AES(key: Data(key))
        
        XCTAssertNoThrow(try cryptor.encrypt(Data(plainText), iv: AES.nullIV, options: .noPadding))
        let cipherText = try cryptor.encrypt(Data(plainText), iv: AES.nullIV, options: .noPadding)
        
        XCTAssertEqual(cipherText, Data(output))
        
        XCTAssertNoThrow(try AES.encrypt(Data(plainText), key: Data(key), iv: AES.nullIV, options: .noPadding))
        XCTAssertEqual(try AES.encrypt(Data(plainText), key: Data(key), iv: AES.nullIV, options: .noPadding), Data(output))
        
        XCTAssertNoThrow(try Data(plainText).encrypt(key: Data(key), iv: AES.nullIV, options: .noPadding))
        XCTAssertEqual(try Data(plainText).encrypt(key: Data(key), iv: AES.nullIV, options: .noPadding), Data(output))
    }
    
    func testAES192Decrypt() throws {
        let cipherText: [UInt8] = [
            0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
            0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91
        ]
        let key: [UInt8] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
        ]
        let output: [UInt8] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
        ]
        
        XCTAssertNoThrow(try AES(key: Data(key)))
        let cryptor = try AES(key: Data(key))
        
        XCTAssertNoThrow(try cryptor.decrypt(Data(cipherText), iv: AES.nullIV, options: .noPadding))
        let plainText = try cryptor.decrypt(Data(cipherText), iv: AES.nullIV, options: .noPadding)
        
        XCTAssertEqual(plainText, Data(output))
        
        XCTAssertNoThrow(try AES.decrypt(Data(cipherText), key: Data(key), iv: AES.nullIV, options: .noPadding))
        XCTAssertEqual(try AES.decrypt(Data(cipherText), key: Data(key), iv: AES.nullIV, options: .noPadding), Data(output))
        
        XCTAssertNoThrow(try Data(cipherText).decrypt(key: Data(key), iv: AES.nullIV, options: .noPadding))
        XCTAssertEqual(try Data(cipherText).decrypt(key: Data(key), iv: AES.nullIV, options: .noPadding), Data(output))
    }
    
    func testAES256Encrypt() throws {
        let plainText: [UInt8] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
        ]
        let key: [UInt8] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        ]
        let output: [UInt8] = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
            0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89
        ]
        
        XCTAssertNoThrow(try AES(key: Data(key)))
        let cryptor = try AES(key: Data(key))
        
        XCTAssertNoThrow(try cryptor.encrypt(Data(plainText), iv: AES.nullIV, options: .noPadding))
        let cipherText = try cryptor.encrypt(Data(plainText), iv: AES.nullIV, options: .noPadding)
        
        XCTAssertEqual(cipherText, Data(output))
        
        XCTAssertNoThrow(try AES.encrypt(Data(plainText), key: Data(key), iv: AES.nullIV, options: .noPadding))
        XCTAssertEqual(try AES.encrypt(Data(plainText), key: Data(key), iv: AES.nullIV, options: .noPadding), Data(output))
        
        XCTAssertNoThrow(try Data(plainText).encrypt(key: Data(key), iv: AES.nullIV, options: .noPadding))
        XCTAssertEqual(try Data(plainText).encrypt(key: Data(key), iv: AES.nullIV, options: .noPadding), Data(output))
    }
    
    func testAES256Decrypt() throws {
        let cipherText: [UInt8] = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
            0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89
        ]
        let key: [UInt8] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        ]
        let output: [UInt8] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
        ]
        
        XCTAssertNoThrow(try AES(key: Data(key)))
        let cryptor = try AES(key: Data(key))
        
        XCTAssertNoThrow(try cryptor.decrypt(Data(cipherText), iv: AES.nullIV, options: .noPadding))
        let plainText = try cryptor.decrypt(Data(cipherText), iv: AES.nullIV, options: .noPadding)
        
        XCTAssertEqual(plainText, Data(output))
        
        XCTAssertNoThrow(try AES.decrypt(Data(cipherText), key: Data(key), iv: AES.nullIV, options: .noPadding))
        XCTAssertEqual(try AES.decrypt(Data(cipherText), key: Data(key), iv: AES.nullIV, options: .noPadding), Data(output))
        
        XCTAssertNoThrow(try Data(cipherText).decrypt(key: Data(key), iv: AES.nullIV, options: .noPadding))
        XCTAssertEqual(try Data(cipherText).decrypt(key: Data(key), iv: AES.nullIV, options: .noPadding), Data(output))
    }
    
}
