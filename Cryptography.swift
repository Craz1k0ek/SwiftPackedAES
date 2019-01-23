//
//  Cryptography.swift
//
//  Created by Craz1k0ek on 21/01/2019.
//

import Foundation
import CommonCrypto


/// The `AESError` enum.
enum AESError: Error {
    /// The `IV` is missing.
    case missingIV
    /// The crypto operation failed.
    case cryptoOperationFailed
}

/// The `AESCryptor` class.
class AESCryptor {
    
    /// Automatically use the AES algorithm.
    var algorithm = CCAlgorithm(kCCAlgorithmAES)
    /// Automatically use PKCS7 padding.
    var options = CCOptions(kCCOptionPKCS7Padding)
    /// The cryptors `IV` value.
    var iv: Data?
    
    /// Create the `AESCryptor` without an `IV`.
    ///
    /// - Note: A random `IV` will be generated.
    init() {
        self.iv = String.randomString(ofLength: kCCBlockSizeAES128).data(using: .utf8)!
    }
    
    /// Create the `AESCryptor` with an `IV`.
    ///
    /// - Parameter iv: The `IV` to use during the crypto operation.
    init(iv: String) {
        self.iv = iv.data(using: .utf8)
    }
    
    /// Encrypt a block of data with a given key.
    ///
    /// - Parameters:
    ///   - data: The data to encrypt.
    ///   - key: The key to use during encryption.
    /// - Returns: The ciphertext as a `Data` object.
    /// - Throws: One of the `AESError` objects when an error occurs.
    func encrypt(data: Data, key: String) throws -> Data {
        do {
            return try self.cryptoOperation(data, key: key, operation: CCOperation(kCCEncrypt))
        } catch {
            throw error
        }
    }
    
    /// Decrypt a block of data with a given key.
    ///
    /// - Parameters:
    ///   - data: The ciphertext to decrypt.
    ///   - key: The key to use during decryption.
    /// - Returns: The data of which the plaintext can be created as a `Data` object.
    /// - Throws: One of the `AESError` objects when an error occurs.
    func decrypt(_ data: Data, key: String) throws -> Data {
        do {
            return try self.cryptoOperation(data, key: key, operation: CCOperation(kCCDecrypt))
        } catch {
            throw error
        }
    }
    
    /// Performs the actual crypto operation.
    ///
    /// - Parameters:
    ///   - inputData: The data to perform the operation on.
    ///   - key: The key to use during the operation.
    ///   - operation: The operation (either kCCEncrypt or kCCDecrypt)
    /// - Returns: The data after the crypto operation was succesful.
    /// - Throws: One of the `AESError` objects when an error occurs.
    internal func cryptoOperation(_ inputData: Data, key: String, operation: CCOperation) throws -> Data {
        // Validation
        if iv == nil {
            throw AESError.missingIV
        }
        
        // Prepare parameters
        let keyData: Data! = key.data(using: String.Encoding.utf8, allowLossyConversion: false)!
        let keyBytes = keyData.withUnsafeBytes { (bytes: UnsafePointer<UInt8>) -> UnsafePointer<UInt8> in
            return bytes
        }
        let keyLength       = size_t(kCCKeySizeAES256)
        let dataLength      = Int(inputData.count)
        let dataBytes       = inputData.withUnsafeBytes { (bytes: UnsafePointer<UInt8>) -> UnsafePointer<UInt8> in
            return bytes
        }
        var bufferData      = Data(count: Int(dataLength) + kCCBlockSizeAES128)
        let bufferPointer   = bufferData.withUnsafeMutableBytes { (bytes: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> in
            return bytes
        }
        let bufferLength    = size_t(bufferData.count)
        let ivBuffer: UnsafePointer<UInt8>? = (iv == nil) ? nil : iv!.withUnsafeBytes({ (bytes: UnsafePointer<UInt8>) -> UnsafePointer<UInt8> in
            return bytes
        })
        var bytesDecrypted  = Int(0)
        
        // Perform operation
        let cryptStatus = CCCrypt(operation, algorithm, options, keyBytes, keyLength, ivBuffer, dataBytes, dataLength, bufferPointer, bufferLength, &bytesDecrypted)
        
        if Int32(cryptStatus) == Int32(kCCSuccess) {
            bufferData.count = bytesDecrypted
            return bufferData as Data
        } else {
            print("Error in crypto operation: \(cryptStatus)")
            throw AESError.cryptoOperationFailed
        }
    }
    
}
