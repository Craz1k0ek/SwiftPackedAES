import Foundation
import CommonCrypto

public struct AES {
    
    public static let nullIV = Data(repeating: 0, count: kCCBlockSizeAES128)
    
    /// The available crypto operations.
    public enum Operation: Int {
        /// The encrypt operation.
        case encrypt = 0
        /// The decrypt operation.
        case decrypt = 1
        
        internal var operation: CCOperation { CCOperation(self.rawValue) }
    }
    
    /// All supported AES key sizes.
    public enum KeySize: Int {
        /// 128 bits AES key size.
        case aes128 = 16
        /// 192 bits AES key size.
        case aes192 = 24
        /// 256 bits AES key size.
        case aes256 = 32
        
        /// The `size_t` value.
        internal var size: size_t {
            switch self {
            case .aes128: return size_t(kCCKeySizeAES128)
            case .aes192: return size_t(kCCKeySizeAES192)
            case .aes256: return size_t(kCCKeySizeAES256)
            }
        }
    }
    
    /// AES errors.
    public enum Error: Swift.Error {
        /// An invalid key size was used.
        case invalidKeySize(Int)
        /// An invalid key was provided.
        case invalidKey
        /// An invalid plain text was provided.
        case invalidPlainText
        /// An invalid IV size was used.
        case invalidIVSize(Int)
        /// The crypto operation could not be executed.
        case operationFailed
    }
    
    /// Options to use during AES crypto.
    public struct Option: OptionSet {
        public let rawValue: CCOptions
        
        public init(rawValue: UInt32) {
            self.rawValue = rawValue
        }
        
        /// Don't use padding during the crypto operation.
        public static let noPadding    = Option(rawValue: CCOptions())
        /// Use PKCS#7 padding during the crypto operation.
        public static let pkcs7Padding = Option(rawValue: CCOptions(kCCOptionPKCS7Padding))
    }
    
    /// The AES key.
    fileprivate let key: Data
    
    /// Initialize the cryptor using a key.
    /// - Parameter key: The key.
    init(key: Data) throws {
        guard KeySize(rawValue: key.count)?.size != nil else { throw AES.Error.invalidKeySize(key.count) }
        self.key = key
    }
    
    /// Initialize the cryptor using a key.
    /// - Parameter key: The key as `String`.
    ///
    /// The key will be encoded using `.utf8`.
    init(key: String) throws {
        guard let key = key.data(using: .utf8) else { throw AES.Error.invalidKey }
        try self.init(key: key)
    }
    
    // MARK: - Operations
    
    /// Performs the AES operation with given parameters.
    /// - Parameters:
    ///   - operation: The operation to perform (`.encrypt`/`.decrypt`).
    ///   - input: The data to perform the operation on.
    ///   - iv: The iv to use during the operation.
    ///   - options: The options used for the operation (defaults to `.noPadding`).
    private func primitive(operation: Operation, input: Data, iv: Data, options: Option) throws -> Data {
        guard iv.count == kCCBlockSizeAES128 else { throw AES.Error.invalidIVSize(iv.count) }
        
        // Put it in byte arrays, so CommonCrypto can use it.
        let keyBytes    = Array(key)
        let inputBytes  = Array(input)
        let ivBytes     = Array(iv)
        
        // Prepare the output.
        var outputBytes = [UInt8](repeating: 0, count: kCCBlockSizeAES128 + input.count)
        var numberOfConsumedBytes = 0
        
        // Perform the operation.
        let status = CCCrypt(operation.operation, CCAlgorithm(kCCAlgorithmAES), options.rawValue, keyBytes, keyBytes.count, ivBytes, inputBytes, inputBytes.count, &outputBytes, outputBytes.count, &numberOfConsumedBytes)
        
        // Verify cryptor status.
        guard status == CCCryptorStatus(kCCSuccess) else {
            throw AES.Error.operationFailed
        }
        // Cut off unnecessary, superfluous data from the output.
        return Data(outputBytes)[..<numberOfConsumedBytes]
    }
    
    /// Encrypt data using AES.
    /// - Parameters:
    ///   - input: The data to encrypt.
    ///   - iv: The iv to use during encryption.
    ///   - options: The options used for the operation (defaults to `.noPadding`).
    public func encrypt(_ input: Data, iv: Data, options: Option = .noPadding) throws -> Data {
        try primitive(operation: .encrypt, input: input, iv: iv, options: options)
    }
    
    /// Decrypt data using AES.
    /// - Parameters:
    ///   - cipherText: The cipher text to decrypt.
    ///   - iv: The iv to use during decryption.
    ///   - options: The options used for the operation (defaults to `.noPadding`).
    public func decrypt(_ cipherText: Data, iv: Data, options: Option = .noPadding) throws -> Data {
        try primitive(operation: .decrypt, input: cipherText, iv: iv, options: options)
    }
    
    // MARK: - Static one shot functions
    
    /// Encrypt data using AES.
    /// - Parameters:
    ///   - input: The data to encrypt.
    ///   - key: The key to use during encryption.
    ///   - iv: The iv to use during encryption.
    ///   - options: The options used for the operation (defaults to `.noPadding`).
    public static func encrypt(_ input: Data, key: Data, iv: Data, options: Option = .noPadding) throws -> Data {
        try AES(key: key).encrypt(input, iv: iv, options: options)
    }
    
    /// Encrypt data using AES.
    /// - Parameters:
    ///   - input: The data to encrypt.
    ///   - key: The key to use during encryption.
    ///   - iv: The iv to use during encryption.
    ///   - options: The options used for the operation (defaults to `.noPadding`).
    public static func encrypt(_ input: Data, key: String, iv: Data, options: Option = .noPadding) throws -> Data {
        try AES(key: key).encrypt(input, iv: iv, options: options)
    }
    
    /// Encrypt data using AES.
    /// - Parameters:
    ///   - input: The data to encrypt.
    ///   - key: The key to use during encryption.
    ///   - iv: The iv to use during encryption.
    ///   - options: The options used for the operation (defaults to `.noPadding`).
    public static func encrypt(_ input: String, key: Data, iv: Data, options: Option = .noPadding) throws -> Data {
        guard let plainText = input.data(using: .utf8) else { throw AES.Error.invalidPlainText }
        return try AES(key: key).encrypt(plainText, iv: iv, options: options)
    }
    
    /// Encrypt data using AES.
    /// - Parameters:
    ///   - input: The data to encrypt.
    ///   - key: The key to use during encryption.
    ///   - iv: The iv to use during encryption.
    ///   - options: The options used for the operation (defaults to `.noPadding`).
    public static func encrypt(_ input: String, key: String, iv: Data, options: Option = .noPadding) throws -> Data {
        guard let plainText = input.data(using: .utf8) else { throw AES.Error.invalidPlainText }
        return try AES(key: key).encrypt(plainText, iv: iv, options: options)
    }
    
    /// Decrypt data using AES.
    /// - Parameters:
    ///   - cipherText: The cipher text to decrypt.
    ///   - key: The key to use during decryption.
    ///   - iv: The iv to use during decryption.
    ///   - options: The options used for the operation (defaults to `.noPadding`).
    public static func decrypt(_ cipherText: Data, key: Data, iv: Data, options: Option = .noPadding) throws -> Data {
        try AES(key: key).decrypt(cipherText, iv: iv, options: options)
    }
    
    /// Decrypt data using AES.
    /// - Parameters:
    ///   - cipherText: The cipher text to decrypt.
    ///   - key: The key to use during decryption.
    ///   - iv: The iv to use during decryption.
    ///   - options: The options used for the operation (defaults to `.noPadding`).
    public static func decrypt(_ cipherText: Data, key: String, iv: Data, options: Option = .noPadding) throws -> Data {
        try AES(key: key).decrypt(cipherText, iv: iv, options: options)
    }
    
}

public extension Data {
    
    /// Encrypt current data object using AES.
    /// - Parameters:
    ///   - key: The key to use during encryption.
    ///   - iv: The iv to use during encryption.
    ///   - options: The options used for the operation (defaults to `.noPadding`).
    func encrypt(key: Data, iv: Data, options: AES.Option = .noPadding) throws -> Data {
        try AES.encrypt(self, key: key, iv: iv, options: options)
    }
    
    /// Encrypt current data object using AES.
    /// - Parameters:
    ///   - key: The key to use during encryption.
    ///   - iv: The iv to use during encryption.
    ///   - options: The options used for the operation (defaults to `.noPadding`).
    func encrypt(key: String, iv: Data, options: AES.Option = .noPadding) throws -> Data {
        try AES.encrypt(self, key: key, iv: iv, options: options)
    }
    
    /// Decrypt current data object using AES.
    /// - Parameters:
    ///   - key: The key to use during decryption.
    ///   - iv: The iv to use during decryption.
    ///   - options: The options used for the operation (defaults to `.noPadding`).
    func decrypt(key: Data, iv: Data, options: AES.Option = .noPadding) throws -> Data {
        try AES.decrypt(self, key: key, iv: iv, options: options)
    }
    
    /// Decrypt current data object using AES.
    /// - Parameters:
    ///   - key: The key to use during decryption.
    ///   - iv: The iv to use during decryption.
    ///   - options: The options used for the operation (defaults to `.noPadding`).
    func decrypt(key: String, iv: Data, options: AES.Option = .noPadding) throws -> Data {
        try AES.decrypt(self, key: key, iv: iv, options: options)
    }
    
}

public extension String {
    
    /// Encrypt current string object using AES.
    /// - Parameters:
    ///   - key: The key to use during encryption.
    ///   - iv: The iv to use during encryption.
    ///   - options: The options used for the operation (defaults to `.noPadding`).
    func encrypt(key: Data, iv: Data, options: AES.Option = .noPadding) throws -> Data {
        try AES.encrypt(self, key: key, iv: iv, options: options)
    }
    
    /// Encrypt current string object using AES.
    /// - Parameters:
    ///   - key: The key to use during encryption.
    ///   - iv: The iv to use during encryption.
    ///   - options: The options used for the operation (defaults to `.noPadding`).
    func encrypt(key: String, iv: Data, options: AES.Option = .noPadding) throws -> Data {
        try AES.encrypt(self, key: key, iv: iv, options: options)
    }
    
}
