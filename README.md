# PackedAES
Simple AES encryption/decryption file

![Swift](https://github.com/Craz1k0ek/SwiftPackedAES/workflows/Swift/badge.svg)

### Usage

For easy access to the single file, please go [here](https://github.com/Craz1k0ek/SwiftPackedAES/blob/master/Sources/SwiftPackedAES/SwiftPackedAES.swift).

You can use the code as follows.

```swift
do {
    let cryptor = try! AES(key: "0123456789ABCDEF")
    let iv      = Data("0123456789ABCDEF".utf8)
    
    let cipherText  = try cryptor.encrypt(Data("blocksizemessage".utf8), iv: iv)
    let plainText   = try cryptor.decrypt(cipherText, iv: iv)
    
    print(String(data: plainText, encoding: .utf8) ?? "Decryption failed, non UTF8 data returned")
} catch {
    print(error)
}
```

#### Block sizes

This AES operation works based on the AES block size. If your message is not a multiple of a block size, the crypto operation will fail.
To prevent this from happening, use `PKCS#7` padding, which is included in the options.

```swift
// "message" converted to data is not exactly a block size, padding is required
try cryptor.encrypt(Data("message".utf8), iv: iv, options: .pkcs7Padding)
```

#### IV

Note that it is very important that hte IV and key combination, should be unique for every crypto operation. 
It is highly recommended you generate a random key or random IV each time you perform a crypto operation.

Explanation and quotes taken from [here](https://crypto.stackexchange.com/questions/3965/what-is-the-main-difference-between-a-key-an-iv-and-a-nonce):
> The IV should be random and unpredictable, or at least unique for each message encrypted with a given key. [...]
> The IV never needs to be kept secret - if it did, it would be a key

However, if you use a random key each time, it's fine to use an all zero IV, which is included via `AES.nullIV`.

```swift
try cryptor.encrypt(plainText, iv: AES.nullIV, options: .pkcs7Padding)
```

#### One liners

There are also one liners to quickly encrypt and decrypt. Some of these one liners also have an implementation on the `Data` type and `String` type through an extension.

_One liners_
```swift
try AES.encrypt("message", key: key, iv: iv, options: .pkcs7Padding)

try AES.decrypt(cipherText, key: key, iv: iv, options: .pkcs7Padding)
```

_Extensions_

String example
```swift
let key = Data(repeating: 0, count: 16)
let iv  = Data(repeating: 6, count: 16)

try "message".encrypt(key: key, iv: iv, options: .pkcs7Padding)
```

Data example
```swift
let key = Data(repeating: 0, count: 16)
let iv  = Data(repeating: 8, count: 16)

try Data(repeating: 9, count: 8).encrypt(key: key, iv: iv, options: .pkcs7Padding)
```
