# PackedAES
Simple AES encryption/decryption file

### It is very important to note that the IV should be unique for each message. ###
Explanation and quotes taken from [here](https://crypto.stackexchange.com/questions/3965/what-is-the-main-difference-between-a-key-an-iv-and-a-nonce):
> The IV should be random and unpredictable, or at least unique for each message encrypted with a given key. [...]
> The IV never needs to be kept secret - if it did, it would be a key


### Usage
Currently, there is no support for AES128. It can be created though. Edit the lines: `let keyLength = size_t(kCCKeySizeAES256)` to `let keyLength = size_t(kCCKeySizeAES128)` in the `cryptoOperation` function.

##### AES256
```swift
let cryptor = AESCryptor(iv: "0123456789ABCDEF")
let key = "012345678ABCDEFFEDCBA9876543210"
let message = "A very secret message".data(using: .utf8)!

do {
  let encrypted = try cryptor.encrypt(data: message, key: key)
  print(encrypted)
  
  let decrypted = try cryptor.decrypt(data: encrypted, key: key)
  // Note that the decrypted data is still `Data`
  print(String(data: decrypted, encoding: .utf8) ?? "Decryption failed")
} catch {
  print(error)
}
```

##### AES256 without IV
```swift
let cryptor = AESCryptor()
let key = "123456780123456701234567801234567"
let message = "Another very secret message".data(using: .utf8)!

do {
  let encrypted = try cryptor.encrypt(data: message, key: key)
  print(encrypted)
  
  let decrypted = try cryptor.decrypt(data: encrypted, key: key)
  print(String(data: decrypted, encoding: .utf8) ?? "Decryption failed")
} catch {
  print(error)
}
```
