//
//  ExtensionString.swift
//
//  Created by Craz1k0ek on 21/01/2019.
//

import Foundation

let kStringLowerCaseAlphabet    = "abcdefghijklmnopqrstuvwxyz"
let kStringUpperCaseAlphabet    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
let kStringNumbersOnly          = "0123456789"

let kStringHexcharacters        = "0123456789ABCDEF"

extension String {
    
    /// Return a random `String` of specified length.
    ///
    /// - Parameters:
    ///   - ofLength: The length of the `String` to create.
    ///   - containingOnly: Characters allowed to create the `String` with.
    /// - Returns: The random `String` with a length as specified.
    static func randomString(ofLength: Int, containingOnly: String = "\(kStringLowerCaseAlphabet)\(kStringUpperCaseAlphabet)\(kStringNumbersOnly)") -> String {
        return String((0 ..< ofLength).map { _ in containingOnly.randomElement()! })
    }
    
}
