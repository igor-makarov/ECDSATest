//
//  ECDSAEncryption.swift
//

import Foundation
import Security

// swiftlint:disable force_cast
// swiftlint:disable trailing_whitespace
// swiftlint:disable force_unwrapping
// swiftlint:disable line_length

public enum EncryptionProviderError: Error {
    case failedEncryption(reason: String)
    case failure(reason: String)
    case couldNotRetrieveKey
    case couldNotDeleteKeys
    case inputError
    case failedDecryption(reason: String)
    case secureEnclaveUnavailable
}

/// Encrypt using the Elliptical Curve cryptography
public struct ECDSAEncryption {
    let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorX963SHA256AESGCM
    let useSecureEnclave: Bool
    let tag: String

    public init(useSecureEnclave: Bool, tag: String) {
        self.useSecureEnclave = useSecureEnclave
        self.tag = tag
    }

    // swiftlint:disable:next function_body_length
    public func encrypt(input: Data) throws -> String {

        //Retrieve the key from the keychain.
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]
        
        if useSecureEnclave == true {
            query[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        }
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        let keyPublic: SecKey
        
        if status == errSecSuccess {
            
            //Use the result
            let key = item as! SecKey //private key
            guard let publicKey = SecKeyCopyPublicKey(key) else {
                throw EncryptionProviderError.failedEncryption(reason: "Could not copy the public key")
            } //get the public key
            
            keyPublic = publicKey
        } else {
            //Create new key
            var attributesPrivate = self.attributesPrivate
            var attributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits as String: 256,
                kSecPrivateKeyAttrs as String: attributesPrivate
            ]
            
            var errorPtr: Unmanaged<CFError>?
            
            if useSecureEnclave == true {
                guard Device.hasSecureEnclave else { throw EncryptionProviderError.secureEnclaveUnavailable }
                var errorPtr: Unmanaged<CFError>?
                guard let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                [.privateKeyUsage, .userPresence],
                                                &errorPtr) else {
                                                    throw EncryptionProviderError.failedEncryption(reason: errorPtr?.takeRetainedValue().localizedDescription ?? "No Error")
                }
                attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
                attributesPrivate[kSecAttrAccessControl as String] = access
                attributes[kSecPrivateKeyAttrs as String] = attributesPrivate
            }
            
            guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &errorPtr) else {
                throw EncryptionProviderError.failedEncryption(reason: errorPtr?.takeRetainedValue().localizedDescription ?? "No Error")
            }
            
            guard let key = SecKeyCopyPublicKey(privateKey) else {
                throw EncryptionProviderError.failedEncryption(reason: "Could not get public key.")
            }
            
            keyPublic = key
        }
        
        let data = input
        var errorPtr: Unmanaged<CFError>?
        let signedPayload = SecKeyCreateEncryptedData(keyPublic, algorithm, data as CFData, &errorPtr)
        
        if let errorStr = errorPtr?.takeRetainedValue().localizedDescription {
            
            throw EncryptionProviderError.failedEncryption(reason: errorStr)
        }
        
        let payload = signedPayload as Data?
        let toSave = payload?.base64EncodedString() ?? ""
        return toSave
    }
    
    public var attributesPublic: [String: Any] {
        return [:]
    }
    
    public var attributesPrivate: [String: Any] {
        return [
            kSecAttrApplicationTag as String: tag.data(using: .utf8)! as CFData,
            kSecAttrIsPermanent as String: true
        ]
    }
    
    public func nuke() throws {
        
        //Retrieve the key from the keychain.
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag.data(using: .utf8)! as CFData,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        
        if useSecureEnclave == true {
            query[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        }
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        if status != errSecSuccess {
            
            if status == errSecItemNotFound {
                throw EncryptionProviderError.failure(reason: "Item not found.")
            }
            
            throw EncryptionProviderError.couldNotRetrieveKey
        }
        
        let tempResults = item as! CFArray
        let results = tempResults as! [[String: Any]]
        
        for attributes in results {
            
            var copyAttr = attributes
            copyAttr[kSecClass as String] = kSecClassKey
            
            if useSecureEnclave == true {
                query[kSecReturnAttributes as String] = nil
                query[kSecMatchLimit as String] = nil
                
                let res = SecItemDelete(query as CFDictionary)
                if res != errSecSuccess {
                    throw EncryptionProviderError.couldNotDeleteKeys
                }
            } else {
             
                let res = SecItemDelete(copyAttr as CFDictionary)
                if res != errSecSuccess {
                    throw EncryptionProviderError.couldNotDeleteKeys
                }
            }
        }
    }
    
    public func decrypt(input: String) throws -> Data {
        //Retrieve the key from the keychain.
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag.data(using: .utf8)! as CFData,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]
        
        if useSecureEnclave == true {
            query[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        }
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        if status == errSecSuccess {
            
            //Use the result
            let key = item as! SecKey //private key
            guard let data = Data(base64Encoded: input) else {
                throw EncryptionProviderError.inputError
            }
            
            var error: Unmanaged<CFError>?
            guard let result = SecKeyCreateDecryptedData(key, algorithm, data as CFData, &error) else {
                throw EncryptionProviderError.failedDecryption(reason: "\(error?.takeRetainedValue().localizedDescription ?? "No Error")")
            }
            
            let retVal = result as Data
            return retVal
        } else {
            throw EncryptionProviderError.failedDecryption(reason: "")
        }
    }
}
