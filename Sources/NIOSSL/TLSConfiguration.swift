//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2021 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@_implementationOnly import CNIOBoringSSL
import NIOCore

/// Known and supported TLS versions.
public enum TLSVersion: NIOSendable {
    case tlsv1
    case tlsv11
    case tlsv12
    case tlsv13
}

/// Places NIOSSL can obtain certificates from.
public enum NIOSSLCertificateSource: Hashable, NIOSendable {
    @available(*, deprecated, message: "Use 'NIOSSLCertificate.fromPEMFile(_:)' to load the certificate(s) and use the '.certificate(NIOSSLCertificate)' case to provide them as a source")
    case file(String)
    case certificate(NIOSSLCertificate)
}

/// Places NIOSSL can obtain private keys from.
public enum NIOSSLPrivateKeySource: Hashable {
    case file(String)
    case privateKey(NIOSSLPrivateKey)
}

#if swift(>=5.6)
extension NIOSSLPrivateKeySource: Sendable {}
#endif

/// Places NIOSSL can obtain a trust store from.
public enum NIOSSLTrustRoots: Hashable, NIOSendable {
    /// Path to either a file of CA certificates in PEM format, or a directory containing CA certificates in PEM format.
    ///
    /// If a path to a file is provided, the file can contain several CA certificates identified by
    ///
    ///     -----BEGIN CERTIFICATE-----
    ///     ... (CA certificate in base64 encoding) ...
    ///     -----END CERTIFICATE-----
    ///
    /// sequences. Before, between, and after the certificates, text is allowed which can be used e.g.
    /// for descriptions of the certificates.
    ///
    /// If a path to a directory is provided, the files each contain one CA certificate in PEM format.
    case file(String)

    /// A list of certificates.
    case certificates([NIOSSLCertificate])

    /// The system default root of trust.
    case `default`

    internal init(from trustRoots: NIOSSLAdditionalTrustRoots) {
        switch trustRoots {
        case .file(let path):
            self = .file(path)
        case .certificates(let certs):
            self = .certificates(certs)
        }
    }
}

/// Places NIOSSL can obtain additional trust roots from.
public enum NIOSSLAdditionalTrustRoots: Hashable, NIOSendable {
    /// See ``NIOSSLTrustRoots/file(_:)``
    case file(String)

    /// See ``NIOSSLTrustRoots/certificates(_:)``
    case certificates([NIOSSLCertificate])
}

/// Available ciphers to use for TLS instead of a string based representation.
public struct NIOTLSCipher: RawRepresentable, Hashable, NIOSendable {
    /// Construct a ``NIOTLSCipher`` from the RFC code point for that cipher.
    public init(rawValue: UInt16) {
        self.rawValue = rawValue
    }

    /// Construct a ``NIOTLSCipher`` from the RFC code point for that cipher.
    public init(_ rawValue: RawValue) {
        self.rawValue = rawValue
    }

    /// The RFC code point for the given cipher.
    public var rawValue: UInt16
    public typealias RawValue = UInt16
    
    public static let TLS_RSA_WITH_AES_128_CBC_SHA                    = NIOTLSCipher(rawValue: 0x2F)
    public static let TLS_RSA_WITH_AES_256_CBC_SHA                    = NIOTLSCipher(rawValue: 0x35)
    public static let TLS_PSK_WITH_AES_128_CBC_SHA                    = NIOTLSCipher(rawValue: 0x8C)
    public static let TLS_PSK_WITH_AES_256_CBC_SHA                    = NIOTLSCipher(rawValue: 0x8D)
    public static let TLS_RSA_WITH_AES_128_GCM_SHA256                 = NIOTLSCipher(rawValue: 0x9C)
    public static let TLS_RSA_WITH_AES_256_GCM_SHA384                 = NIOTLSCipher(rawValue: 0x9D)
    public static let TLS_AES_128_GCM_SHA256                          = NIOTLSCipher(rawValue: 0x1301)
    public static let TLS_AES_256_GCM_SHA384                          = NIOTLSCipher(rawValue: 0x1302)
    public static let TLS_CHACHA20_POLY1305_SHA256                    = NIOTLSCipher(rawValue: 0x1303)
    public static let TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA            = NIOTLSCipher(rawValue: 0xC009)
    public static let TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA            = NIOTLSCipher(rawValue: 0xC00A)
    public static let TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA              = NIOTLSCipher(rawValue: 0xC013)
    public static let TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA              = NIOTLSCipher(rawValue: 0xC014)
    public static let TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA              = NIOTLSCipher(rawValue: 0xC035)
    public static let TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA              = NIOTLSCipher(rawValue: 0xC036)
    public static let TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256         = NIOTLSCipher(rawValue: 0xC02B)
    public static let TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384         = NIOTLSCipher(rawValue: 0xC02C)
    public static let TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256           = NIOTLSCipher(rawValue: 0xC02F)
    public static let TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384           = NIOTLSCipher(rawValue: 0xC030)
    public static let TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256     = NIOTLSCipher(rawValue: 0xCCA8)
    public static let TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256   = NIOTLSCipher(rawValue: 0xCCA9)
    
    public var standardName: String {
        let boringSSLCipher = CNIOBoringSSL_SSL_get_cipher_by_value(self.rawValue)
        return String(cString: CNIOBoringSSL_SSL_CIPHER_standard_name(boringSSLCipher))
    }
}

/// Formats NIOSSL supports for serializing keys and certificates.
public enum NIOSSLSerializationFormats: NIOSendable {
    case pem
    case der
}

/// Certificate verification modes.
public enum CertificateVerification: NIOSendable {
    /// All certificate verification disabled.
    case none

    /// Certificates will be validated against the trust store, but will not
    /// be checked to see if they are valid for the given hostname.
    case noHostnameVerification

    /// Certificates will be validated against the trust store and checked
    /// against the hostname of the service we are contacting.
    case fullVerification
}

/// Support for TLS renegotiation.
///
/// In general, renegotiation should not be enabled except in circumstances where it is absolutely necessary.
/// Renegotiation is only supported in TLS 1.2 and earlier, and generally does not work very well. NIOSSL will
/// disallow most uses of renegotiation: the only supported use-case is to perform post-connection authentication
/// *as a client*. There is no way to initiate a TLS renegotiation in NIOSSL.
public enum NIORenegotiationSupport: NIOSendable {
    /// No support for TLS renegotiation. The default and recommended setting.
    case none

    /// Allow renegotiation exactly once. If you must use renegotiation, use this setting.
    case once

    /// Allow repeated renegotiation. To be avoided.
    case always
}

/// Signature algorithms. The values are defined as in TLS 1.3
public struct SignatureAlgorithm : RawRepresentable, Hashable, NIOSendable {
    
    public typealias RawValue = UInt16
    public var rawValue: UInt16
    
    public init(rawValue: UInt16) {
        self.rawValue = rawValue
    }
    
    public static let rsaPkcs1Sha1 = SignatureAlgorithm(rawValue: 0x0201)
    public static let rsaPkcs1Sha256 = SignatureAlgorithm(rawValue: 0x0401)
    public static let rsaPkcs1Sha384 = SignatureAlgorithm(rawValue: 0x0501)
    public static let rsaPkcs1Sha512 = SignatureAlgorithm(rawValue: 0x0601)
    public static let ecdsaSha1 = SignatureAlgorithm(rawValue: 0x0203)
    public static let ecdsaSecp256R1Sha256 = SignatureAlgorithm(rawValue: 0x0403)
    public static let ecdsaSecp384R1Sha384 = SignatureAlgorithm(rawValue: 0x0503)
    public static let ecdsaSecp521R1Sha512 = SignatureAlgorithm(rawValue: 0x0603)
    public static let rsaPssRsaeSha256 = SignatureAlgorithm(rawValue: 0x0804)
    public static let rsaPssRsaeSha384 = SignatureAlgorithm(rawValue: 0x0805)
    public static let rsaPssRsaeSha512 = SignatureAlgorithm(rawValue: 0x0806)
    public static let ed25519 = SignatureAlgorithm(rawValue: 0x0807)
}


/// A secure default configuration of cipher suites for TLS 1.2 and earlier.
///
/// The goal of this cipher suite string is:
/// - Prefer cipher suites that offer Perfect Forward Secrecy (DHE/ECDHE)
/// - Prefer ECDH(E) to DH(E) for performance.
/// - Prefer any AEAD cipher suite over non-AEAD suites for better performance and security
/// - Prefer AES-GCM over ChaCha20 because hardware-accelerated AES is common
/// - Disable NULL authentication and encryption and any appearance of MD5
public let defaultCipherSuites = [
    "ECDH+AESGCM",
    "ECDH+CHACHA20",
    "DH+AESGCM",
    "DH+CHACHA20",
    "ECDH+AES256",
    "DH+AES256",
    "ECDH+AES128",
    "DH+AES",
    "RSA+AESGCM",
    "RSA+AES",
    "!aNULL",
    "!eNULL",
    "!MD5",
    ].joined(separator: ":")

/// Encodes a string to the wire format of an ALPN identifier. These MUST be ASCII, and so
/// this routine will crash the program if they aren't, as these are always user-supplied
/// strings.
internal func encodeALPNIdentifier(identifier: String) -> [UInt8] {
    var encodedIdentifier = [UInt8]()
    encodedIdentifier.append(UInt8(identifier.utf8.count))

    for codePoint in identifier.unicodeScalars {
        encodedIdentifier.append(contentsOf: Unicode.ASCII.encode(codePoint)!)
    }

    return encodedIdentifier
}

/// Decodes a string from the wire format of an ALPN identifier. These MUST be correctly
/// formatted ALPN identifiers, and so this routine will crash the program if they aren't.
internal func decodeALPNIdentifier(identifier: [UInt8]) -> String {
    return String(decoding: identifier[1..<identifier.count], as: Unicode.ASCII.self)
}

/// Manages configuration of TLS for SwiftNIO programs.
public struct TLSConfiguration {
    /// A default TLS configuration for client use.
    public static let clientDefault = TLSConfiguration.makeClientConfiguration()

    /// The minimum TLS version to allow in negotiation. Defaults to ``TLSVersion/tlsv1``.
    public var minimumTLSVersion: TLSVersion

    /// The maximum TLS version to allow in negotiation. If `nil`, there is no upper limit. Defaults to `nil`.
    public var maximumTLSVersion: TLSVersion?

    /// The pre-TLS1.3 cipher suites supported by this handler. This uses the OpenSSL cipher string format.
    /// TLS 1.3 cipher suites cannot be configured.
    public var cipherSuites: String = defaultCipherSuites
    
    /// Public property used to set the internal ``cipherSuites`` from ``NIOTLSCipher``.
    public var cipherSuiteValues: [NIOTLSCipher] {
        get {
            guard let sslContext = try? NIOSSLContext(configuration: self) else {
                return []
            }
            return sslContext.cipherSuites
        }
        set {
            let assignedCiphers = newValue.map { $0.standardName }
            self.cipherSuites = assignedCiphers.joined(separator: ":")
        }
    }

    /// Allowed algorithms to verify signatures. Passing `nil` means that a built-in set of algorithms will be used.
    public var verifySignatureAlgorithms : [SignatureAlgorithm]?

    /// Allowed algorithms to sign signatures. Passing `nil` means that a built-in set of algorithms will be used.
    public var signingSignatureAlgorithms : [SignatureAlgorithm]?

    /// Whether to verify remote certificates.
    public var certificateVerification: CertificateVerification

    /// The trust roots to use to validate certificates. This only needs to be provided if you intend to validate
    /// certificates.
    ///
    /// - NOTE: If certificate validation is enabled and ``trustRoots`` is `nil` then the system default root of
    /// trust is used (as if ``trustRoots`` had been explicitly set to ``NIOSSLTrustRoots/default``).
    ///
    /// - NOTE: If a directory path is used here to load a directory of certificates into a configuration, then the
    ///         certificates in this directory must be formatted by `c_rehash` to create the rehash file format of `HHHHHHHH.D` with a symlink.
    public var trustRoots: NIOSSLTrustRoots?

    /// Additional trust roots to use to validate certificates, used in addition to ``trustRoots``.
    public var additionalTrustRoots: [NIOSSLAdditionalTrustRoots]

    /// The certificates to offer during negotiation. If not present, no certificates will be offered.
    public var certificateChain: [NIOSSLCertificateSource]

    /// The private key associated with the leaf certificate.
    public var privateKey: NIOSSLPrivateKeySource?
    
    /// PSK Client Callback to get the key based on hint and identity.
    public var pskClientCallback: NIOPSKClientIdentityCallback? = nil
    
    /// PSK Server Callback to get the key based on hint and identity.
    public var pskServerCallback: NIOPSKServerIdentityCallback? = nil
    
    /// Optional PSK hint to be used during SSLContext create.
    public var pskHint: String? = nil

    /// The application protocols to use in the connection. Should be an ordered list of ASCII
    /// strings representing the ALPN identifiers of the protocols to negotiate. For clients,
    /// the protocols will be offered in the order given. For servers, the protocols will be matched
    /// against the client's offered protocols in order.
    public var applicationProtocols: [String] {
        get {
            return self.encodedApplicationProtocols.map(decodeALPNIdentifier)
        }
        set {
            self.encodedApplicationProtocols = newValue.map(encodeALPNIdentifier)
        }
    }

    internal var encodedApplicationProtocols: [[UInt8]]

    /// The amount of time to wait after initiating a shutdown before performing an unclean
    /// shutdown. Defaults to 5 seconds.
    public var shutdownTimeout: TimeAmount
    
    /// A callback that can be used to implement `SSLKEYLOGFILE` support.
    public var keyLogCallback: NIOSSLKeyLogCallback?

    /// Whether renegotiation is supported.
    public var renegotiationSupport: NIORenegotiationSupport
    
    /// Send the CA names derived from the ``trustRoots`` for client authentication.
    /// This instructs the client which identities can be used by evaluating what CA the identity certificate was issued from.
    public var sendCANameList: Bool

    private init(cipherSuiteValues: [NIOTLSCipher] = [],
                 cipherSuites: String = defaultCipherSuites,
                 verifySignatureAlgorithms: [SignatureAlgorithm]?,
                 signingSignatureAlgorithms: [SignatureAlgorithm]?,
                 minimumTLSVersion: TLSVersion,
                 maximumTLSVersion: TLSVersion?,
                 certificateVerification: CertificateVerification,
                 trustRoots: NIOSSLTrustRoots,
                 certificateChain: [NIOSSLCertificateSource],
                 privateKey: NIOSSLPrivateKeySource?,
                 applicationProtocols: [String],
                 shutdownTimeout: TimeAmount,
                 keyLogCallback: NIOSSLKeyLogCallback?,
                 renegotiationSupport: NIORenegotiationSupport,
                 additionalTrustRoots: [NIOSSLAdditionalTrustRoots],
                 sendCANameList: Bool = false,
                 pskClientCallback: NIOPSKClientIdentityCallback? = nil,
                 pskServerCallback: NIOPSKServerIdentityCallback? = nil,
                 pskHint: String? = nil) {
        self.cipherSuites = cipherSuites
        self.verifySignatureAlgorithms = verifySignatureAlgorithms
        self.signingSignatureAlgorithms = signingSignatureAlgorithms
        self.minimumTLSVersion = minimumTLSVersion
        self.maximumTLSVersion = maximumTLSVersion
        self.certificateVerification = certificateVerification
        self.trustRoots = trustRoots
        self.additionalTrustRoots = additionalTrustRoots
        self.certificateChain = certificateChain
        self.privateKey = privateKey
        self.encodedApplicationProtocols = []
        self.shutdownTimeout = shutdownTimeout
        self.renegotiationSupport = renegotiationSupport
        self.sendCANameList = sendCANameList
        self.applicationProtocols = applicationProtocols
        self.keyLogCallback = keyLogCallback
        self.pskClientCallback = pskClientCallback
        self.pskServerCallback = pskServerCallback
        self.pskHint = pskHint
        if !cipherSuiteValues.isEmpty {
            self.cipherSuiteValues = cipherSuiteValues
        }
    }
}

#if swift(>=5.7)
extension TLSConfiguration: Sendable {}
#endif

// MARK: BestEffortHashable
extension TLSConfiguration {
    /// Returns a best effort result of whether two ``TLSConfiguration`` objects are equal.
    ///
    /// The "best effort" stems from the fact that we are checking the pointer to the ``keyLogCallback`` closure.
    ///
    /// - warning: You should probably not use this function. This function can return false-negatives, but not false-positives.
    public func bestEffortEquals(_ comparing: TLSConfiguration) -> Bool {
        let isKeyLoggerCallbacksEqual = withUnsafeBytes(of: self.keyLogCallback) { callbackPointer1 in
            return withUnsafeBytes(of: comparing.keyLogCallback) { callbackPointer2 in
                return callbackPointer1.elementsEqual(callbackPointer2)
            }
        }
        let isPSKClientCallbackEqual = withUnsafeBytes(of: self.pskClientCallback) { pskClientCallback1 in
            return withUnsafeBytes(of: comparing.pskClientCallback) { pskClientCallback2 in
                return pskClientCallback1.elementsEqual(pskClientCallback2)
            }
        }
        let isPSKServerCallbackEqual = withUnsafeBytes(of: self.pskServerCallback) { pskServerCallback1 in
            return withUnsafeBytes(of: comparing.pskServerCallback) { pskServerCallback2 in
                return pskServerCallback1.elementsEqual(pskServerCallback2)
            }
        }
        
        return self.minimumTLSVersion == comparing.minimumTLSVersion &&
            self.maximumTLSVersion == comparing.maximumTLSVersion &&
            self.cipherSuites == comparing.cipherSuites &&
            self.verifySignatureAlgorithms == comparing.verifySignatureAlgorithms &&
            self.signingSignatureAlgorithms == comparing.signingSignatureAlgorithms &&
            self.certificateVerification == comparing.certificateVerification &&
            self.trustRoots == comparing.trustRoots &&
            self.additionalTrustRoots == comparing.additionalTrustRoots &&
            self.certificateChain == comparing.certificateChain &&
            self.privateKey == comparing.privateKey &&
            self.encodedApplicationProtocols == comparing.encodedApplicationProtocols &&
            self.shutdownTimeout == comparing.shutdownTimeout &&
            isKeyLoggerCallbacksEqual &&
            self.renegotiationSupport == comparing.renegotiationSupport &&
            self.sendCANameList == comparing.sendCANameList &&
            isPSKClientCallbackEqual &&
            isPSKServerCallbackEqual &&
            self.pskHint == comparing.pskHint
    }
    
    /// Returns a best effort hash of this TLS configuration.
    ///
    /// The "best effort" stems from the fact that we are hashing the pointer bytes of the ``keyLogCallback`` closure.
    ///
    /// - warning: You should probably not use this function. This function can return false-negatives, but not false-positives.
    public func bestEffortHash(into hasher: inout Hasher) {
        hasher.combine(minimumTLSVersion)
        hasher.combine(maximumTLSVersion)
        hasher.combine(cipherSuites)
        hasher.combine(verifySignatureAlgorithms)
        hasher.combine(signingSignatureAlgorithms)
        hasher.combine(certificateVerification)
        hasher.combine(trustRoots)
        hasher.combine(additionalTrustRoots)
        hasher.combine(certificateChain)
        hasher.combine(privateKey)
        hasher.combine(encodedApplicationProtocols)
        hasher.combine(shutdownTimeout)
        withUnsafeBytes(of: keyLogCallback) { closureBits in
            hasher.combine(bytes: closureBits)
        }
        hasher.combine(renegotiationSupport)
        hasher.combine(sendCANameList)
        withUnsafeBytes(of: pskClientCallback) { closureClientBits in
            hasher.combine(bytes: closureClientBits)
        }
        withUnsafeBytes(of: pskServerCallback) { closureServerBits in
            hasher.combine(bytes: closureServerBits)
        }
        hasher.combine(pskHint)
    }

    /// Creates a TLS configuration for use with client-side contexts.
    ///
    /// This provides sensible defaults, and can be used without customisation. For server-side
    /// contexts, you should use ``TLSConfiguration/makeServerConfiguration(certificateChain:privateKey:)`` instead.
    ///
    /// For customising fields, modify the returned TLSConfiguration object.
    public static func makeClientConfiguration() -> TLSConfiguration {
        return TLSConfiguration(cipherSuites: defaultCipherSuites,
                                verifySignatureAlgorithms: nil,
                                signingSignatureAlgorithms: nil,
                                minimumTLSVersion: .tlsv1,
                                maximumTLSVersion: nil,
                                certificateVerification: .fullVerification,
                                trustRoots: .default,
                                certificateChain: [],
                                privateKey: nil,
                                applicationProtocols: [],
                                shutdownTimeout: .seconds(5),
                                keyLogCallback: nil,
                                renegotiationSupport: .none,
                                additionalTrustRoots: [],
                                sendCANameList: false,
                                pskClientCallback: nil,
                                pskServerCallback: nil,
                                pskHint: nil)
    }

    /// Create a TLS configuration for use with server-side contexts.
    ///
    /// This provides sensible defaults while requiring that you provide any data that is necessary
    /// for server-side function. For client use, try ``TLSConfiguration/makeClientConfiguration()`` instead.
    ///
    /// For customising fields, modify the returned TLSConfiguration object.
    public static func makeServerConfiguration(
        certificateChain: [NIOSSLCertificateSource],
        privateKey: NIOSSLPrivateKeySource
    ) -> TLSConfiguration {
        return TLSConfiguration(cipherSuites: defaultCipherSuites,
                                verifySignatureAlgorithms: nil,
                                signingSignatureAlgorithms: nil,
                                minimumTLSVersion: .tlsv1,
                                maximumTLSVersion: nil,
                                certificateVerification: .none,
                                trustRoots: .default,
                                certificateChain: certificateChain,
                                privateKey: privateKey,
                                applicationProtocols: [],
                                shutdownTimeout: .seconds(5),
                                keyLogCallback: nil,
                                renegotiationSupport: .none,
                                additionalTrustRoots: [],
                                sendCANameList: false,
                                pskClientCallback: nil,
                                pskServerCallback: nil,
                                pskHint: nil)
    }
    
    /// Create a TLS configuration for use with server-side or client-side contexts that uses Pre-Shared Keys for TLS 1.2 and below.
    ///
    /// This provides sensible defaults while requiring that you provide any data that is necessary
    /// for server-side or client-side functionality.  This configuration uses Pre-Shared Keys instead of certificates.
    ///
    /// For customising fields, modify the returned TLSConfiguration object.
    public static func makePreSharedKeyConfiguration() -> TLSConfiguration {
        
        return TLSConfiguration(cipherSuites: defaultCipherSuites,
                                verifySignatureAlgorithms: nil,
                                signingSignatureAlgorithms: nil,
                                minimumTLSVersion: .tlsv1,
                                maximumTLSVersion: nil,
                                certificateVerification: .none,
                                trustRoots: .default,
                                certificateChain: [],
                                privateKey: nil,
                                applicationProtocols: [],
                                shutdownTimeout: .seconds(5),
                                keyLogCallback: nil,
                                renegotiationSupport: .none,
                                additionalTrustRoots: [],
                                sendCANameList: false,
                                pskClientCallback: nil,
                                pskServerCallback: nil,
                                pskHint: nil)
    }
}

// MARK: Deprecated constructors.

extension TLSConfiguration {
    /// Create a TLS configuration for use with server-side contexts. This allows setting the ``NIOTLSCipher`` property specifically.
    ///
    /// This provides sensible defaults while requiring that you provide any data that is necessary
    /// for server-side function. For client use, try ``TLSConfiguration/makeClientConfiguration()`` instead.
    @available(*, deprecated, renamed: "makeServerConfiguration(certificateChain:privateKey:)")
    public static func forServer(certificateChain: [NIOSSLCertificateSource],
                                 privateKey: NIOSSLPrivateKeySource,
                                 cipherSuites: [NIOTLSCipher],
                                 verifySignatureAlgorithms: [SignatureAlgorithm]? = nil,
                                 signingSignatureAlgorithms: [SignatureAlgorithm]? = nil,
                                 minimumTLSVersion: TLSVersion = .tlsv1,
                                 maximumTLSVersion: TLSVersion? = nil,
                                 certificateVerification: CertificateVerification = .none,
                                 trustRoots: NIOSSLTrustRoots = .default,
                                 applicationProtocols: [String] = [],
                                 shutdownTimeout: TimeAmount = .seconds(5),
                                 keyLogCallback: NIOSSLKeyLogCallback? = nil,
                                 additionalTrustRoots: [NIOSSLAdditionalTrustRoots] = []) -> TLSConfiguration {
        return TLSConfiguration(cipherSuiteValues: cipherSuites,
                                verifySignatureAlgorithms: verifySignatureAlgorithms,
                                signingSignatureAlgorithms: signingSignatureAlgorithms,
                                minimumTLSVersion: minimumTLSVersion,
                                maximumTLSVersion: maximumTLSVersion,
                                certificateVerification: certificateVerification,
                                trustRoots: trustRoots,
                                certificateChain: certificateChain,
                                privateKey: privateKey,
                                applicationProtocols: applicationProtocols,
                                shutdownTimeout: shutdownTimeout,
                                keyLogCallback: keyLogCallback,
                                renegotiationSupport: .none,  // Servers never support renegotiation: there's no point.
                                additionalTrustRoots: additionalTrustRoots)
    }

    /// Create a TLS configuration for use with server-side contexts.
    ///
    /// This provides sensible defaults while requiring that you provide any data that is necessary
    /// for server-side function. For client use, try ``TLSConfiguration/makeClientConfiguration()`` instead.
    @available(*, deprecated, renamed: "makeServerConfiguration(certificateChain:privateKey:)")
    public static func forServer(certificateChain: [NIOSSLCertificateSource],
                                 privateKey: NIOSSLPrivateKeySource,
                                 cipherSuites: String = defaultCipherSuites,
                                 minimumTLSVersion: TLSVersion = .tlsv1,
                                 maximumTLSVersion: TLSVersion? = nil,
                                 certificateVerification: CertificateVerification = .none,
                                 trustRoots: NIOSSLTrustRoots = .default,
                                 applicationProtocols: [String] = [],
                                 shutdownTimeout: TimeAmount = .seconds(5),
                                 keyLogCallback: NIOSSLKeyLogCallback? = nil) -> TLSConfiguration {
        return TLSConfiguration(cipherSuites: cipherSuites,
                                verifySignatureAlgorithms: nil,
                                signingSignatureAlgorithms: nil,
                                minimumTLSVersion: minimumTLSVersion,
                                maximumTLSVersion: maximumTLSVersion,
                                certificateVerification: certificateVerification,
                                trustRoots: trustRoots,
                                certificateChain: certificateChain,
                                privateKey: privateKey,
                                applicationProtocols: applicationProtocols,
                                shutdownTimeout: shutdownTimeout,
                                keyLogCallback: keyLogCallback,
                                renegotiationSupport: .none,  // Servers never support renegotiation: there's no point.
                                additionalTrustRoots: [])
    }

    /// Create a TLS configuration for use with server-side contexts.
    ///
    /// This provides sensible defaults while requiring that you provide any data that is necessary
    /// for server-side function. For client use, try ``TLSConfiguration/makeClientConfiguration()`` instead.
    @available(*, deprecated, renamed: "makeServerConfiguration(certificateChain:privateKey:)")
    public static func forServer(certificateChain: [NIOSSLCertificateSource],
                                 privateKey: NIOSSLPrivateKeySource,
                                 cipherSuites: String = defaultCipherSuites,
                                 verifySignatureAlgorithms: [SignatureAlgorithm]? = nil,
                                 signingSignatureAlgorithms: [SignatureAlgorithm]? = nil,
                                 minimumTLSVersion: TLSVersion = .tlsv1,
                                 maximumTLSVersion: TLSVersion? = nil,
                                 certificateVerification: CertificateVerification = .none,
                                 trustRoots: NIOSSLTrustRoots = .default,
                                 applicationProtocols: [String] = [],
                                 shutdownTimeout: TimeAmount = .seconds(5),
                                 keyLogCallback: NIOSSLKeyLogCallback? = nil) -> TLSConfiguration {
        return TLSConfiguration(cipherSuites: cipherSuites,
                                verifySignatureAlgorithms: verifySignatureAlgorithms,
                                signingSignatureAlgorithms: signingSignatureAlgorithms,
                                minimumTLSVersion: minimumTLSVersion,
                                maximumTLSVersion: maximumTLSVersion,
                                certificateVerification: certificateVerification,
                                trustRoots: trustRoots,
                                certificateChain: certificateChain,
                                privateKey: privateKey,
                                applicationProtocols: applicationProtocols,
                                shutdownTimeout: shutdownTimeout,
                                keyLogCallback: keyLogCallback,
                                renegotiationSupport: .none,  // Servers never support renegotiation: there's no point.
                                additionalTrustRoots: [])
    }

    /// Create a TLS configuration for use with server-side contexts.
    ///
    /// This provides sensible defaults while requiring that you provide any data that is necessary
    /// for server-side function. For client use, try ``TLSConfiguration/makeClientConfiguration()`` instead.
    @available(*, deprecated, renamed: "makeServerConfiguration(certificateChain:privateKey:)")
    public static func forServer(certificateChain: [NIOSSLCertificateSource],
                                 privateKey: NIOSSLPrivateKeySource,
                                 cipherSuites: String = defaultCipherSuites,
                                 verifySignatureAlgorithms: [SignatureAlgorithm]? = nil,
                                 signingSignatureAlgorithms: [SignatureAlgorithm]? = nil,
                                 minimumTLSVersion: TLSVersion = .tlsv1,
                                 maximumTLSVersion: TLSVersion? = nil,
                                 certificateVerification: CertificateVerification = .none,
                                 trustRoots: NIOSSLTrustRoots = .default,
                                 applicationProtocols: [String] = [],
                                 shutdownTimeout: TimeAmount = .seconds(5),
                                 keyLogCallback: NIOSSLKeyLogCallback? = nil,
                                 additionalTrustRoots: [NIOSSLAdditionalTrustRoots]) -> TLSConfiguration {
        return TLSConfiguration(cipherSuites: cipherSuites,
                                verifySignatureAlgorithms: verifySignatureAlgorithms,
                                signingSignatureAlgorithms: signingSignatureAlgorithms,
                                minimumTLSVersion: minimumTLSVersion,
                                maximumTLSVersion: maximumTLSVersion,
                                certificateVerification: certificateVerification,
                                trustRoots: trustRoots,
                                certificateChain: certificateChain,
                                privateKey: privateKey,
                                applicationProtocols: applicationProtocols,
                                shutdownTimeout: shutdownTimeout,
                                keyLogCallback: keyLogCallback,
                                renegotiationSupport: .none,  // Servers never support renegotiation: there's no point.
                                additionalTrustRoots: additionalTrustRoots)
    }

    /// Creates a TLS configuration for use with client-side contexts. This allows setting the ``NIOTLSCipher`` property specifically.
    ///
    /// This provides sensible defaults, and can be used without customisation. For server-side
    /// contexts, you should use ``TLSConfiguration/makeServerConfiguration(certificateChain:privateKey:)`` instead.
    @available(*, deprecated, renamed: "makeClientConfiguration()")
    public static func forClient(cipherSuites: [NIOTLSCipher],
                                 verifySignatureAlgorithms: [SignatureAlgorithm]? = nil,
                                 signingSignatureAlgorithms: [SignatureAlgorithm]? = nil,
                                 minimumTLSVersion: TLSVersion = .tlsv1,
                                 maximumTLSVersion: TLSVersion? = nil,
                                 certificateVerification: CertificateVerification = .fullVerification,
                                 trustRoots: NIOSSLTrustRoots = .default,
                                 certificateChain: [NIOSSLCertificateSource] = [],
                                 privateKey: NIOSSLPrivateKeySource? = nil,
                                 applicationProtocols: [String] = [],
                                 shutdownTimeout: TimeAmount = .seconds(5),
                                 keyLogCallback: NIOSSLKeyLogCallback? = nil,
                                 renegotiationSupport: NIORenegotiationSupport = .none,
                                 additionalTrustRoots: [NIOSSLAdditionalTrustRoots] = []) -> TLSConfiguration {
        return TLSConfiguration(cipherSuiteValues: cipherSuites,
                                verifySignatureAlgorithms: verifySignatureAlgorithms,
                                signingSignatureAlgorithms: signingSignatureAlgorithms,
                                minimumTLSVersion: minimumTLSVersion,
                                maximumTLSVersion: maximumTLSVersion,
                                certificateVerification: certificateVerification,
                                trustRoots: trustRoots,
                                certificateChain: certificateChain,
                                privateKey: privateKey,
                                applicationProtocols: applicationProtocols,
                                shutdownTimeout: shutdownTimeout,
                                keyLogCallback: keyLogCallback,
                                renegotiationSupport: renegotiationSupport,
                                additionalTrustRoots: additionalTrustRoots)
    }

    /// Creates a TLS configuration for use with client-side contexts.
    ///
    /// This provides sensible defaults, and can be used without customisation. For server-side
    /// contexts, you should use ``TLSConfiguration/makeServerConfiguration(certificateChain:privateKey:)`` instead.
    @available(*, deprecated, renamed: "makeClientConfiguration()")
    public static func forClient(cipherSuites: String = defaultCipherSuites,
                                 minimumTLSVersion: TLSVersion = .tlsv1,
                                 maximumTLSVersion: TLSVersion? = nil,
                                 certificateVerification: CertificateVerification = .fullVerification,
                                 trustRoots: NIOSSLTrustRoots = .default,
                                 certificateChain: [NIOSSLCertificateSource] = [],
                                 privateKey: NIOSSLPrivateKeySource? = nil,
                                 applicationProtocols: [String] = [],
                                 shutdownTimeout: TimeAmount = .seconds(5),
                                 keyLogCallback: NIOSSLKeyLogCallback? = nil) -> TLSConfiguration {
        return TLSConfiguration(cipherSuites: cipherSuites,
                                verifySignatureAlgorithms: nil,
                                signingSignatureAlgorithms: nil,
                                minimumTLSVersion: minimumTLSVersion,
                                maximumTLSVersion: maximumTLSVersion,
                                certificateVerification: certificateVerification,
                                trustRoots: trustRoots,
                                certificateChain: certificateChain,
                                privateKey: privateKey,
                                applicationProtocols: applicationProtocols,
                                shutdownTimeout: shutdownTimeout,
                                keyLogCallback: keyLogCallback,
                                renegotiationSupport: .none,  // Default value is here for backward-compatibility.
                                additionalTrustRoots: [])
    }


    /// Creates a TLS configuration for use with client-side contexts.
    ///
    /// This provides sensible defaults, and can be used without customisation. For server-side
    /// contexts, you should use ``TLSConfiguration/makeServerConfiguration(certificateChain:privateKey:)`` instead.
    @available(*, deprecated, renamed: "makeClientConfiguration()")
    public static func forClient(cipherSuites: String = defaultCipherSuites,
                                 minimumTLSVersion: TLSVersion = .tlsv1,
                                 maximumTLSVersion: TLSVersion? = nil,
                                 certificateVerification: CertificateVerification = .fullVerification,
                                 trustRoots: NIOSSLTrustRoots = .default,
                                 certificateChain: [NIOSSLCertificateSource] = [],
                                 privateKey: NIOSSLPrivateKeySource? = nil,
                                 applicationProtocols: [String] = [],
                                 shutdownTimeout: TimeAmount = .seconds(5),
                                 keyLogCallback: NIOSSLKeyLogCallback? = nil,
                                 renegotiationSupport: NIORenegotiationSupport) -> TLSConfiguration {
        return TLSConfiguration(cipherSuites: cipherSuites,
                                verifySignatureAlgorithms: nil,
                                signingSignatureAlgorithms: nil,
                                minimumTLSVersion: minimumTLSVersion,
                                maximumTLSVersion: maximumTLSVersion,
                                certificateVerification: certificateVerification,
                                trustRoots: trustRoots,
                                certificateChain: certificateChain,
                                privateKey: privateKey,
                                applicationProtocols: applicationProtocols,
                                shutdownTimeout: shutdownTimeout,
                                keyLogCallback: keyLogCallback,
                                renegotiationSupport: renegotiationSupport,
                                additionalTrustRoots: [])
    }

    /// Creates a TLS configuration for use with client-side contexts.
    ///
    /// This provides sensible defaults, and can be used without customisation. For server-side
    /// contexts, you should use ``TLSConfiguration/makeServerConfiguration(certificateChain:privateKey:)`` instead.
    @available(*, deprecated, renamed: "makeClientConfiguration()")
    public static func forClient(cipherSuites: String = defaultCipherSuites,
                                 verifySignatureAlgorithms: [SignatureAlgorithm]? = nil,
                                 signingSignatureAlgorithms: [SignatureAlgorithm]? = nil,
                                 minimumTLSVersion: TLSVersion = .tlsv1,
                                 maximumTLSVersion: TLSVersion? = nil,
                                 certificateVerification: CertificateVerification = .fullVerification,
                                 trustRoots: NIOSSLTrustRoots = .default,
                                 certificateChain: [NIOSSLCertificateSource] = [],
                                 privateKey: NIOSSLPrivateKeySource? = nil,
                                 applicationProtocols: [String] = [],
                                 shutdownTimeout: TimeAmount = .seconds(5),
                                 keyLogCallback: NIOSSLKeyLogCallback? = nil,
                                 renegotiationSupport: NIORenegotiationSupport) -> TLSConfiguration {
        return TLSConfiguration(cipherSuites: cipherSuites,
                                verifySignatureAlgorithms: verifySignatureAlgorithms,
                                signingSignatureAlgorithms: signingSignatureAlgorithms,
                                minimumTLSVersion: minimumTLSVersion,
                                maximumTLSVersion: maximumTLSVersion,
                                certificateVerification: certificateVerification,
                                trustRoots: trustRoots,
                                certificateChain: certificateChain,
                                privateKey: privateKey,
                                applicationProtocols: applicationProtocols,
                                shutdownTimeout: shutdownTimeout,
                                keyLogCallback: keyLogCallback,
                                renegotiationSupport: renegotiationSupport,
                                additionalTrustRoots: [])
    }

    /// Creates a TLS configuration for use with client-side contexts.
    ///
    /// This provides sensible defaults, and can be used without customisation. For server-side
    /// contexts, you should use ``TLSConfiguration/makeServerConfiguration(certificateChain:privateKey:)`` instead.
    @available(*, deprecated, renamed: "makeClientConfiguration()")
    public static func forClient(cipherSuites: String = defaultCipherSuites,
                                 verifySignatureAlgorithms: [SignatureAlgorithm]? = nil,
                                 signingSignatureAlgorithms: [SignatureAlgorithm]? = nil,
                                 minimumTLSVersion: TLSVersion = .tlsv1,
                                 maximumTLSVersion: TLSVersion? = nil,
                                 certificateVerification: CertificateVerification = .fullVerification,
                                 trustRoots: NIOSSLTrustRoots = .default,
                                 certificateChain: [NIOSSLCertificateSource] = [],
                                 privateKey: NIOSSLPrivateKeySource? = nil,
                                 applicationProtocols: [String] = [],
                                 shutdownTimeout: TimeAmount = .seconds(5),
                                 keyLogCallback: NIOSSLKeyLogCallback? = nil,
                                 renegotiationSupport: NIORenegotiationSupport = .none,
                                 additionalTrustRoots: [NIOSSLAdditionalTrustRoots]) -> TLSConfiguration {
        return TLSConfiguration(cipherSuites: cipherSuites,
                                verifySignatureAlgorithms: verifySignatureAlgorithms,
                                signingSignatureAlgorithms: signingSignatureAlgorithms,
                                minimumTLSVersion: minimumTLSVersion,
                                maximumTLSVersion: maximumTLSVersion,
                                certificateVerification: certificateVerification,
                                trustRoots: trustRoots,
                                certificateChain: certificateChain,
                                privateKey: privateKey,
                                applicationProtocols: applicationProtocols,
                                shutdownTimeout: shutdownTimeout,
                                keyLogCallback: keyLogCallback,
                                renegotiationSupport: renegotiationSupport,
                                additionalTrustRoots: additionalTrustRoots)
    }
}

extension TLSConfiguration {
    /// Provides the resolved signature algorithms for signing, if any.
    ///
    /// Users can override the signature algorithms in two ways. Firstly, they can provide a
    /// value for the `signingSignatureAlgorithms` field in the `TLSConfiguration` structure.
    /// This acts as an artificial limiter, preventing certain algorithms from being used even
    /// though a key might nominally support them.
    ///
    /// Secondly, users can provide a custom key. This custom key is only capable of using
    /// certain signing algorithms.
    ///
    /// This property resolves these two into a single unified set by diffing them together.
    /// If there is no override (i.e. a native key and no override of the
    /// `signingSignatureAlgorithms` field then this returns `nil`.
    internal var resolvedSigningSignatureAlgorithms: [SignatureAlgorithm]? {
        switch (self.signingSignatureAlgorithms, self.privateKey?.customSigningAlgorithms) {
        case (.none, .none):
            // No overrides.
            return nil

        case (.some(let manualOverrides), .none):
            return manualOverrides

        case (.none, .some(let keyRequirements)):
            return keyRequirements

        case (.some(let manualOverrides), .some(let keyRequirements)):
            // Here we have to filter the set. We assume the two lists are small, and so we
            // just use `Array.filter` instead of composing into a Set. Note that the order
            // here is _semantic_: we have to filter the manual overrides array becuase
            // that order was specified by the user, and we want to honor it.
            return manualOverrides.filter { keyRequirements.contains($0) }
        }
    }
}

extension NIOSSLPrivateKeySource {
    /// The custom signing algorithms required by this private key, if any.
    ///
    /// Is `nil` when the key is a file-backed key, as this is handled by BoringSSL as a native key.
    fileprivate var customSigningAlgorithms: [SignatureAlgorithm]? {
        switch self {
        case .file:
            return nil
        case .privateKey(let key):
            return key.customSigningAlgorithms
        }
    }
}
