//
//  Proxyman+Extensions.swift
//  NIOSSL
//
//  Exposes internal NIOSSL APIs as public for use by ProxymanCore.
//  Each wrapper delegates to the original internal API with a __ prefix.
//

// MARK: - NIOSSLCertificate

extension NIOSSLCertificate {

    @inlinable
    public func __withUnsafeMutableX509Pointer<ResultType>(
        _ body: (OpaquePointer) throws -> ResultType
    ) rethrows -> ResultType {
        try self.withUnsafeMutableX509Pointer(body)
    }

    public static func __fromUnsafePointer(takingOwnership pointer: OpaquePointer) -> NIOSSLCertificate {
        self.fromUnsafePointer(takingOwnership: pointer)
    }
}

// MARK: - NIOSSLPrivateKey

extension NIOSSLPrivateKey {

    public func __withUnsafeMutableEVPPKEYPointer<ReturnType>(
        _ body: (OpaquePointer) throws -> ReturnType
    ) rethrows -> ReturnType {
        try self.withUnsafeMutableEVPPKEYPointer(body)
    }

    public static func __fromUnsafePointer(takingOwnership pointer: OpaquePointer) -> NIOSSLPrivateKey {
        self.fromUnsafePointer(takingOwnership: pointer)
    }
}

// MARK: - NIOTLSCipher

extension NIOTLSCipher {

    public var __standardName: String {
        self.standardName
    }
}

// MARK: - NIOSSLContext

extension NIOSSLContext {

    public var __cipherSuites: [NIOTLSCipher] {
        self.cipherSuites
    }
}
