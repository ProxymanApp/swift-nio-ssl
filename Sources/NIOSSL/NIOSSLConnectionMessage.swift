// Copyright (c) Proxyman. Licensed under Apache License v2.0.

/// Describes a TLS message without retaining its bytes, certificates, or key material.
public struct NIOSSLConnectionMessage: Sendable, Equatable {
    public let outgoing: Bool
    public let version: Int
    public let contentType: Int
    public let messageType: Int
    public let alertLevel: Int?

    init?(outgoing: Bool, version: Int, contentType: Int, bytes: UnsafeRawPointer, count: Int) {
        // Ignore record framing and application data. Only complete protocol messages are useful here.
        guard version != 0, [20, 21, 22].contains(contentType), count >= (contentType == 21 ? 2 : 1) else { return nil }
        self.outgoing = outgoing
        self.version = version
        self.contentType = contentType
        self.messageType = Int(bytes.load(fromByteOffset: contentType == 21 ? 1 : 0, as: UInt8.self))
        self.alertLevel = contentType == 21 ? Int(bytes.load(as: UInt8.self)) : nil
    }
}
