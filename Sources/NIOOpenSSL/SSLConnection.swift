//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2018 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIO
import CNIOOpenSSL

internal let SSL_MAX_RECORD_SIZE = 16 * 1024;

/// Encodes the return value of a non-blocking OpenSSL method call.
///
/// This enum maps OpenSSL's return values to a small number of cases. A success
/// value naturally maps to `.complete`, and most errors map to `.failed`. However,
/// the OpenSSL "errors" `WANT_READ` and `WANT_WRITE` are mapped to `.incomplete`, to
/// help distinguish them from the other error cases. This makes it easier for code to
/// handle the "must wait for more data" case by calling it out directly.
enum AsyncOperationResult<T> {
    case incomplete
    case complete(T)
    case failed(OpenSSLError)
}

/// A wrapper class that encapsulates OpenSSL's `SSL *` object.
///
/// This class represents a single TLS connection, and performs all of crypto and record
/// framing required by TLS. It also records the configuration and parent `SSLContext` object
/// used to create the connection.
internal final class SSLConnection {
    private let ssl: UnsafeMutablePointer<SSL>
    private let parentContext: SSLContext
    private var bio: ByteBufferBIO?

    /// Whether certificate hostnames should be validated.
    var validateHostnames: Bool {
        if case .fullVerification = parentContext.configuration.certificateVerification {
            return true
        }
        return false
    }
    
    init(ownedSSL: UnsafeMutablePointer<SSL>, parentContext: SSLContext) {
        self.ssl = ownedSSL
        self.parentContext = parentContext
    }
    
    deinit {
        SSL_free(ssl)
    }

    /// Configures this as a server connection.
    func setAcceptState() {
        SSL_set_accept_state(ssl)
    }

    /// Configures this as a client connection.
    func setConnectState() {
        SSL_set_connect_state(ssl)
    }

    func setAllocator(_ allocator: ByteBufferAllocator) {
        self.bio = ByteBufferBIO(allocator: allocator)

        // This weird dance where we pass the *exact same* pointer in to both objects is because, weirdly,
        // the OpenSSL docs claim that only one reference count will be consumed here. We therefore need to
        // avoid calling BIO_up_ref too many times.
        let bioPtr = self.bio!.retainedBIO()
        SSL_set_bio(self.ssl, bioPtr, bioPtr)
    }

    /// Sets the value of the SNI extension to send to the server.
    ///
    /// This method must only be called with a hostname, not an IP address. Sending
    /// an IP address in the SNI extension is invalid, and may result in handshake
    /// failure.
    func setSNIServerName(name: String) throws {
        ERR_clear_error()
        let rc = name.withCString {
            return CNIOOpenSSL_SSL_set_tlsext_host_name(ssl, $0)
        }
        guard rc == 1 else {
            throw OpenSSLError.invalidSNIName(OpenSSLError.buildErrorStack())
        }
    }

    /// Spins the handshake state machine and performs the next step of the handshake
    /// protocol.
    ///
    /// This method may write data into internal buffers that must be sent: call
    /// `getDataForNetwork` after this method is called. This method also consumes
    /// data from internal buffers: call `consumeDataFromNetwork` before calling this
    /// method.
    func doHandshake() -> AsyncOperationResult<Int32> {
        ERR_clear_error()
        let rc = SSL_do_handshake(ssl)
        
        if (rc == 1) { return .complete(rc) }
        
        let result = SSL_get_error(ssl, rc)
        let error = OpenSSLError.fromSSLGetErrorResult(result)!
        
        switch error {
        case .wantRead,
             .wantWrite:
            return .incomplete
        default:
            return .failed(error)
        }
    }

    /// Spins the shutdown state machine and performs the next step of the shutdown
    /// protocol.
    ///
    /// This method may write data into internal buffers that must be sent: call
    /// `getDataForNetwork` after this method is called. This method also consumes
    /// data from internal buffers: call `consumeDataFromNetwork` before calling this
    /// method.
    func doShutdown() -> AsyncOperationResult<Int32> {
        ERR_clear_error()
        let rc = SSL_shutdown(ssl)
        
        switch rc {
        case 1:
            return .complete(rc)
        case 0:
            return .incomplete
        default:
            let result = SSL_get_error(ssl, rc)
            let error = OpenSSLError.fromSSLGetErrorResult(result)!
            
            switch error {
            case .wantRead,
                 .wantWrite:
                return .incomplete
            default:
                return .failed(error)
            }
        }
    }
    
    /// Given some unprocessed data from the remote peer, places it into
    /// OpenSSL's receive buffer ready for handling by OpenSSL.
    ///
    /// This method should be called whenever data is received from the remote
    /// peer. It must be immediately followed by an I/O operation, e.g. `readDataFromNetwork`
    /// or `doHandshake` or `doShutdown`.
    func consumeDataFromNetwork(_ data: ByteBuffer) {
        self.bio!.receiveFromNetwork(buffer: data)
    }

    /// Obtains some encrypted data ready for the network from OpenSSL.
    ///
    /// This call obtains only data that OpenSSL has already written into its send
    /// buffer. As a result, it should be called last, after all other operations have
    /// been performed, to allow OpenSSL to write as much data as necessary into the
    /// `BIO`.
    ///
    /// Returns `nil` if there is no data to write. Otherwise, returns all of the pending
    /// data.
    func getDataForNetwork(allocator: ByteBufferAllocator) -> ByteBuffer? {
        return self.bio!.outboundCiphertext()
    }

    /// Attempts to decrypt any application data sent by the remote peer, and fills a buffer
    /// containing the cleartext bytes.
    ///
    /// This method can only consume data previously fed into OpenSSL in `consumeDataFromNetwork`.
    func readDataFromNetwork(outputBuffer: inout ByteBuffer) -> AsyncOperationResult<Int> {
        // TODO(cory): It would be nice to have an withUnsafeMutableWriteableBytes here, but we don't, so we
        // need to make do with writeWithUnsafeMutableBytes instead. The core issue is that we can't
        // safely return any of the error values that SSL_read might provide here because writeWithUnsafeMutableBytes
        // will try to use that as the number of bytes written and blow up. If we could prevent it doing that (which
        // we can with reading) that would be grand, but we can't, so instead we need to use a temp variable. Not ideal.
        var bytesRead: Int32 = 0
        let rc = outputBuffer.writeWithUnsafeMutableBytes { (pointer) -> Int in
            bytesRead = SSL_read(self.ssl, pointer.baseAddress, Int32(pointer.count))
            return bytesRead >= 0 ? Int(bytesRead) : 0
        }
        
        if bytesRead > 0 {
            return .complete(rc)
        } else {
            let result = SSL_get_error(ssl, Int32(bytesRead))
            let error = OpenSSLError.fromSSLGetErrorResult(result)!
            
            switch error {
            case .wantRead,
                 .wantWrite:
                return .incomplete
            default:
                return .failed(error)
            }
        }
    }

    /// Encrypts cleartext application data ready for sending on the network.
    ///
    /// This call will only write the data into OpenSSL's internal buffers. It needs to be obtained
    /// by calling `getDataForNetwork` after this call completes.
    func writeDataToNetwork(_ data: inout ByteBuffer) -> AsyncOperationResult<Int32> {
        // OpenSSL does not allow calling SSL_write with zero-length buffers. Zero-length
        // writes always succeed.
        guard data.readableBytes > 0 else {
            return .complete(0)
        }

        let writtenBytes = data.withUnsafeReadableBytes { (pointer) -> Int32 in
            return SSL_write(ssl, pointer.baseAddress, Int32(pointer.count))
        }
        
        if writtenBytes > 0 {
            // The default behaviour of SSL_write is to only return once *all* of the data has been written,
            // unless the underlying BIO cannot satisfy the need (in which case WANT_WRITE will be returned).
            // We're using our BIO, which is always writable, so WANT_WRITE cannot fire so we'd always
            // expect this to write the complete quantity of readable bytes in our buffer.
            precondition(writtenBytes == data.readableBytes)
            data.moveReaderIndex(forwardBy: Int(writtenBytes))
            return .complete(writtenBytes)
        } else {
            let result = SSL_get_error(ssl, writtenBytes)
            let error = OpenSSLError.fromSSLGetErrorResult(result)!
            
            switch error {
            case .wantRead, .wantWrite:
                return .incomplete
            default:
                return .failed(error)
            }
        }
    }

    /// Returns the protocol negotiated via ALPN, if any. Returns `nil` if no protocol
    /// was negotiated.
    func getAlpnProtocol() -> String? {
        var protoName = UnsafePointer<UInt8>(bitPattern: 0)
        var protoLen: UInt32 = 0

        CNIOOpenSSL_SSL_get0_alpn_selected(ssl, &protoName, &protoLen)
        guard protoLen > 0 else {
            return nil
        }

        return String(decoding: UnsafeBufferPointer(start: protoName, count: Int(protoLen)), as: UTF8.self)
    }

    /// Get the leaf certificate from the peer certificate chain as a managed object,
    /// if available.
    func getPeerCertificate() -> OpenSSLCertificate? {
        guard let certPtr = SSL_get_peer_certificate(ssl) else {
            return nil
        }

        return OpenSSLCertificate.fromUnsafePointer(takingOwnership: certPtr)
    }
}
