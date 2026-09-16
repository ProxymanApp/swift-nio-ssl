import XCTest
import NIOCore
import NIOEmbedded
@testable import NIOSSL

final class ConnectionMessageTests: XCTestCase {
    func testTLS12HandshakeMessages() throws { try handshake(version: .tlsv12, verify: false) }
    func testTLS13HandshakeMessages() throws { try handshake(version: .tlsv13, verify: false) }
    func testVerifiedHandshakeMessages() throws { try handshake(version: .tlsv13, verify: true) }

    private func handshake(version: TLSVersion, verify: Bool) throws {
        let client = EmbeddedChannel()
        let server = EmbeddedChannel()
        defer { _ = try? client.finish(); _ = try? server.finish() }
        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(NIOSSLIntegrationTest.cert)],
            privateKey: .privateKey(NIOSSLIntegrationTest.key))
        serverConfig.minimumTLSVersion = version
        serverConfig.maximumTLSVersion = version
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = verify ? .noHostnameVerification : .none
        clientConfig.trustRoots = .certificates([NIOSSLIntegrationTest.cert])
        let ssl = try NIOSSLClientHandler(context: NIOSSLContext(configuration: clientConfig), serverHostname: nil)
        var messages: [NIOSSLConnectionMessage] = []
        ssl.connectionMessageCallback = { messages.append($0) }
        try server.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: NIOSSLContext(configuration: serverConfig)))
        try client.pipeline.syncOperations.addHandler(ssl)
        let connection = client.connect(to: try SocketAddress(unixDomainSocketPath: "/tmp/connection-message-test"))
        server.pipeline.fireChannelActive()
        try interactInMemory(clientChannel: client, serverChannel: server)
        try connection.wait()
        XCTAssertTrue(messages.contains { $0.contentType == 22 && $0.messageType == 1 && $0.outgoing })
        XCTAssertTrue(messages.contains { $0.contentType == 22 && $0.messageType == 2 && !$0.outgoing })
        XCTAssertTrue(messages.contains { $0.contentType == 22 && $0.messageType == 20 && !$0.outgoing })
        XCTAssertTrue(messages.contains { $0.contentType == 22 && $0.messageType == 20 && $0.outgoing })
        XCTAssertTrue(messages.allSatisfy { [20, 21, 22].contains($0.contentType) })
        let count = messages.count
        ssl.connectionMessageCallback = nil
        _ = client.close()
        try interactInMemory(clientChannel: client, serverChannel: server)
        XCTAssertEqual(messages.count, count)
    }

    func testFiltersFramingAndChecksAlertLength() {
        let bytes: [UInt8] = [2, 40]
        bytes.withUnsafeBytes { buffer in
            XCTAssertNil(NIOSSLConnectionMessage(outgoing: true, version: 0, contentType: 256, bytes: buffer.baseAddress!, count: 2))
            XCTAssertNil(NIOSSLConnectionMessage(outgoing: true, version: 0x303, contentType: 23, bytes: buffer.baseAddress!, count: 2))
            XCTAssertNil(NIOSSLConnectionMessage(outgoing: true, version: 0x303, contentType: 21, bytes: buffer.baseAddress!, count: 1))
            let message = NIOSSLConnectionMessage(outgoing: false, version: 0x303, contentType: 21, bytes: buffer.baseAddress!, count: 2)
            XCTAssertEqual(message?.messageType, 40)
            XCTAssertEqual(message?.alertLevel, 2)
        }
    }
}
