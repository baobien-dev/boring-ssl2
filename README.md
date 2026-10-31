# boring-ssl2

BoringSSL as the engine behind ssl2: one shared library with brotli inside, built from a pinned commit with two small patches and bound with ctypes. A ClientHello model goes out byte for byte or is refused with the reason, over TCP or, for a QUIC stack, through the handshake and packet protection of RFC 9001. Requires Python 3.14 and ssl2.

```text
uv add boring-ssl2
```

## HTTPS over the system trust store

```python
from boring_ssl2 import ClientContext
from ssl2 import NextProtocol, TLSClientConfiguration

client = ClientContext(TLSClientConfiguration(inner_protocols=(NextProtocol.HTTP1,)))
connection = client.connect(("www.python.org", 443), timeout=10)
connection.send(b"HEAD / HTTP/1.1\r\nHost: www.python.org\r\nConnection: close\r\n\r\n")
print(connection.recv(4096).split(b"\r\n", 1)[0])  # b'HTTP/1.1 200 OK'
print(connection.negotiated_tls_version, connection.cipher(), connection.negotiated_protocol())  # TLSVersion.TLSv1_3 CipherSuite.TLS_AES_128_GCM_SHA256 NextProtocol.HTTP1
connection.close()
```

## A ClientHello, byte for byte

```python
from boring_ssl2 import ClientContext
from ssl2 import (
    JA4,
    CertificateCompressionAlgorithm,
    CipherSuite,
    ClientHelloBuilder,
    ClientHelloParser,
    ECPointFormat,
    ExtensionType,
    NamedGroup,
    NextProtocol,
    ProtocolVersion,
    PskKeyExchangeMode,
    SignatureScheme,
    TLSClientConfiguration,
    WantReadError,
)

profile = (
    ClientHelloBuilder()
    .supported_versions(ProtocolVersion.TLS_1_3, ProtocolVersion.TLS_1_2)
    .cipher_suites(
        CipherSuite.TLS_AES_128_GCM_SHA256,
        CipherSuite.TLS_AES_256_GCM_SHA384,
        CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
    )
    .extensions(
        ExtensionType.server_name,
        ExtensionType.extended_main_secret,
        ExtensionType.renegotiation_info,
        ExtensionType.supported_groups,
        ExtensionType.ec_point_formats,
        ExtensionType.session_ticket,
        ExtensionType.application_layer_protocol_negotiation,
        ExtensionType.status_request,
        ExtensionType.signature_algorithms,
        ExtensionType.signed_certificate_timestamp,
        ExtensionType.key_share,
        ExtensionType.psk_key_exchange_modes,
        ExtensionType.supported_versions,
        ExtensionType.compress_certificate,
        ExtensionType.application_settings,
        ExtensionType.encrypted_client_hello,
    )
    .supported_groups(NamedGroup.X25519MLKEM768, NamedGroup.x25519, NamedGroup.secp256r1, NamedGroup.secp384r1)
    .key_shares(NamedGroup.X25519MLKEM768, NamedGroup.x25519)
    .ec_point_formats(ECPointFormat.uncompressed)
    .signature_algorithms(
        SignatureScheme.ecdsa_secp256r1_sha256,
        SignatureScheme.rsa_pss_rsae_sha256,
        SignatureScheme.rsa_pkcs1_sha256,
        SignatureScheme.ecdsa_secp384r1_sha384,
        SignatureScheme.rsa_pss_rsae_sha384,
        SignatureScheme.rsa_pkcs1_sha384,
        SignatureScheme.rsa_pss_rsae_sha512,
        SignatureScheme.rsa_pkcs1_sha512,
    )
    .application_protocols(NextProtocol.H2, NextProtocol.HTTP1)
    .application_settings(NextProtocol.H2)
    .certificate_compression(CertificateCompressionAlgorithm.brotli)
    .psk_key_exchange_modes(PskKeyExchangeMode.psk_dhe_ke)
    .build()
)
client = ClientContext(TLSClientConfiguration(client_hello=profile))

buffer = client.create_buffer("tls.peet.ws")
try:
    buffer.do_handshake()
except WantReadError:
    pass
print(ClientHelloParser.parse(buffer.process_outgoing(65536)) == profile)  # True
print(JA4.of(profile).text)  # t13d1516h2_8daaf6152771_d8a2da3f94cd, what tls.peet.ws reports for this connection

connection = client.connect(("tls.peet.ws", 443), timeout=10)  # or proxy=Proxy.parse("socks5h://user:secret@127.0.0.1:1080")
print(connection.negotiated_protocol())  # NextProtocol.H2
connection.close()
```

`grease=True` and `permute_extensions=True` on the model give Chrome's randomized order. What BoringSSL cannot send is refused when the context is built, with the reason:

```python
from dataclasses import replace

from ssl2 import ConfigurationError, NamedGroup

try:
    ClientContext(TLSClientConfiguration(client_hello=replace(profile, supported_groups=(NamedGroup.ffdhe2048, *profile.supported_groups))))
except ConfigurationError as refusal:
    print(refusal)  # BoringSSL does not support the group ffdhe2048
```

## An older client

Clients built on BoringSSL before August 2026, Android among them, pad a ClientHello of 256 to 511 bytes up to 512 with the `padding` extension. The second patch keeps that behaviour available: list `padding` last and set `legacy_padding`, and the padding comes and goes with the size of the hello, as it did on those clients.

```python
from boring_ssl2 import ClientContext
from ssl2 import CipherSuite, ClientHelloBuilder, ClientHelloParser, ECPointFormat, ExtensionType, NamedGroup, NextProtocol, ProtocolVersion, SignatureScheme, TLSClientConfiguration, WantReadError

android = (
    ClientHelloBuilder()
    .supported_versions(ProtocolVersion.TLS_1_2)
    .cipher_suites(
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
    )
    .extensions(
        ExtensionType.server_name,
        ExtensionType.extended_main_secret,
        ExtensionType.renegotiation_info,
        ExtensionType.supported_groups,
        ExtensionType.ec_point_formats,
        ExtensionType.signature_algorithms,
        ExtensionType.application_layer_protocol_negotiation,
        ExtensionType.padding,
    )
    .supported_groups(NamedGroup.x25519, NamedGroup.secp256r1, NamedGroup.secp384r1)
    .ec_point_formats(ECPointFormat.uncompressed)
    .signature_algorithms(
        SignatureScheme.ecdsa_secp256r1_sha256,
        SignatureScheme.rsa_pss_rsae_sha256,
        SignatureScheme.rsa_pkcs1_sha256,
        SignatureScheme.ecdsa_secp384r1_sha384,
        SignatureScheme.rsa_pss_rsae_sha384,
        SignatureScheme.rsa_pkcs1_sha384,
        SignatureScheme.rsa_pss_rsae_sha512,
        SignatureScheme.rsa_pkcs1_sha512,
        SignatureScheme.rsa_pkcs1_sha1,
    )
    .application_protocols(NextProtocol.H2, NextProtocol.HTTP1)
    .legacy_padding()
    .build()
)
client = ClientContext(TLSClientConfiguration(client_hello=android))
for host in ("www.example.com", "a-longer-server-name-with-many-labels.in-the-middle-of-a-domain-that-goes-on.and-another-label-to-pass-the-size.example.org"):
    buffer = client.create_buffer(host)
    try:
        buffer.do_handshake()
    except WantReadError:
        pass
    record = buffer.process_outgoing(65536)
    print(len(record) - 5, ExtensionType.padding in ClientHelloParser.parse(record).extensions)  # 162 False, then 512 True
```

## asyncio

```python
import asyncio

from boring_ssl2 import ClientContext
from ssl2 import NextProtocol, TLSClientConfiguration, TLSStream


async def main() -> None:
    client = ClientContext(TLSClientConfiguration(inner_protocols=(NextProtocol.HTTP1,)))
    async with asyncio.timeout(10):
        stream = await TLSStream.connect(client, ("www.python.org", 443))
    await stream.write(b"HEAD / HTTP/1.1\r\nHost: www.python.org\r\nConnection: close\r\n\r\n")
    print((await stream.read(4096)).split(b"\r\n", 1)[0])  # b'HTTP/1.1 200 OK'
    await stream.close()


asyncio.run(main())
```

## Session resumption

```python
from boring_ssl2 import ClientContext
from ssl2 import NextProtocol, SessionCache, TLSClientConfiguration

cache = SessionCache()
client = ClientContext(TLSClientConfiguration(inner_protocols=(NextProtocol.HTTP1,)), session_cache=cache)
for _ in range(2):
    connection = client.connect(("www.python.org", 443), timeout=10)
    connection.send(b"HEAD / HTTP/1.1\r\nHost: www.python.org\r\nConnection: close\r\n\r\n")
    connection.recv(4096)
    print(connection.buffer.session_reused)  # False, then True
    connection.close()
```

A model that lists `pre_shared_key` last needs a `session_cache`; the first hello goes out without it and the resumed hello equals the model. `key_log="keys.txt"` on `ClientContext` appends every secret of its TCP and QUIC handshakes in the NSS key log format, which Wireshark reads.

## Server

```python
from boring_ssl2 import ServerContext
from ssl2 import Certificate, PrivateKey, SigningChain, TLSServerConfiguration

chain = SigningChain((Certificate.from_file("server.pem"), PrivateKey.from_file("server.key")))
server = ServerContext(TLSServerConfiguration(certificate_chain=(chain,)))
listener = server.connect(("127.0.0.1", 8443))
listener.listen(5)
connection, peer = listener.accept()
connection.send(b"echo: " + connection.recv(1024))
connection.close()
```

Several chains in `certificate_chain` are picked by SNI. A `trust_store` on the server configuration demands a client certificate, which the client passes as `certificate_chain`. The server offers brotli, zstd and zlib certificate compression to clients that ask for it.

## Sans-IO

```python
import socket

from boring_ssl2 import ClientContext
from ssl2 import TLSClientConfiguration, WantReadError

client = ClientContext(TLSClientConfiguration())
tcp = socket.create_connection(("www.python.org", 443))
buffer = client.create_buffer("www.python.org")
while True:
    try:
        buffer.do_handshake()
        break
    except WantReadError:
        tcp.sendall(buffer.process_outgoing(65536))
        buffer.process_incoming(tcp.recv(65536))
print(buffer.negotiated_tls_version, buffer.cipher())  # TLSVersion.TLSv1_3 CipherSuite.TLS_AES_128_GCM_SHA256
```

## Your own BoringSSL

The wheel carries a build of the pinned commit. A build of your own, another commit or a patched checkout, is a path:

```python
from boring_ssl2 import Library

library = Library()  # the bundled build; Library(path="/opt/tls/libboring_ssl2.so") is yours
print(library.source_revision)  # ed9209cff8b5a2fbc6c10050f29b3355048bda85
```

`ClientContext(configuration, library=library)` and `ServerContext(configuration, library=library)` use it. Functions bind when first called, so a build that lacks one fails at the feature that needs it and names the symbol, not at import.

The same `CMakeLists.txt` builds any version. The commit, its archive hash and the patch directory are cache variables; a checkout on disk skips the download and the patches:

```text
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target boring_ssl2
cmake --install build --prefix src       # writes src/boring_ssl2/libboring_ssl2.so, .dylib or .dll

cmake -S . -B build -DBORINGSSL_REVISION=<commit> -DBORINGSSL_ARCHIVE_SHA256=<sha256 of the GitHub archive>
cmake -S . -B build -DBORINGSSL_SOURCE_DIR=/path/to/boringssl
```

The patches in `patches/boringssl` add `SSL_CTX_set1_extension_order` for the model's extension order and `SSL_CTX_set_legacy_padding` for the padding of older clients. They come from commits on a checkout and apply to the download in file name order; a build without them lacks those two features and nothing else.

The wheels on PyPI carry the library for Linux (glibc 2.28, x86_64 and aarch64), macOS 11 (arm64 and x86_64) and Windows x64, with the licenses of BoringSSL and brotli next to it in `boring_ssl2/licenses`. On Termux, `pkg install cmake ninja clang git` and the three cmake commands above build it on the device, after which `uv pip install .` packages what was built. For an iOS app the publish workflow leaves the arm64 device and simulator builds as artifacts; the app bundles one as a framework and passes its path to `Library`.
