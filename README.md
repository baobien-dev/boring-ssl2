# boring-ssl2

BoringSSL, at a pinned commit with one patch for explicit ClientHello extension order, built into one shared library with brotli inside and bound with ctypes. It implements the `ssl2` (PEP 748) interface: `ClientContext`, `ServerContext`, `TLSBuffer`. A `ClientHello` model is sent exactly as described or refused with the reason, over TCP or, with `quic_transport_parameters` listed, over QUIC. Certificate compression with brotli, zstd and zlib, session resumption, SNI based chain selection and client certificates are included, and `QuicHandshake` with `PacketProtection` give a QUIC stack the TLS 1.3 handshake, packet keys, header protection, key updates and 0-RTT of RFC 9001. Requires Python 3.14 and `ssl2`.

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
print(connection.negotiated_tls_version, connection.cipher().name, connection.negotiated_protocol())  # TLSVersion.TLSv1_3 TLS_AES_128_GCM_SHA256 NextProtocol.HTTP1
connection.close()
```

## A ClientHello profile, byte for byte

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
    Proxy,
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

Set `grease=True` and `permute_extensions=True` on the model for Chrome's randomized order. What BoringSSL cannot send is refused when the context is built:

```python
from dataclasses import replace

from ssl2 import ConfigurationError, NamedGroup

try:
    ClientContext(TLSClientConfiguration(client_hello=replace(profile, supported_groups=(NamedGroup.ffdhe2048, *profile.supported_groups))))
except ConfigurationError as refusal:
    print(refusal)  # BoringSSL does not support the group ffdhe2048
```

## asyncio

```python
import asyncio

from boring_ssl2 import ClientContext
from ssl2 import NextProtocol, TLSClientConfiguration, TLSStream


async def main() -> None:
    client = ClientContext(TLSClientConfiguration(inner_protocols=(NextProtocol.HTTP1,)))
    stream = await TLSStream.connect(client, ("www.python.org", 443), timeout=10)
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

A `ClientHello` model that lists `pre_shared_key` last needs a `session_cache`; the first hello goes out without it and the resumed hello equals the model.

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

Several chains in `certificate_chain` are selected by SNI. A `trust_store` on the server configuration demands a client certificate, which the client passes as `certificate_chain`. The server offers brotli, zstd and zlib certificate compression to clients that ask for it.

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
print(buffer.negotiated_tls_version, buffer.cipher().name)  # TLSVersion.TLSv1_3 TLS_AES_128_GCM_SHA256
```

## Building the library

```text
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target boring_ssl2
cmake --install build --prefix src
uv build --wheel
```

The library links the static BoringSSL and brotli archives with whole-archive and `-Bsymbolic`, depends only on libc and libm, and reports its commit through `boring_ssl2.LIBRARY.source_revision`.
