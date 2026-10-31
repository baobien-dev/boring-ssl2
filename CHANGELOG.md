# Changelog

All notable changes to boring-ssl2. The format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

The engine was written again from the ground up. What a program sees:

### Changed

- BoringSSL at commit ed9209cf of 2026-10-31 and brotli 1.2.1, with two patches made from a checkout.
- `Library(path=...)` loads a build of your own; `ClientContext` and `ServerContext` take `library=`. Functions bind on first use, so a build that lacks one fails at the feature that needs it and names the symbol.
- `LIBRARY` and `IMPLEMENTATION` are gone: `Library.default()` is the bundled build, `BoringSSL.implementation()` the PEP 748 `TLSImplementation`.
- `ClientHelloProfile`, `PacketProtection`, `BrotliDecoder`, `ParsedCertificate` and `CertificateRevocationList` take the `Library` they run on.
- `CMakeLists.txt` takes `BORINGSSL_REVISION`, `BORINGSSL_ARCHIVE_SHA256`, `BORINGSSL_SOURCE_DIR`, `BORINGSSL_PATCHES`, `BROTLI_VERSION` and `BROTLI_ARCHIVE_SHA256`, so another version builds with the same file.

### Added

- `SSL_CTX_set_legacy_padding` in the second patch, and `legacy_padding` on the model, for clients that pad a hello of 256 to 511 bytes to 512.
- The `boring_ssl2` logger reports the loaded build, key logs and stored sessions.

## [1.3.0] - 2026-10-27

- `key_log=` on `ClientContext` writes the NSS key log of TCP and QUIC handshakes.

## [1.2.0] - 2026-10-26

- `QuicVersion`, certificate revocation lists, the socket as BoringSSL's BIO, Chrome's trust anchors.

## [1.1.0] - 2026-10-26

- The ClientHello and HTTP/3 Chrome 155 sends over QUIC.

## [1.0.1] - 2026-10-26

- Requires Python 3.14, not the 3.14.8 patch release.

## [1.0.0] - 2026-10-26

- BoringSSL engine for ssl2.
