# Changelog

All notable changes to boring-ssl2. The format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
