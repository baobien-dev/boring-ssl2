import ctypes
from ctypes import CFUNCTYPE, c_int, c_size_t, c_uint8, c_void_p
from enum import IntEnum
from typing import Final, Self, final

from ssl2.errors import EarlyDataRejected, WantReadError

from boring_ssl2.buffer import TLSBuffer
from boring_ssl2.contexts import ClientContext
from boring_ssl2.library import LIBRARY

TLS_1_3: Final = 0x0304
QUIC_V1: Final = 0x00000001
QUIC_V2: Final = 0x6B3343CF
INITIAL_SALTS: Final = {
    QUIC_V1: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    QUIC_V2: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
}
LABEL_PREFIXES: Final = {QUIC_V1: b"quic ", QUIC_V2: b"quicv2 "}
RETRY_KEYS: Final = {
    QUIC_V1: (
        bytes.fromhex("be0c690b9f66575a1d766b54e368c84e"),
        bytes.fromhex("461599d35d632bf2239825bb"),
    ),
    QUIC_V2: (
        bytes.fromhex("8fb4b01b56ac48e260fbcbcead7ccc92"),
        bytes.fromhex("d86969bc2d7c6d9990efb04a"),
    ),
}
TAG_LENGTH: Final = 16
SAMPLE_LENGTH: Final = 16
NONCE_LENGTH: Final = 12
AES_KEY_STRUCTURE: Final = 256

SetSecretFunction = CFUNCTYPE(c_int, c_void_p, c_int, c_void_p, c_void_p, c_size_t)
AddHandshakeDataFunction = CFUNCTYPE(c_int, c_void_p, c_int, c_void_p, c_size_t)
FlushFlightFunction = CFUNCTYPE(c_int, c_void_p)
SendAlertFunction = CFUNCTYPE(c_int, c_void_p, c_int, c_uint8)


class EncryptionLevel(IntEnum):
    INITIAL = 0
    EARLY_DATA = 1
    HANDSHAKE = 2
    APPLICATION = 3


class Suite(IntEnum):
    AES_128_GCM_SHA256 = 0x1301
    AES_256_GCM_SHA384 = 0x1302
    CHACHA20_POLY1305_SHA256 = 0x1303

    @property
    def key_length(self) -> int:
        return 16 if self is Suite.AES_128_GCM_SHA256 else 32

    @property
    def hash_length(self) -> int:
        return 48 if self is Suite.AES_256_GCM_SHA384 else 32

    @property
    def digest(self) -> int:
        return (
            LIBRARY.EVP_sha384()
            if self is Suite.AES_256_GCM_SHA384
            else LIBRARY.EVP_sha256()
        )

    @property
    def aead(self) -> int:
        match self:
            case Suite.AES_128_GCM_SHA256:
                return LIBRARY.EVP_aead_aes_128_gcm()
            case Suite.AES_256_GCM_SHA384:
                return LIBRARY.EVP_aead_aes_256_gcm()
            case Suite.CHACHA20_POLY1305_SHA256:
                return LIBRARY.EVP_aead_chacha20_poly1305()


@final
class QuicMethod(ctypes.Structure):
    _fields_ = (
        ("set_read_secret", SetSecretFunction),
        ("set_write_secret", SetSecretFunction),
        ("add_handshake_data", AddHandshakeDataFunction),
        ("flush_flight", FlushFlightFunction),
        ("send_alert", SendAlertFunction),
    )


@final
class QuicHandshake:
    def __init__(
        self,
        context: ClientContext,
        server_hostname: str,
        transport_parameters: bytes,
        remembered_transport_parameters: bytes = b"",
    ) -> None:
        self.buffer: TLSBuffer = context.create_buffer(server_hostname, quic=True)
        self.secrets: list[tuple[EncryptionLevel, bool, Suite, bytes]] = []
        self.outgoing: dict[EncryptionLevel, bytearray] = {
            level: bytearray() for level in EncryptionLevel
        }
        self.alert: tuple[EncryptionLevel, int] | None = None
        self.flushed = False
        self._callbacks = (
            SetSecretFunction(self._read_secret),
            SetSecretFunction(self._write_secret),
            AddHandshakeDataFunction(self._add_handshake_data),
            FlushFlightFunction(self._flush_flight),
            SendAlertFunction(self._send_alert),
        )
        self._method = QuicMethod(*self._callbacks)
        ssl = self.buffer.handle
        if LIBRARY.SSL_set_min_proto_version(ssl, TLS_1_3) != 1:
            raise LIBRARY.error("SSL_set_min_proto_version")
        if LIBRARY.SSL_set_quic_method(ssl, ctypes.addressof(self._method)) != 1:
            raise LIBRARY.error("SSL_set_quic_method")
        if (
            LIBRARY.SSL_set_quic_transport_params(
                ssl, transport_parameters, len(transport_parameters)
            )
            != 1
        ):
            raise LIBRARY.error("SSL_set_quic_transport_params")
        # BoringSSL keeps no record of the server's transport parameters, so 0-RTT needs the ones the caller remembered
        session = LIBRARY.SSL_get_session(ssl)
        resumable = (
            session is not None and LIBRARY.SSL_SESSION_early_data_capable(session) == 1
        )
        self.remembered_transport_parameters = (
            remembered_transport_parameters if resumable else b""
        )
        self.early_data_offered = bool(self.remembered_transport_parameters)
        self.early_data_rejected = False
        if self.early_data_offered:
            LIBRARY.SSL_set_early_data_enabled(ssl, 1)

    @property
    def in_early_data(self) -> bool:
        return LIBRARY.SSL_in_early_data(self.buffer.handle) == 1

    @property
    def early_data_accepted(self) -> bool:
        return LIBRARY.SSL_early_data_accepted(self.buffer.handle) == 1

    def provide(self, level: EncryptionLevel, data: bytes) -> None:
        if (
            LIBRARY.SSL_provide_quic_data(self.buffer.handle, level, data, len(data))
            != 1
        ):
            raise LIBRARY.error("SSL_provide_quic_data")

    def advance(self) -> bool:
        try:
            self.buffer.do_handshake()
        except WantReadError:
            return False
        except EarlyDataRejected:
            # the handshake goes on without the early data; whatever went out in 0-RTT is sent again in 1-RTT
            LIBRARY.SSL_reset_early_data_reject(self.buffer.handle)
            self.early_data_rejected = True
            return self.advance()
        return not self.in_early_data

    def process_post_handshake(self) -> None:
        if LIBRARY.SSL_process_quic_post_handshake(self.buffer.handle) != 1:
            raise LIBRARY.error("SSL_process_quic_post_handshake")

    @property
    def peer_transport_parameters(self) -> bytes:
        data, length = c_void_p(), c_size_t()
        LIBRARY.SSL_get_peer_quic_transport_params(
            self.buffer.handle, ctypes.byref(data), ctypes.byref(length)
        )
        return b"" if data.value is None else ctypes.string_at(data.value, length.value)

    def take_secrets(self) -> list[tuple[EncryptionLevel, bool, Suite, bytes]]:
        secrets, self.secrets = self.secrets, []
        return secrets

    def take_outgoing(self, level: EncryptionLevel) -> bytes:
        data = bytes(self.outgoing[level])
        self.outgoing[level] = bytearray()
        return data

    def _read_secret(
        self, _ssl: int, level: int, cipher: int, secret: int, length: int
    ) -> int:
        self.secrets.append(
            (
                EncryptionLevel(level),
                False,
                Suite(LIBRARY.SSL_CIPHER_get_protocol_id(cipher)),
                ctypes.string_at(secret, length),
            )
        )
        return 1

    def _write_secret(
        self, _ssl: int, level: int, cipher: int, secret: int, length: int
    ) -> int:
        self.secrets.append(
            (
                EncryptionLevel(level),
                True,
                Suite(LIBRARY.SSL_CIPHER_get_protocol_id(cipher)),
                ctypes.string_at(secret, length),
            )
        )
        return 1

    def _add_handshake_data(self, _ssl: int, level: int, data: int, length: int) -> int:
        self.outgoing[EncryptionLevel(level)] += ctypes.string_at(data, length)
        return 1

    def _flush_flight(self, _ssl: int) -> int:
        self.flushed = True
        return 1

    def _send_alert(self, _ssl: int, level: int, alert: int) -> int:
        self.alert = (EncryptionLevel(level), alert)
        return 1


OUTPUT_BUFFER: Final = 2048


@final
class PacketProtection:
    def __init__(self, suite: Suite, secret: bytes, version: int) -> None:
        self.suite = suite
        self.secret = secret
        self.version = version
        prefix = LABEL_PREFIXES[version]
        key = self.expand_label(suite, secret, prefix + b"key", suite.key_length)
        self._iv = int.from_bytes(
            self.expand_label(suite, secret, prefix + b"iv", NONCE_LENGTH), "big"
        )
        header_key = self.expand_label(suite, secret, prefix + b"hp", suite.key_length)
        aead = LIBRARY.EVP_AEAD_CTX_new(suite.aead, key, len(key), TAG_LENGTH)
        if aead is None:
            raise LIBRARY.error("EVP_AEAD_CTX_new")
        self._aead = aead
        self._output = ctypes.create_string_buffer(OUTPUT_BUFFER)
        self._written = c_size_t()
        self._mask_output = ctypes.create_string_buffer(16)
        self._chacha_key = header_key
        self._aes_key = ctypes.create_string_buffer(AES_KEY_STRUCTURE)
        if (
            suite is not Suite.CHACHA20_POLY1305_SHA256
            and LIBRARY.AES_set_encrypt_key(
                header_key, len(header_key) * 8, self._aes_key
            )
            != 0
        ):
            raise LIBRARY.error("AES_set_encrypt_key")

    def __del__(self) -> None:
        LIBRARY.EVP_AEAD_CTX_free(self._aead)

    @classmethod
    def initial(cls, version: int, connection_id: bytes) -> tuple[Self, Self]:
        suite = Suite.AES_128_GCM_SHA256
        prk = ctypes.create_string_buffer(suite.hash_length)
        prk_length = c_size_t()
        salt = INITIAL_SALTS[version]
        if (
            LIBRARY.HKDF_extract(
                prk,
                ctypes.byref(prk_length),
                suite.digest,
                connection_id,
                len(connection_id),
                salt,
                len(salt),
            )
            != 1
        ):
            raise LIBRARY.error("HKDF_extract")
        initial = prk.raw[: prk_length.value]
        client = cls.expand_label(suite, initial, b"client in", suite.hash_length)
        server = cls.expand_label(suite, initial, b"server in", suite.hash_length)
        return cls(suite, client, version), cls(suite, server, version)

    def update(self) -> Self:
        prefix = LABEL_PREFIXES[self.version]
        updated = type(self)(
            self.suite,
            self.expand_label(
                self.suite, self.secret, prefix + b"ku", self.suite.hash_length
            ),
            self.version,
        )
        # RFC 9001 section 6.1: a key update changes the packet protection keys, never the header protection key
        updated._chacha_key = self._chacha_key
        updated._aes_key = self._aes_key
        return updated

    def seal(self, packet_number: int, header: bytes, payload: bytes) -> bytes:
        out = (
            self._output
            if len(payload) + TAG_LENGTH <= OUTPUT_BUFFER
            else ctypes.create_string_buffer(len(payload) + TAG_LENGTH)
        )
        written = self._written
        nonce = (self._iv ^ packet_number).to_bytes(NONCE_LENGTH, "big")
        if (
            LIBRARY.EVP_AEAD_CTX_seal(
                self._aead,
                out,
                ctypes.byref(written),
                len(out),
                nonce,
                NONCE_LENGTH,
                payload,
                len(payload),
                header,
                len(header),
            )
            != 1
        ):
            raise LIBRARY.error("EVP_AEAD_CTX_seal")
        return ctypes.string_at(out, written.value)

    def open(self, packet_number: int, header: bytes, ciphertext: bytes) -> bytes:
        out = (
            self._output
            if len(ciphertext) <= OUTPUT_BUFFER
            else ctypes.create_string_buffer(len(ciphertext))
        )
        written = self._written
        nonce = (self._iv ^ packet_number).to_bytes(NONCE_LENGTH, "big")
        if (
            LIBRARY.EVP_AEAD_CTX_open(
                self._aead,
                out,
                ctypes.byref(written),
                len(out),
                nonce,
                NONCE_LENGTH,
                ciphertext,
                len(ciphertext),
                header,
                len(header),
            )
            != 1
        ):
            LIBRARY.ERR_clear_error()
            raise ValueError("the packet failed authentication")
        return ctypes.string_at(out, written.value)

    def mask(self, sample: bytes) -> bytes:
        out = self._mask_output
        if self.suite is Suite.CHACHA20_POLY1305_SHA256:
            LIBRARY.CRYPTO_chacha_20(
                out,
                bytes(5),
                5,
                self._chacha_key,
                sample[4:16],
                int.from_bytes(sample[:4], "little"),
            )
        else:
            LIBRARY.AES_encrypt(sample, out, self._aes_key)
        return ctypes.string_at(out, 5)

    @staticmethod
    def retry_tag(
        version: int, original_destination: bytes, pseudo_packet: bytes
    ) -> bytes:
        key, nonce = RETRY_KEYS[version]
        aead = LIBRARY.EVP_AEAD_CTX_new(
            Suite.AES_128_GCM_SHA256.aead, key, len(key), TAG_LENGTH
        )
        if aead is None:
            raise LIBRARY.error("EVP_AEAD_CTX_new")
        out = ctypes.create_string_buffer(TAG_LENGTH)
        written = c_size_t()
        associated = (
            bytes((len(original_destination),)) + original_destination + pseudo_packet
        )
        accepted = LIBRARY.EVP_AEAD_CTX_seal(
            aead,
            out,
            ctypes.byref(written),
            len(out),
            nonce,
            len(nonce),
            b"",
            0,
            associated,
            len(associated),
        )
        LIBRARY.EVP_AEAD_CTX_free(aead)
        if accepted != 1:
            raise LIBRARY.error("EVP_AEAD_CTX_seal")
        return out.raw[: written.value]

    @staticmethod
    def random(length: int) -> bytes:
        out = ctypes.create_string_buffer(length)
        if LIBRARY.RAND_bytes(out, length) != 1:
            raise LIBRARY.error("RAND_bytes")
        return out.raw

    @staticmethod
    def expand_label(suite: Suite, secret: bytes, label: bytes, length: int) -> bytes:
        full = b"tls13 " + label
        info = length.to_bytes(2, "big") + bytes((len(full),)) + full + b"\x00"
        out = ctypes.create_string_buffer(length)
        if (
            LIBRARY.HKDF_expand(
                out, length, suite.digest, secret, len(secret), info, len(info)
            )
            != 1
        ):
            raise LIBRARY.error("HKDF_expand")
        return out.raw
