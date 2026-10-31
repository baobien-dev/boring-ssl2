import ctypes
from ctypes import c_size_t, c_void_p
from enum import IntEnum
from typing import Self

from ssl2.errors import EarlyDataRejectedError, WantReadError
from ssl2.registry import ProtocolVersion

from boring_ssl2.binding import Callback
from boring_ssl2.buffer import TLSBuffer
from boring_ssl2.contexts import ClientContext
from boring_ssl2.library import Library


class QuicVersion(IntEnum):
    V1 = 0x00000001
    V2 = 0x6B3343CF

    @property
    def initial_salt(self) -> bytes:
        # RFC 9001 section 5.2 and RFC 9369 section 3.3.1
        match self:
            case QuicVersion.V1:
                return bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
            case QuicVersion.V2:
                return bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")

    @property
    def label_prefix(self) -> bytes:
        match self:
            case QuicVersion.V1:
                return b"quic "
            case QuicVersion.V2:
                return b"quicv2 "

    @property
    def retry_key(self) -> tuple[bytes, bytes]:
        # RFC 9001 section 5.8 and RFC 9369 section 3.3.3: the key and nonce of the Retry integrity tag
        match self:
            case QuicVersion.V1:
                return (bytes.fromhex("be0c690b9f66575a1d766b54e368c84e"), bytes.fromhex("461599d35d632bf2239825bb"))
            case QuicVersion.V2:
                return (bytes.fromhex("8fb4b01b56ac48e260fbcbcead7ccc92"), bytes.fromhex("d86969bc2d7c6d9990efb04a"))


class EncryptionLevel(IntEnum):
    INITIAL = 0
    EARLY_DATA = 1
    HANDSHAKE = 2
    APPLICATION = 3


class Size(IntEnum):
    TAG = 16
    SAMPLE = 16
    NONCE = 12
    MASK = 5
    # the first four bytes of the sample are ChaCha20's block counter, the other twelve its nonce
    CHACHA_COUNTER = 4
    # sizeof(AES_KEY) is 244 bytes; the buffer is rounded up
    AES_KEY_STRUCTURE = 256
    OUTPUT = 2048
    BITS_PER_BYTE = 8


class Suite(IntEnum):
    AES_128_GCM_SHA256 = 0x1301
    AES_256_GCM_SHA384 = 0x1302
    CHACHA20_POLY1305_SHA256 = 0x1303

    @property
    def key_length(self) -> int:
        return Size.SAMPLE if self is Suite.AES_128_GCM_SHA256 else Size.SAMPLE + Size.SAMPLE

    @property
    def hash_length(self) -> int:
        return HashLength.SHA384 if self is Suite.AES_256_GCM_SHA384 else HashLength.SHA256

    def digest(self, library: Library) -> int:
        return library.EVP_sha384() if self is Suite.AES_256_GCM_SHA384 else library.EVP_sha256()

    def aead(self, library: Library) -> int:
        match self:
            case Suite.AES_128_GCM_SHA256:
                return library.EVP_aead_aes_128_gcm()
            case Suite.AES_256_GCM_SHA384:
                return library.EVP_aead_aes_256_gcm()
            case Suite.CHACHA20_POLY1305_SHA256:
                return library.EVP_aead_chacha20_poly1305()


class HashLength(IntEnum):
    SHA256 = 32
    SHA384 = 48


class QuicMethod(ctypes.Structure):
    _fields_ = (
        ("set_read_secret", Callback.QUIC_SET_SECRET),
        ("set_write_secret", Callback.QUIC_SET_SECRET),
        ("add_handshake_data", Callback.QUIC_ADD_HANDSHAKE_DATA),
        ("flush_flight", Callback.QUIC_FLUSH_FLIGHT),
        ("send_alert", Callback.QUIC_SEND_ALERT),
    )


class QuicHandshake:
    # BoringSSL's QUIC method: the handshake messages and secrets come out through callbacks, the QUIC stack moves them
    def __init__(
        self,
        context: ClientContext,
        server_hostname: str,
        transport_parameters: bytes,
        remembered_transport_parameters: bytes = b"",
    ) -> None:
        self.buffer: TLSBuffer = context.create_buffer(server_hostname, quic=True)
        self.library: Library = context.library
        self.secrets: list[tuple[EncryptionLevel, bool, Suite, bytes]] = []
        self.outgoing: dict[EncryptionLevel, bytearray] = {level: bytearray() for level in EncryptionLevel}
        self.alert: tuple[EncryptionLevel, int] | None = None
        self.flushed = False
        self._callbacks = (
            Callback.QUIC_SET_SECRET(self._read_secret),
            Callback.QUIC_SET_SECRET(self._write_secret),
            Callback.QUIC_ADD_HANDSHAKE_DATA(self._add_handshake_data),
            Callback.QUIC_FLUSH_FLIGHT(self._flush_flight),
            Callback.QUIC_SEND_ALERT(self._send_alert),
        )
        self._method = QuicMethod(*self._callbacks)
        library, ssl = self.library, self.buffer.handle
        library.check(library.SSL_set_min_proto_version(ssl, ProtocolVersion.TLS_1_3), "SSL_set_min_proto_version")
        library.check(library.SSL_set_quic_method(ssl, ctypes.addressof(self._method)), "SSL_set_quic_method")
        library.check(
            library.SSL_set_quic_transport_params(ssl, transport_parameters, len(transport_parameters)),
            "SSL_set_quic_transport_params",
        )
        # BoringSSL keeps no record of the server's transport parameters, so 0-RTT needs the ones the caller remembered
        session = library.SSL_get_session(ssl)
        resumable = session is not None and library.SSL_SESSION_early_data_capable(session) == 1
        self.remembered_transport_parameters = remembered_transport_parameters if resumable else b""
        self.early_data_offered = bool(self.remembered_transport_parameters)
        self.early_data_rejected = False
        if self.early_data_offered:
            library.SSL_set_early_data_enabled(ssl, 1)

    @property
    def in_early_data(self) -> bool:
        return self.library.SSL_in_early_data(self.buffer.handle) == 1

    @property
    def early_data_accepted(self) -> bool:
        return self.library.SSL_early_data_accepted(self.buffer.handle) == 1

    def provide(self, level: EncryptionLevel, data: bytes) -> None:
        self.library.check(
            self.library.SSL_provide_quic_data(self.buffer.handle, level, data, len(data)), "SSL_provide_quic_data"
        )

    def advance(self) -> bool:
        # returns whether the handshake is complete
        try:
            self.buffer.do_handshake()
        except WantReadError:
            return False
        except EarlyDataRejectedError:
            # the handshake goes on without the early data; whatever went out in 0-RTT is sent again in 1-RTT
            self.library.SSL_reset_early_data_reject(self.buffer.handle)
            self.early_data_rejected = True
            return self.advance()
        return not self.in_early_data

    def process_post_handshake(self) -> None:
        self.library.check(
            self.library.SSL_process_quic_post_handshake(self.buffer.handle), "SSL_process_quic_post_handshake"
        )

    @property
    def peer_transport_parameters(self) -> bytes:
        data, length = c_void_p(), c_size_t()
        self.library.SSL_get_peer_quic_transport_params(self.buffer.handle, ctypes.byref(data), ctypes.byref(length))
        return b"" if data.value is None else ctypes.string_at(data.value, length.value)

    def take_secrets(self) -> list[tuple[EncryptionLevel, bool, Suite, bytes]]:
        secrets, self.secrets = self.secrets, []
        return secrets

    def take_outgoing(self, level: EncryptionLevel) -> bytes:
        data = bytes(self.outgoing[level])
        self.outgoing[level] = bytearray()
        return data

    def _read_secret(self, _ssl: int, level: int, cipher: int, secret: int, length: int) -> int:
        self._record_secret(level, cipher, secret, length, write=False)
        return 1

    def _write_secret(self, _ssl: int, level: int, cipher: int, secret: int, length: int) -> int:
        self._record_secret(level, cipher, secret, length, write=True)
        return 1

    def _record_secret(self, level: int, cipher: int, secret: int, length: int, *, write: bool) -> None:
        suite = Suite(self.library.SSL_CIPHER_get_protocol_id(cipher))
        self.secrets.append((EncryptionLevel(level), write, suite, ctypes.string_at(secret, length)))

    def _add_handshake_data(self, _ssl: int, level: int, data: int, length: int) -> int:
        self.outgoing[EncryptionLevel(level)] += ctypes.string_at(data, length)
        return 1

    def _flush_flight(self, _ssl: int) -> int:
        self.flushed = True
        return 1

    def _send_alert(self, _ssl: int, level: int, alert: int) -> int:
        self.alert = (EncryptionLevel(level), alert)
        return 1


class PacketProtection:
    # RFC 9001 section 5: the packet keys, header protection and key update of one direction at one level
    def __init__(
        self, library: Library, suite: Suite, secret: bytes, version: QuicVersion, header_key: bytes | None = None
    ) -> None:
        self.library = library
        self.suite = suite
        self.secret = secret
        self.version = version
        prefix = version.label_prefix
        key = self.expand_label(library, suite, secret, prefix + b"key", suite.key_length)
        self._iv = int.from_bytes(self.expand_label(library, suite, secret, prefix + b"iv", Size.NONCE), "big")
        # a key update keeps the header protection key of the keys it replaces, so update() passes it in
        self._header_key = header_key or self.expand_label(library, suite, secret, prefix + b"hp", suite.key_length)
        aead = library.EVP_AEAD_CTX_new(suite.aead(library), key, len(key), Size.TAG)
        if aead is None:
            raise library.error("EVP_AEAD_CTX_new")
        self._aead = aead
        self._output = ctypes.create_string_buffer(Size.OUTPUT)
        self._written = c_size_t()
        self._written_ref = ctypes.byref(self._written)
        self._mask_output = ctypes.create_string_buffer(Size.SAMPLE)
        self._aes_key = ctypes.create_string_buffer(Size.AES_KEY_STRUCTURE)
        # AES_set_encrypt_key answers zero on success
        if suite is not Suite.CHACHA20_POLY1305_SHA256 and (
            library.AES_set_encrypt_key(self._header_key, len(self._header_key) * Size.BITS_PER_BYTE, self._aes_key)
            != 0
        ):
            raise library.error("AES_set_encrypt_key")

    def __del__(self) -> None:
        self.library.EVP_AEAD_CTX_free(self._aead)

    @classmethod
    def initial(cls, library: Library, version: QuicVersion, connection_id: bytes) -> tuple[Self, Self]:
        # RFC 9001 section 5.2: the client and server Initial keys from the destination connection id
        suite = Suite.AES_128_GCM_SHA256
        prk = ctypes.create_string_buffer(suite.hash_length)
        prk_length = c_size_t()
        salt = version.initial_salt
        extracted = library.HKDF_extract(
            prk, ctypes.byref(prk_length), suite.digest(library), connection_id, len(connection_id), salt, len(salt)
        )
        library.check(extracted, "HKDF_extract")
        initial = prk.raw[: prk_length.value]
        client = cls.expand_label(library, suite, initial, b"client in", suite.hash_length)
        server = cls.expand_label(library, suite, initial, b"server in", suite.hash_length)
        return cls(library, suite, client, version), cls(library, suite, server, version)

    def update(self) -> Self:
        # RFC 9001 section 6.1: a key update changes the packet protection keys, never the header protection key
        prefix = self.version.label_prefix
        secret = self.expand_label(self.library, self.suite, self.secret, prefix + b"ku", self.suite.hash_length)
        return type(self)(self.library, self.suite, secret, self.version, header_key=self._header_key)

    def seal(self, packet_number: int, header: bytes, payload: bytes) -> bytes:
        out = (
            self._output
            if len(payload) + Size.TAG <= Size.OUTPUT
            else ctypes.create_string_buffer(len(payload) + Size.TAG)
        )
        sealed = self.library.EVP_AEAD_CTX_seal(
            self._aead,
            out,
            self._written_ref,
            len(out),
            self._nonce(packet_number),
            Size.NONCE,
            payload,
            len(payload),
            header,
            len(header),
        )
        self.library.check(sealed, "EVP_AEAD_CTX_seal")
        return out.raw[: self._written.value]

    def open(self, packet_number: int, header: bytes, ciphertext: bytes) -> bytes:
        out = self._output if len(ciphertext) <= Size.OUTPUT else ctypes.create_string_buffer(len(ciphertext))
        opened = self.library.EVP_AEAD_CTX_open(
            self._aead,
            out,
            self._written_ref,
            len(out),
            self._nonce(packet_number),
            Size.NONCE,
            ciphertext,
            len(ciphertext),
            header,
            len(header),
        )
        if opened != 1:
            self.library.ERR_clear_error()
            raise ValueError("the packet failed authentication")
        return out.raw[: self._written.value]

    def mask(self, sample: bytes) -> bytes:
        # RFC 9001 section 5.4: the header protection mask from a sample of the ciphertext
        out = self._mask_output
        if self.suite is Suite.CHACHA20_POLY1305_SHA256:
            counter = int.from_bytes(sample[: Size.CHACHA_COUNTER], "little")
            self.library.CRYPTO_chacha_20(
                out, bytes(Size.MASK), Size.MASK, self._header_key, sample[Size.CHACHA_COUNTER : Size.SAMPLE], counter
            )
        else:
            self.library.AES_encrypt(sample, out, self._aes_key)
        return out.raw[: Size.MASK]

    @staticmethod
    def retry_tag(library: Library, version: QuicVersion, original_destination: bytes, pseudo_packet: bytes) -> bytes:
        # RFC 9001 section 5.8: the integrity tag over the original destination id and the Retry packet
        key, nonce = version.retry_key
        aead = library.EVP_AEAD_CTX_new(Suite.AES_128_GCM_SHA256.aead(library), key, len(key), Size.TAG)
        if aead is None:
            raise library.error("EVP_AEAD_CTX_new")
        out = ctypes.create_string_buffer(Size.TAG)
        written = c_size_t()
        associated = bytes((len(original_destination),)) + original_destination + pseudo_packet
        sealed = library.EVP_AEAD_CTX_seal(
            aead, out, ctypes.byref(written), len(out), nonce, len(nonce), b"", 0, associated, len(associated)
        )
        library.EVP_AEAD_CTX_free(aead)
        library.check(sealed, "EVP_AEAD_CTX_seal")
        return out.raw[: written.value]

    @staticmethod
    def random(library: Library, length: int) -> bytes:
        out = ctypes.create_string_buffer(length)
        library.check(library.RAND_bytes(out, length), "RAND_bytes")
        return out.raw

    @staticmethod
    def expand_label(library: Library, suite: Suite, secret: bytes, label: bytes, length: int) -> bytes:
        # RFC 8446 section 7.1 HKDF-Expand-Label with the tls13 prefix
        full = b"tls13 " + label
        info = length.to_bytes(2, "big") + bytes((len(full),)) + full + b"\x00"
        out = ctypes.create_string_buffer(length)
        library.check(
            library.HKDF_expand(out, length, suite.digest(library), secret, len(secret), info, len(info)), "HKDF_expand"
        )
        return out.raw

    def _nonce(self, packet_number: int) -> bytes:
        return (self._iv ^ packet_number).to_bytes(Size.NONCE, "big")
