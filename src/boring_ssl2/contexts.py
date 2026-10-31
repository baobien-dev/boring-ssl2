import ctypes
import ipaddress
import logging
import os
from collections.abc import Callable, Iterable
from ctypes import c_size_t, c_void_p
from enum import IntEnum, IntFlag
from pathlib import Path

from ssl2.credentials import Certificate, Credential, PrivateKey, SigningChain, TrustStore
from ssl2.errors import ConfigurationError
from ssl2.interface import SessionCache, TLSClientConfiguration, TLSImplementation, TLSServerConfiguration, TLSSocket
from ssl2.proxy import Proxy
from ssl2.registry import (
    CertificateCompressionAlgorithm,
    ExtensionType,
    NextProtocol,
    ProtocolVersion,
    ServerNameType,
    TLSVersion,
)
from ssl2.tracing import Trace

from boring_ssl2.binding import Callback
from boring_ssl2.buffer import TLSBuffer
from boring_ssl2.compression import CertificateCompression
from boring_ssl2.library import Library
from boring_ssl2.profile import CipherList, ClientHelloProfile


class VerifyMode(IntFlag):
    NONE = 0x00
    PEER = 0x01
    FAIL_IF_NO_PEER_CERT = 0x02


class SessionCacheMode(IntFlag):
    CLIENT = 0x01


class ExtensionCallbackResult(IntEnum):
    # SSL_TLSEXT_ERR_*
    OK = 0
    ALERT_FATAL = 2
    NOACK = 3


class ProtocolSelection(IntEnum):
    # SSL_select_next_proto
    NEGOTIATED = 1


class Pem:
    PREAMBLE = b"-----BEGIN"


class Context:
    logger = logging.getLogger("boring_ssl2")

    def __init__(self, library: Library | None) -> None:
        self.library = library or Library.default()
        self._callbacks: list[object] = []
        self._compression = CertificateCompression(self.library)

    @classmethod
    def validate(
        cls, configuration: TLSClientConfiguration | TLSServerConfiguration, library: Library | None = None
    ) -> None:
        library = library or Library.default()
        match configuration:
            case TLSClientConfiguration():
                chains = () if configuration.certificate_chain is None else (configuration.certificate_chain,)
                if configuration.client_hello is not None:
                    handle = cls._new(library)
                    ClientHelloProfile(configuration.client_hello).configure(library, handle)
                    library.SSL_CTX_free(handle)
            case TLSServerConfiguration():
                chains = configuration.certificate_chain or ()
                if not chains:
                    raise ConfigurationError("a server needs at least one signing chain")
        credentials: list[Credential | None] = [configuration.trust_store]
        for chain in chains:
            credentials += (*chain.leaf, *(chain.chain or ()))
        for credential in credentials:
            if credential is not None and credential.id is not None:
                raise ConfigurationError(f"BoringSSL cannot load a {type(credential).__name__} by identifier")

    @staticmethod
    def _new(library: Library) -> int:
        handle = library.SSL_CTX_new(library.TLS_method())
        if handle is None:
            raise library.error("SSL_CTX_new")
        return handle

    def _set_versions(self, handle: int, lowest: TLSVersion | None, highest: TLSVersion | None) -> None:
        minimum = ProtocolVersion.TLS_1_2 if lowest is None else ProtocolVersion.of(lowest) or ProtocolVersion.TLS_1_0
        maximum = ProtocolVersion.TLS_1_3 if highest is None else ProtocolVersion.of(highest) or ProtocolVersion.TLS_1_3
        self.library.check(self.library.SSL_CTX_set_min_proto_version(handle, minimum), "SSL_CTX_set_min_proto_version")
        self.library.check(self.library.SSL_CTX_set_max_proto_version(handle, maximum), "SSL_CTX_set_max_proto_version")

    @staticmethod
    def _alpn_wire(protocols: Iterable[NextProtocol | bytes]) -> bytes:
        values = (protocol.value if isinstance(protocol, NextProtocol) else protocol for protocol in protocols)
        return ClientHelloProfile.alpn_wire(values)

    def _load_trust(self, handle: int, store: TrustStore) -> None:
        library = self.library
        if store.buffer is not None:
            for certificate in self._pem_certificates(store.buffer):
                accepted = library.X509_STORE_add_cert(library.SSL_CTX_get_cert_store(handle), certificate)
                library.X509_free(certificate)
                library.check(accepted, "X509_STORE_add_cert")
        elif store.path is not None:
            bundle, directory = (bytes(store.path), None) if store.path.is_file() else (None, bytes(store.path))
            library.check(
                library.SSL_CTX_load_verify_locations(handle, bundle, directory), "SSL_CTX_load_verify_locations"
            )
        elif store.id is not None:
            raise ConfigurationError("BoringSSL cannot load a trust store by identifier")
        else:
            self._load_trust(handle, TrustStore.system())

    def _use_chain(self, handle: int, chain: SigningChain) -> int:
        library = self.library
        leaf_source, key_source = chain.leaf
        if key_source is None:
            raise ConfigurationError("BoringSSL needs the private key of the leaf certificate")
        leaf = self._certificate(leaf_source)
        library.check(library.SSL_CTX_use_certificate(handle, leaf), "SSL_CTX_use_certificate")
        key = self._private_key(key_source)
        accepted = library.SSL_CTX_use_PrivateKey(handle, key)
        library.EVP_PKEY_free(key)
        library.check(accepted, "SSL_CTX_use_PrivateKey")
        for intermediate in chain.chain or ():
            certificate = self._certificate(intermediate)
            accepted = library.SSL_CTX_add1_chain_cert(handle, certificate)
            library.X509_free(certificate)
            library.check(accepted, "SSL_CTX_add1_chain_cert")
        return leaf

    def _certificate(self, source: Certificate) -> int:
        data = self._bytes(source)
        if data.lstrip().startswith(Pem.PREAMBLE):
            first, *extra = self._pem_certificates(data)
            for certificate in extra:
                self.library.X509_free(certificate)
            return first
        return self._der(data, self.library.d2i_X509, "d2i_X509")

    def _private_key(self, source: PrivateKey) -> int:
        data = self._bytes(source)
        if not data.lstrip().startswith(Pem.PREAMBLE):
            return self._der(data, self.library.d2i_AutoPrivateKey, "d2i_AutoPrivateKey")
        memory = self._memory(data)
        key = self.library.PEM_read_bio_PrivateKey(memory, None, None, None)
        self.library.BIO_free(memory)
        if key is None:
            raise self.library.error("PEM_read_bio_PrivateKey")
        return key

    def _pem_certificates(self, data: bytes) -> list[int]:
        library = self.library
        memory = self._memory(data)
        certificates: list[int] = []
        while (certificate := library.PEM_read_bio_X509(memory, None, None, None)) is not None:
            certificates.append(certificate)
        library.BIO_free(memory)
        # the loop ends on BoringSSL's "no start line" error, which is the end of the data, not a failure
        library.ERR_clear_error()
        if not certificates:
            raise ConfigurationError("no PEM certificate found")
        return certificates

    def _memory(self, data: bytes) -> int:
        memory = self.library.BIO_new_mem_buf(data, len(data))
        if memory is None:
            raise self.library.error("BIO_new_mem_buf")
        return memory

    def _der(self, data: bytes, parse: Callable[[None, object, int], int | None], operation: str) -> int:
        storage = ctypes.create_string_buffer(data, len(data))
        cursor = c_void_p(ctypes.addressof(storage))
        handle = parse(None, ctypes.byref(cursor), len(data))
        if handle is None:
            raise self.library.error(operation)
        return handle

    @staticmethod
    def _bytes(credential: Credential) -> bytes:
        if credential.buffer is not None:
            return credential.buffer
        if credential.path is not None:
            return Path(credential.path).read_bytes()
        if credential.id is not None:
            raise ConfigurationError(f"BoringSSL cannot load a {type(credential).__name__} by identifier")
        raise ConfigurationError(f"the {type(credential).__name__} has neither a buffer nor a path")


class ClientContext(Context):
    def __init__(
        self,
        configuration: TLSClientConfiguration,
        *,
        session_cache: SessionCache | None = None,
        key_log: str | os.PathLike[str] | None = None,
        library: Library | None = None,
    ) -> None:
        super().__init__(library)
        self._configuration = configuration
        self._cache = session_cache
        self._key_log = key_log
        self._handle = self._new(self.library)
        hello = configuration.client_hello
        self._profile = None if hello is None else ClientHelloProfile(hello)
        if configuration.verify_certificates:
            self.library.SSL_CTX_set_verify(self._handle, VerifyMode.PEER, None)
            self._load_trust(self._handle, configuration.trust_store or TrustStore.system())
        else:
            self.library.SSL_CTX_set_verify(self._handle, VerifyMode.NONE, None)
        if configuration.certificate_chain is not None:
            self.library.X509_free(self._use_chain(self._handle, configuration.certificate_chain))
        if hello is None or self._profile is None:
            self._set_versions(
                self._handle, configuration.lowest_supported_version, configuration.highest_supported_version
            )
            if configuration.ciphers is not None:
                CipherList(configuration.ciphers).configure(self.library, self._handle)
            if configuration.inner_protocols:
                wire = self._alpn_wire(configuration.inner_protocols)
                self.library.check(
                    self.library.SSL_CTX_set_alpn_protos(self._handle, wire, len(wire)) == 0, "SSL_CTX_set_alpn_protos"
                )
        else:
            self._profile.configure(self.library, self._handle)
            for algorithm in hello.certificate_compression_algorithms:
                self._compression.register(self._handle, algorithm, client=True)
        resumption = hello is not None and hello.offers(ExtensionType.pre_shared_key)
        if hello is not None and resumption != (session_cache is not None):
            raise ConfigurationError("pre_shared_key in the ClientHello and a session cache go together")
        if session_cache is not None:
            callback = Callback.NEW_SESSION(self._record_session)
            self._callbacks.append(callback)
            self.library.SSL_CTX_set_session_cache_mode(self._handle, SessionCacheMode.CLIENT)
            self.library.SSL_CTX_sess_set_new_cb(self._handle, callback)
        if key_log is not None:
            callback = Callback.KEY_LOG(self._log_key)
            self._callbacks.append(callback)
            self.library.SSL_CTX_set_keylog_callback(self._handle, callback)
            self.logger.info("context.key_log path=%s", key_log)
        self.logger.debug(
            "context.created profile=%s verify=%s session_cache=%s",
            hello is not None,
            configuration.verify_certificates,
            session_cache is not None,
        )

    def __del__(self) -> None:
        self.library.SSL_CTX_free(self._handle)

    @property
    def configuration(self) -> TLSClientConfiguration:
        return self._configuration

    def connect(
        self,
        address: tuple[str | None, int],
        *,
        proxy: Proxy | None = None,
        timeout: float | None = None,
        trace: Trace | None = None,
    ) -> TLSSocket:
        host, port = address
        if host is None:
            raise ConfigurationError("a client connection needs a host")
        return TLSSocket.connect(self, (host, port), proxy=proxy, timeout=timeout, trace=trace)

    def create_buffer(self, server_hostname: str, *, quic: bool = False) -> TLSBuffer:
        library = self.library
        if self._profile is not None:
            self._profile.check_transport(quic=quic)
        buffer = TLSBuffer(self, library, self._handle, server=False, session_key=server_hostname)
        ssl = buffer.handle
        try:
            ipaddress.ip_address(server_hostname)
        except ValueError:
            name = server_hostname.encode("idna")
            library.check(library.SSL_set_tlsext_host_name(ssl, name), "SSL_set_tlsext_host_name")
            library.check(library.SSL_set1_host(ssl, name), "SSL_set1_host")
        else:
            address = server_hostname.encode("ascii")
            library.check(
                library.X509_VERIFY_PARAM_set1_ip_asc(library.SSL_get0_param(ssl), address),
                "X509_VERIFY_PARAM_set1_ip_asc",
            )
        if self._profile is not None:
            self._profile.prepare(library, ssl)
        if self._cache is not None and (session := self._cache.take(server_hostname)) is not None:
            self._resume(ssl, session)
            self.logger.debug("session.offered host=%s", server_hostname)
        return buffer

    def _resume(self, ssl: int, serialized: bytes) -> None:
        library = self.library
        session = library.SSL_SESSION_from_bytes(serialized, len(serialized), self._handle)
        if session is None:
            raise library.error("SSL_SESSION_from_bytes")
        accepted = library.SSL_set_session(ssl, session)
        library.SSL_SESSION_free(session)
        library.check(accepted, "SSL_set_session")

    def _log_key(self, _ssl: int, line: bytes) -> None:
        # one secret per line in the NSS key log format that Wireshark reads, QUIC handshakes included
        if self._key_log is not None:
            with Path(self._key_log).open("a", encoding="ascii") as log:
                log.write(line.decode("ascii") + "\n")

    def _record_session(self, ssl: int, session: int) -> int:
        library = self.library
        key = library.SSL_get_ex_data(ssl, ExDataIndex.SESSION_KEY)
        data, length = c_void_p(), c_size_t()
        if (
            key is None
            or self._cache is None
            or library.SSL_SESSION_to_bytes(session, ctypes.byref(data), ctypes.byref(length)) != 1
            or data.value is None
        ):
            return 0
        serialized = ctypes.string_at(data.value, length.value)
        library.OPENSSL_free(data.value)
        single_use = library.SSL_SESSION_should_be_single_use(session) == 1
        host = ctypes.string_at(key).decode()
        self._cache.store(host, serialized, single_use=single_use)
        self.logger.debug("session.stored host=%s single_use=%s size=%d", host, single_use, len(serialized))
        return 0


class ExDataIndex(IntEnum):
    SESSION_KEY = 0


class ServerContext(Context):
    def __init__(self, configuration: TLSServerConfiguration, *, library: Library | None = None) -> None:
        super().__init__(library)
        if not configuration.certificate_chain:
            raise ConfigurationError("a server needs at least one signing chain")
        self._configuration = configuration
        self._alpn = self._alpn_wire(configuration.inner_protocols or ())
        self._handles: list[int] = []
        self._leaves: list[int] = []
        for chain in configuration.certificate_chain:
            handle = self._new(self.library)
            self._handles.append(handle)
            self._leaves.append(self._use_chain(handle, chain))
            self._set_versions(handle, configuration.lowest_supported_version, configuration.highest_supported_version)
            if configuration.ciphers is not None:
                CipherList(configuration.ciphers).configure(self.library, handle)
            if self._alpn:
                callback = Callback.PROTOCOL_SELECT(self._select_protocol)
                self._callbacks.append(callback)
                self.library.SSL_CTX_set_alpn_select_cb(handle, callback, None)
            if configuration.trust_store is not None:
                self._load_trust(handle, configuration.trust_store)
                self.library.SSL_CTX_set_verify(handle, VerifyMode.PEER | VerifyMode.FAIL_IF_NO_PEER_CERT, None)
            for algorithm in (
                CertificateCompressionAlgorithm.brotli,
                CertificateCompressionAlgorithm.zstd,
                CertificateCompressionAlgorithm.zlib,
            ):
                self._compression.register(handle, algorithm, client=False)
        if len(self._handles) > 1:
            callback = Callback.SERVER_NAME(self._choose_chain)
            self._callbacks.append(callback)
            self.library.check(
                self.library.SSL_CTX_set_tlsext_servername_callback(self._handles[0], callback),
                "SSL_CTX_set_tlsext_servername_callback",
            )
        self.logger.debug("context.created chains=%d", len(self._handles))

    def __del__(self) -> None:
        for handle in self._handles:
            self.library.SSL_CTX_free(handle)
        for leaf in self._leaves:
            self.library.X509_free(leaf)

    @property
    def configuration(self) -> TLSServerConfiguration:
        return self._configuration

    def connect(self, address: tuple[str | None, int]) -> TLSSocket:
        return TLSSocket.bind(self, address)

    def create_buffer(self) -> TLSBuffer:
        return TLSBuffer(self, self.library, self._handles[0], server=True)

    def _select_protocol(
        self, _ssl: int, out: int, out_length: int, peer: int, peer_length: int, _argument: None
    ) -> int:
        status = self.library.SSL_select_next_proto(out, out_length, peer, peer_length, self._alpn, len(self._alpn))
        return int(
            ExtensionCallbackResult.OK if status == ProtocolSelection.NEGOTIATED else ExtensionCallbackResult.NOACK
        )

    def _choose_chain(self, ssl: int, _out_alert: int, _argument: None) -> int:
        # the chain whose leaf names the requested server; the first chain otherwise
        library = self.library
        name = library.SSL_get_servername(ssl, ServerNameType.host_name)
        if name is not None:
            for handle, leaf in zip(self._handles, self._leaves, strict=True):
                if library.X509_check_host(leaf, name, len(name), 0, None) == 1:
                    if library.SSL_set_SSL_CTX(ssl, handle) is None:
                        return int(ExtensionCallbackResult.ALERT_FATAL)
                    break
        return int(ExtensionCallbackResult.OK)


class BoringSSL:
    @staticmethod
    def implementation() -> TLSImplementation[ClientContext, ServerContext]:
        return TLSImplementation(ClientContext, ServerContext, Context.validate)
