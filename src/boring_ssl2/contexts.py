import ctypes
import ipaddress
from collections.abc import Callable, Iterable
from ctypes import c_size_t, c_void_p
from enum import IntEnum, IntFlag
from pathlib import Path
from typing import Final, final

from ssl2.credentials import (
    Certificate,
    Credential,
    PrivateKey,
    SigningChain,
    TrustStore,
)
from ssl2.errors import ConfigurationError
from ssl2.interface import (
    SessionCache,
    TLSClientConfiguration,
    TLSImplementation,
    TLSServerConfiguration,
    TLSSocket,
)
from ssl2.parameters import (
    CertificateCompressionAlgorithm,
    ExtensionType,
    NextProtocol,
    ProtocolVersion,
    ServerNameType,
    TLSVersion,
)
from ssl2.proxy import Proxy

from boring_ssl2.buffer import TLSBuffer
from boring_ssl2.client_hello import CipherList, ClientHelloProfile
from boring_ssl2.compression import CertificateCompression
from boring_ssl2.library import (
    LIBRARY,
    NewSessionFunction,
    ProtocolSelectFunction,
    ServerNameFunction,
)

PEM_PREAMBLE: Final = b"-----BEGIN"
SESSION_CACHE_CLIENT: Final = 0x01
NEXT_PROTOCOL_NEGOTIATED: Final = 1


class VerifyMode(IntFlag):
    NONE = 0x00
    PEER = 0x01
    FAIL_IF_NO_PEER_CERT = 0x02


class ExtensionCallbackResult(IntEnum):
    OK = 0
    ALERT_FATAL = 2
    NOACK = 3


class Context:
    def __init__(self) -> None:
        self._callbacks: list[object] = []
        self._compression: CertificateCompression = CertificateCompression()

    @staticmethod
    def validate(
        configuration: TLSClientConfiguration | TLSServerConfiguration,
    ) -> None:
        match configuration:
            case TLSClientConfiguration():
                chains = (
                    ()
                    if configuration.certificate_chain is None
                    else (configuration.certificate_chain,)
                )
                if configuration.client_hello is not None:
                    handle = Context._new()
                    ClientHelloProfile(configuration.client_hello).configure(handle)
                    LIBRARY.SSL_CTX_free(handle)
            case TLSServerConfiguration():
                chains = configuration.certificate_chain or ()
                if not chains:
                    raise ConfigurationError(
                        "a server needs at least one signing chain"
                    )
        credentials: list[Credential | None] = [configuration.trust_store]
        for chain in chains:
            credentials += (*chain.leaf, *(chain.chain or ()))
        for credential in credentials:
            if credential is not None and credential.id is not None:
                raise ConfigurationError(
                    f"BoringSSL cannot load a {type(credential).__name__} by identifier"
                )

    @staticmethod
    def _new() -> int:
        handle = LIBRARY.SSL_CTX_new(LIBRARY.TLS_method())
        if handle is None:
            raise LIBRARY.error("SSL_CTX_new")
        return handle

    @staticmethod
    def _check(accepted: int, operation: str) -> None:
        if accepted != 1:
            raise LIBRARY.error(operation)

    def _set_versions(
        self, handle: int, lowest: TLSVersion | None, highest: TLSVersion | None
    ) -> None:
        minimum = (
            ProtocolVersion.TLS_1_2
            if lowest is None
            else lowest.protocol_version or ProtocolVersion.TLS_1_0
        )
        maximum = (
            ProtocolVersion.TLS_1_3
            if highest is None
            else highest.protocol_version or ProtocolVersion.TLS_1_3
        )
        self._check(
            LIBRARY.SSL_CTX_set_min_proto_version(handle, minimum),
            "SSL_CTX_set_min_proto_version",
        )
        self._check(
            LIBRARY.SSL_CTX_set_max_proto_version(handle, maximum),
            "SSL_CTX_set_max_proto_version",
        )

    @staticmethod
    def _alpn_wire(protocols: Iterable[NextProtocol | bytes]) -> bytes:
        values = (
            protocol.value if isinstance(protocol, NextProtocol) else protocol
            for protocol in protocols
        )
        return ClientHelloProfile.alpn_wire(values)

    def _load_trust(self, handle: int, store: TrustStore) -> None:
        if store.buffer is not None:
            certificates = self._pem_certificates(store.buffer)
            for certificate in certificates:
                self._check(
                    LIBRARY.X509_STORE_add_cert(
                        LIBRARY.SSL_CTX_get_cert_store(handle), certificate
                    ),
                    "X509_STORE_add_cert",
                )
                LIBRARY.X509_free(certificate)
        elif store.path is not None:
            path = Path(store.path)
            bundle, directory = (
                (bytes(path), None) if path.is_file() else (None, bytes(path))
            )
            self._check(
                LIBRARY.SSL_CTX_load_verify_locations(handle, bundle, directory),
                "SSL_CTX_load_verify_locations",
            )
        elif store.id is not None:
            raise ConfigurationError(
                "BoringSSL cannot load a trust store by identifier"
            )
        else:
            self._load_trust(handle, TrustStore.system())

    def _use_chain(self, handle: int, chain: SigningChain) -> int:
        leaf_source, key_source = chain.leaf
        if key_source is None:
            raise ConfigurationError(
                "BoringSSL needs the private key of the leaf certificate"
            )
        leaf = self._certificate(leaf_source)
        self._check(
            LIBRARY.SSL_CTX_use_certificate(handle, leaf), "SSL_CTX_use_certificate"
        )
        key = self._private_key(key_source)
        accepted = LIBRARY.SSL_CTX_use_PrivateKey(handle, key)
        LIBRARY.EVP_PKEY_free(key)
        self._check(accepted, "SSL_CTX_use_PrivateKey")
        for intermediate in chain.chain or ():
            certificate = self._certificate(intermediate)
            accepted = LIBRARY.SSL_CTX_add1_chain_cert(handle, certificate)
            LIBRARY.X509_free(certificate)
            self._check(accepted, "SSL_CTX_add1_chain_cert")
        return leaf

    def _certificate(self, source: Certificate) -> int:
        data = self._bytes(source)
        if data.lstrip().startswith(PEM_PREAMBLE):
            certificates = self._pem_certificates(data)
            for extra in certificates[1:]:
                LIBRARY.X509_free(extra)
            return certificates[0]
        return self._der(data, LIBRARY.d2i_X509, "d2i_X509")

    def _private_key(self, source: PrivateKey) -> int:
        data = self._bytes(source)
        if not data.lstrip().startswith(PEM_PREAMBLE):
            return self._der(data, LIBRARY.d2i_AutoPrivateKey, "d2i_AutoPrivateKey")
        memory = self._memory(data)
        key = LIBRARY.PEM_read_bio_PrivateKey(memory, None, None, None)
        _ = LIBRARY.BIO_free(memory)
        if key is None:
            raise LIBRARY.error("PEM_read_bio_PrivateKey")
        return key

    def _pem_certificates(self, data: bytes) -> list[int]:
        memory = self._memory(data)
        certificates: list[int] = []
        while (
            certificate := LIBRARY.PEM_read_bio_X509(memory, None, None, None)
        ) is not None:
            certificates.append(certificate)
        _ = LIBRARY.BIO_free(memory)
        # the loop ends on BoringSSL's "no start line" error, which is the end of the data, not a failure
        LIBRARY.ERR_clear_error()
        if not certificates:
            raise ConfigurationError("no PEM certificate found")
        return certificates

    @staticmethod
    def _memory(data: bytes) -> int:
        memory = LIBRARY.BIO_new_mem_buf(data, len(data))
        if memory is None:
            raise LIBRARY.error("BIO_new_mem_buf")
        return memory

    @staticmethod
    def _der(
        data: bytes, parse: Callable[[None, object, int], int | None], operation: str
    ) -> int:
        storage = ctypes.create_string_buffer(data, len(data))
        cursor = c_void_p(ctypes.addressof(storage))
        handle = parse(None, ctypes.byref(cursor), len(data))
        if handle is None:
            raise LIBRARY.error(operation)
        return handle

    @staticmethod
    def _bytes(credential: Credential) -> bytes:
        if credential.buffer is not None:
            return credential.buffer
        if credential.path is not None:
            return Path(credential.path).read_bytes()
        if credential.id is not None:
            raise ConfigurationError(
                f"BoringSSL cannot load a {type(credential).__name__} by identifier"
            )
        raise ConfigurationError(
            f"the {type(credential).__name__} has neither a buffer nor a path"
        )


@final
class ClientContext(Context):
    def __init__(
        self,
        configuration: TLSClientConfiguration,
        *,
        session_cache: SessionCache | None = None,
    ) -> None:
        super().__init__()
        self._configuration = configuration
        self._cache = session_cache
        self._handle = self._new()
        hello = configuration.client_hello
        self._profile = None if hello is None else ClientHelloProfile(hello)
        if configuration.verify_certificates:
            LIBRARY.SSL_CTX_set_verify(self._handle, VerifyMode.PEER, None)
            self._load_trust(
                self._handle, configuration.trust_store or TrustStore.system()
            )
        else:
            LIBRARY.SSL_CTX_set_verify(self._handle, VerifyMode.NONE, None)
        if configuration.certificate_chain is not None:
            LIBRARY.X509_free(
                self._use_chain(self._handle, configuration.certificate_chain)
            )
        if hello is None or self._profile is None:
            self._set_versions(
                self._handle,
                configuration.lowest_supported_version,
                configuration.highest_supported_version,
            )
            if configuration.ciphers is not None:
                CipherList(configuration.ciphers).configure(self._handle)
            if configuration.inner_protocols:
                wire = self._alpn_wire(configuration.inner_protocols)
                self._check(
                    LIBRARY.SSL_CTX_set_alpn_protos(self._handle, wire, len(wire)) == 0,
                    "SSL_CTX_set_alpn_protos",
                )
        else:
            self._profile.configure(self._handle)
            for algorithm in hello.certificate_compression_algorithms:
                self._compression.register(self._handle, algorithm, client=True)
        resumption = hello is not None and hello.offers(ExtensionType.pre_shared_key)
        if hello is not None and resumption != (session_cache is not None):
            raise ConfigurationError(
                "pre_shared_key in the ClientHello and a session cache go together"
            )
        if session_cache is not None:
            callback = NewSessionFunction(self._record_session)
            self._callbacks.append(callback)
            _ = LIBRARY.SSL_CTX_set_session_cache_mode(
                self._handle, SESSION_CACHE_CLIENT
            )
            LIBRARY.SSL_CTX_sess_set_new_cb(self._handle, callback)

    def __del__(self) -> None:
        LIBRARY.SSL_CTX_free(self._handle)

    @property
    def configuration(self) -> TLSClientConfiguration:
        return self._configuration

    def connect(
        self,
        address: tuple[str | None, int],
        *,
        proxy: Proxy | None = None,
        timeout: float | None = None,
    ) -> TLSSocket:
        host, port = address
        if host is None:
            raise ValueError("a client connection needs a host")
        return TLSSocket.connect(self, (host, port), proxy=proxy, timeout=timeout)

    def create_buffer(self, server_hostname: str, *, quic: bool = False) -> TLSBuffer:
        if self._profile is not None:
            self._profile.check_transport(quic=quic)
        buffer = TLSBuffer(
            self, self._handle, server=False, session_key=server_hostname
        )
        ssl = buffer.handle
        try:
            _ = ipaddress.ip_address(server_hostname)
        except ValueError:
            name = server_hostname.encode("idna")
            self._check(
                LIBRARY.SSL_set_tlsext_host_name(ssl, name), "SSL_set_tlsext_host_name"
            )
            self._check(LIBRARY.SSL_set1_host(ssl, name), "SSL_set1_host")
        else:
            address = server_hostname.encode("ascii")
            self._check(
                LIBRARY.X509_VERIFY_PARAM_set1_ip_asc(
                    LIBRARY.SSL_get0_param(ssl), address
                ),
                "X509_VERIFY_PARAM_set1_ip_asc",
            )
        if self._profile is not None:
            self._profile.prepare(ssl)
        if (
            self._cache is not None
            and (session := self._cache.take(server_hostname)) is not None
        ):
            self._resume(ssl, session)
        return buffer

    def _resume(self, ssl: int, serialized: bytes) -> None:
        session = LIBRARY.SSL_SESSION_from_bytes(
            serialized, len(serialized), self._handle
        )
        if session is None:
            raise LIBRARY.error("SSL_SESSION_from_bytes")
        accepted = LIBRARY.SSL_set_session(ssl, session)
        LIBRARY.SSL_SESSION_free(session)
        self._check(accepted, "SSL_set_session")

    def _record_session(self, ssl: int, session: int) -> int:
        key = LIBRARY.SSL_get_ex_data(ssl, 0)
        data, length = c_void_p(), c_size_t()
        if (
            key is None
            or self._cache is None
            or LIBRARY.SSL_SESSION_to_bytes(
                session, ctypes.byref(data), ctypes.byref(length)
            )
            != 1
            or data.value is None
        ):
            return 0
        serialized = ctypes.string_at(data.value, length.value)
        LIBRARY.OPENSSL_free(data.value)
        single_use = LIBRARY.SSL_SESSION_should_be_single_use(session) == 1
        self._cache.store(
            ctypes.string_at(key).decode(), serialized, single_use=single_use
        )
        return 0


@final
class ServerContext(Context):
    def __init__(self, configuration: TLSServerConfiguration) -> None:
        super().__init__()
        if not configuration.certificate_chain:
            raise ConfigurationError("a server needs at least one signing chain")
        self._configuration = configuration
        self._alpn = self._alpn_wire(configuration.inner_protocols or ())
        self._handles: list[int] = []
        self._leaves: list[int] = []
        for chain in configuration.certificate_chain:
            handle = self._new()
            self._handles.append(handle)
            self._leaves.append(self._use_chain(handle, chain))
            self._set_versions(
                handle,
                configuration.lowest_supported_version,
                configuration.highest_supported_version,
            )
            if configuration.ciphers is not None:
                CipherList(configuration.ciphers).configure(handle)
            if self._alpn:
                callback = ProtocolSelectFunction(self._select_protocol)
                self._callbacks.append(callback)
                LIBRARY.SSL_CTX_set_alpn_select_cb(handle, callback, None)
            if configuration.trust_store is not None:
                self._load_trust(handle, configuration.trust_store)
                LIBRARY.SSL_CTX_set_verify(
                    handle, VerifyMode.PEER | VerifyMode.FAIL_IF_NO_PEER_CERT, None
                )
            for algorithm in (
                CertificateCompressionAlgorithm.brotli,
                CertificateCompressionAlgorithm.zstd,
                CertificateCompressionAlgorithm.zlib,
            ):
                self._compression.register(handle, algorithm, client=False)
        if len(self._handles) > 1:
            callback = ServerNameFunction(self._choose_chain)
            self._callbacks.append(callback)
            self._check(
                LIBRARY.SSL_CTX_set_tlsext_servername_callback(
                    self._handles[0], callback
                ),
                "SSL_CTX_set_tlsext_servername_callback",
            )

    def __del__(self) -> None:
        for handle in self._handles:
            LIBRARY.SSL_CTX_free(handle)
        for leaf in self._leaves:
            LIBRARY.X509_free(leaf)

    @property
    def configuration(self) -> TLSServerConfiguration:
        return self._configuration

    def connect(self, address: tuple[str | None, int]) -> TLSSocket:
        return TLSSocket.bind(self, address)

    def create_buffer(self) -> TLSBuffer:
        return TLSBuffer(self, self._handles[0], server=True)

    def _select_protocol(
        self,
        _ssl: int,
        out: int,
        out_length: int,
        peer: int,
        peer_length: int,
        _argument: None,
    ) -> int:
        status = LIBRARY.SSL_select_next_proto(
            out, out_length, peer, peer_length, self._alpn, len(self._alpn)
        )
        return int(
            ExtensionCallbackResult.OK
            if status == NEXT_PROTOCOL_NEGOTIATED
            else ExtensionCallbackResult.NOACK
        )

    def _choose_chain(self, ssl: int, _out_alert: int, _argument: None) -> int:
        name = LIBRARY.SSL_get_servername(ssl, ServerNameType.host_name)
        if name is not None:
            for handle, leaf in zip(self._handles, self._leaves, strict=True):
                if LIBRARY.X509_check_host(leaf, name, len(name), 0, None) == 1:
                    if LIBRARY.SSL_set_SSL_CTX(ssl, handle) is None:
                        return int(ExtensionCallbackResult.ALERT_FATAL)
                    break
        return int(ExtensionCallbackResult.OK)


IMPLEMENTATION: Final = TLSImplementation(
    ClientContext, ServerContext, Context.validate
)
