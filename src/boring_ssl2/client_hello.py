from collections.abc import Iterable, Sequence
from ctypes import Array, c_uint16
from typing import Final, final

from ssl2.client_hello import ClientHello
from ssl2.errors import ConfigurationError
from ssl2.parameters import (
    CipherSuite,
    ECPointFormat,
    ExtensionType,
    NamedGroup,
    ProtocolVersion,
    PskKeyExchangeMode,
)

from boring_ssl2.library import LIBRARY

SSL_OP_NO_TICKET: Final = 0x4000
CLIENT_VERSIONS: Final = (
    ProtocolVersion.TLS_1_0,
    ProtocolVersion.TLS_1_1,
    ProtocolVersion.TLS_1_2,
    ProtocolVersion.TLS_1_3,
)
TLS13_CIPHER_SUITES: Final = frozenset(
    {
        CipherSuite.TLS_AES_128_GCM_SHA256,
        CipherSuite.TLS_AES_256_GCM_SHA384,
        CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_AES_128_CCM_SHA256,
        CipherSuite.TLS_AES_128_CCM_8_SHA256,
    }
)
POST_QUANTUM_GROUPS: Final = frozenset(
    {NamedGroup.X25519MLKEM768, NamedGroup.MLKEM1024}
)
TOGGLED_EXTENSIONS: Final = frozenset(
    {
        ExtensionType.status_request,
        ExtensionType.signed_certificate_timestamp,
        ExtensionType.session_ticket,
        ExtensionType.application_layer_protocol_negotiation,
        ExtensionType.application_settings,
        ExtensionType.application_settings_old,
        ExtensionType.compress_certificate,
        ExtensionType.encrypted_client_hello,
    }
)
FREE_EXTENSIONS: Final = frozenset(
    {ExtensionType.server_name, ExtensionType.padding, ExtensionType.pre_shared_key}
)
QUIC_EXTENSIONS: Final = frozenset({ExtensionType.quic_transport_parameters})
TRAILING_EXTENSIONS: Final = (ExtensionType.padding, ExtensionType.pre_shared_key)
EMPTY_BODY_EXTENSIONS: Final = frozenset(
    {
        ExtensionType.extended_main_secret,
        ExtensionType.session_ticket,
        ExtensionType.signed_certificate_timestamp,
    }
)
LEGACY_EXTENSIONS: Final = (
    ExtensionType.extended_main_secret,
    ExtensionType.renegotiation_info,
    ExtensionType.ec_point_formats,
)
MODERN_EXTENSIONS: Final = (
    ExtensionType.key_share,
    ExtensionType.psk_key_exchange_modes,
    ExtensionType.supported_versions,
)
UNSENDABLE_REASONS: Final = {
    ExtensionType.delegated_credential: "BoringSSL does not offer delegated credentials",
    ExtensionType.record_size_limit: "BoringSSL does not send record_size_limit",
    ExtensionType.early_data: "BoringSSL sends early_data only with a resumed session that allows 0-RTT",
    ExtensionType.trust_anchors: "BoringSSL sends trust_anchors only with requested trust anchor identifiers, which the model does not carry",
    ExtensionType.server_padding: "BoringSSL sends server_padding only with a requested size, which the model does not carry",
}


@final
class CipherList:
    def __init__(self, suites: Sequence[CipherSuite]) -> None:
        self.modern = tuple(suite for suite in suites if suite in TLS13_CIPHER_SUITES)
        self.legacy = tuple(
            suite for suite in suites if suite not in TLS13_CIPHER_SUITES
        )

    def configure(self, handle: int) -> None:
        if self.modern:
            identifiers = (c_uint16 * len(self.modern))(*self.modern)
            if (
                LIBRARY.SSL_CTX_set1_tls13_ciphers(
                    handle, identifiers, None, len(identifiers)
                )
                != 1
            ):
                raise ConfigurationError(
                    f"BoringSSL rejected the TLS 1.3 cipher suites: {'; '.join(LIBRARY.errors())}"
                )
        if self.legacy:
            names: list[bytes] = []
            for suite in self.legacy:
                cipher = LIBRARY.SSL_get_cipher_by_value(suite)
                if cipher is None:
                    raise ConfigurationError(
                        f"BoringSSL does not implement {suite.name}"
                    )
                names.append(LIBRARY.SSL_CIPHER_standard_name(cipher))
            if LIBRARY.SSL_CTX_set_strict_cipher_list(handle, b":".join(names)) != 1:
                raise ConfigurationError(
                    f"BoringSSL rejected the cipher list: {'; '.join(LIBRARY.errors())}"
                )


@final
class ClientHelloProfile:
    def __init__(self, hello: ClientHello) -> None:
        self._hello = hello
        self._minimum = hello.lowest_version
        self._maximum = hello.highest_version
        self._check_versions()
        self._check_ciphers()
        self._check_extensions()
        self._check_trailing()
        self._check_payloads()
        # padding and pre_shared_key are not in BoringSSL's extension table; it always places them last
        self._order = tuple(
            extension
            for extension in hello.extensions
            if extension not in TRAILING_EXTENSIONS
        )

    def configure(self, handle: int) -> None:
        hello = self._hello
        self._apply(
            LIBRARY.SSL_CTX_set_min_proto_version(handle, self._minimum),
            "minimum version",
        )
        self._apply(
            LIBRARY.SSL_CTX_set_max_proto_version(handle, self._maximum),
            "maximum version",
        )
        LIBRARY.SSL_CTX_set_grease_enabled(handle, int(hello.grease))
        LIBRARY.SSL_CTX_set_permute_extensions(handle, int(hello.permute_extensions))
        if not hello.permute_extensions:
            order = self.array(self._order)
            self._apply(
                LIBRARY.SSL_CTX_set1_extension_order(handle, order, len(order)),
                "extension order",
            )
        CipherList(hello.cipher_suites).configure(handle)
        for group in hello.supported_groups:
            if LIBRARY.SSL_CTX_set1_group_ids(handle, self.array((group,)), 1) != 1:
                LIBRARY.ERR_clear_error()
                raise ConfigurationError(
                    f"BoringSSL does not support the group {group.name}"
                )
        groups = self.array(hello.supported_groups)
        self._apply(
            LIBRARY.SSL_CTX_set1_group_ids(handle, groups, len(groups)),
            "supported groups",
        )
        for scheme in hello.signature_algorithms:
            if (
                LIBRARY.SSL_CTX_set_verify_algorithm_prefs(
                    handle, self.array((scheme,)), 1
                )
                != 1
            ):
                LIBRARY.ERR_clear_error()
                raise ConfigurationError(
                    f"BoringSSL does not support the signature scheme {scheme.name}"
                )
        if hello.signature_algorithms:
            schemes = self.array(hello.signature_algorithms)
            self._apply(
                LIBRARY.SSL_CTX_set_verify_algorithm_prefs(
                    handle, schemes, len(schemes)
                ),
                "signature algorithms",
            )
        if hello.application_protocols:
            wire = self.alpn_wire(hello.application_protocols)
            self._apply(
                LIBRARY.SSL_CTX_set_alpn_protos(handle, wire, len(wire)) == 0,
                "application protocols",
            )
        if hello.offers(ExtensionType.status_request):
            LIBRARY.SSL_CTX_enable_ocsp_stapling(handle)
        if hello.offers(ExtensionType.signed_certificate_timestamp):
            LIBRARY.SSL_CTX_enable_signed_cert_timestamps(handle)
        if not hello.offers(ExtensionType.session_ticket):
            _ = LIBRARY.SSL_CTX_set_options(handle, SSL_OP_NO_TICKET)

    def prepare(self, ssl: int) -> None:
        hello = self._hello
        if hello.key_share_groups:
            shares = self.array(hello.key_share_groups)
            self._apply(
                LIBRARY.SSL_set1_client_key_shares(ssl, shares, len(shares)),
                "key shares",
            )
        for protocol in hello.application_settings:
            self._apply(
                LIBRARY.SSL_add_application_settings(
                    ssl, protocol, len(protocol), None, 0
                ),
                "application settings",
            )
        if hello.application_settings:
            LIBRARY.SSL_set_alps_use_new_codepoint(
                ssl, int(hello.offers(ExtensionType.application_settings))
            )
        if hello.offers(ExtensionType.encrypted_client_hello):
            LIBRARY.SSL_set_enable_ech_grease(ssl, 1)

    def check_transport(self, *, quic: bool) -> None:
        listed = self._hello.offers(ExtensionType.quic_transport_parameters)
        if quic and not listed:
            raise ConfigurationError(
                "BoringSSL always sends quic_transport_parameters over QUIC; list it in the model"
            )
        if listed and not quic:
            raise ConfigurationError(
                "BoringSSL sends quic_transport_parameters only over QUIC"
            )
        if quic and self._minimum < ProtocolVersion.TLS_1_3:
            raise ConfigurationError(
                f"QUIC offers TLS 1.3 only; the model offers {self._minimum.name}"
            )

    @staticmethod
    def array(values: Iterable[int]) -> Array[c_uint16]:
        items = tuple(values)
        return (c_uint16 * len(items))(*items)

    @staticmethod
    def alpn_wire(protocols: Iterable[bytes]) -> bytes:
        return b"".join(bytes((len(protocol),)) + protocol for protocol in protocols)

    def _check_versions(self) -> None:
        offered = self._hello.supported_versions
        foreign = [
            version.name for version in offered if version not in CLIENT_VERSIONS
        ]
        if foreign:
            raise ConfigurationError(
                f"BoringSSL clients cannot offer {', '.join(foreign)}"
            )
        positions = sorted(CLIENT_VERSIONS.index(version) for version in offered)
        if positions != list(range(positions[0], positions[-1] + 1)):
            raise ConfigurationError("BoringSSL offers a contiguous range of versions")
        if offered != tuple(sorted(offered, reverse=True)):
            raise ConfigurationError(
                "BoringSSL offers versions from the highest to the lowest"
            )

    def _check_ciphers(self) -> None:
        suites = self._hello.cipher_suites
        ciphers = CipherList(suites)
        if suites[: len(ciphers.modern)] != ciphers.modern:
            raise ConfigurationError(
                "BoringSSL lists the TLS 1.3 cipher suites before the others"
            )
        if bool(ciphers.modern) != (self._maximum >= ProtocolVersion.TLS_1_3):
            raise ConfigurationError(
                "TLS 1.3 cipher suites are offered exactly when TLS 1.3 is offered"
            )
        if bool(ciphers.legacy) != (self._minimum < ProtocolVersion.TLS_1_3):
            raise ConfigurationError(
                "older cipher suites are offered exactly when a version below TLS 1.3 is offered"
            )

    def _check_extensions(self) -> None:
        hello = self._hello
        expected = {ExtensionType.supported_groups}
        if self._minimum < ProtocolVersion.TLS_1_3:
            expected.update(LEGACY_EXTENSIONS)
        if self._maximum >= ProtocolVersion.TLS_1_2:
            expected.add(ExtensionType.signature_algorithms)
        if self._maximum >= ProtocolVersion.TLS_1_3:
            expected.update(MODERN_EXTENSIONS)
        requested = set(hello.extensions)
        if (
            ExtensionType.session_ticket in requested
            and self._minimum >= ProtocolVersion.TLS_1_3
        ):
            raise ConfigurationError(
                "session_ticket is sent only when a version below TLS 1.3 is offered"
            )
        if hello.application_settings and (
            not hello.application_protocols or self._maximum < ProtocolVersion.TLS_1_3
        ):
            raise ConfigurationError(
                "application_settings is sent only with ALPN and TLS 1.3 offered"
            )
        if (
            hello.offers(ExtensionType.encrypted_client_hello)
            and self._maximum < ProtocolVersion.TLS_1_3
        ):
            raise ConfigurationError(
                "encrypted_client_hello is sent only when TLS 1.3 is offered"
            )
        unsendable = (
            requested
            - expected
            - TOGGLED_EXTENSIONS
            - FREE_EXTENSIONS
            - QUIC_EXTENSIONS
        )
        if unsendable:
            reasons = (
                UNSENDABLE_REASONS.get(
                    extension,
                    f"BoringSSL cannot send {extension.name} in a ClientHello",
                )
                for extension in sorted(unsendable)
            )
            raise ConfigurationError("; ".join(reasons))
        missing = expected - requested
        if missing:
            raise ConfigurationError(
                f"BoringSSL always sends {', '.join(sorted(extension.name for extension in missing))} with the offered versions"
            )
        post_quantum = [
            group.name
            for group in hello.supported_groups
            if group in POST_QUANTUM_GROUPS
        ]
        if post_quantum and self._maximum < ProtocolVersion.TLS_1_3:
            raise ConfigurationError(
                f"BoringSSL sends {', '.join(post_quantum)} only when TLS 1.3 is offered"
            )

    def _check_trailing(self) -> None:
        hello = self._hello
        trailing = tuple(
            extension for extension in TRAILING_EXTENSIONS if hello.offers(extension)
        )
        if hello.extensions[len(hello.extensions) - len(trailing) :] != trailing:
            raise ConfigurationError(
                "BoringSSL sends padding and then pre_shared_key after every other extension"
            )
        wanted = hello.offers(ExtensionType.padding)
        if wanted and hello.permute_extensions:
            raise ConfigurationError(
                "padding placement is unpredictable while extensions are permuted"
            )
        preceding = [
            extension
            for extension in hello.extensions
            if extension not in TRAILING_EXTENSIONS
        ]
        predicted = (
            not hello.grease
            and bool(preceding)
            and preceding[-1] in EMPTY_BODY_EXTENSIONS
        )
        if predicted and not wanted and not hello.permute_extensions:
            raise ConfigurationError(
                f"BoringSSL pads after an empty {preceding[-1].name}; list padding last or reorder"
            )
        if wanted and not predicted:
            raise ConfigurationError(
                "BoringSSL pads only without GREASE and after an extension with an empty body"
            )

    def _check_payloads(self) -> None:
        hello = self._hello
        if self._minimum < ProtocolVersion.TLS_1_3 and hello.ec_point_formats != (
            ECPointFormat.uncompressed,
        ):
            raise ConfigurationError(
                "BoringSSL sends ec_point_formats with only the uncompressed format"
            )
        if (
            self._maximum >= ProtocolVersion.TLS_1_3
            and hello.psk_key_exchange_modes != (PskKeyExchangeMode.psk_dhe_ke,)
        ):
            raise ConfigurationError(
                "BoringSSL sends psk_key_exchange_modes with only psk_dhe_ke"
            )

    @staticmethod
    def _apply(accepted: int | bool, what: str) -> None:
        if accepted != 1:
            raise ConfigurationError(
                f"BoringSSL rejected the {what}: {'; '.join(LIBRARY.errors())}"
            )
