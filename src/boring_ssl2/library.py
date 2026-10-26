import ctypes
import sys
from collections.abc import Callable
from ctypes import (
    CFUNCTYPE,
    Array,
    c_char,
    c_char_p,
    c_int,
    c_long,
    c_size_t,
    c_ssize_t,
    c_uint,
    c_uint16,
    c_uint32,
    c_void_p,
)
from pathlib import Path
from typing import Final, final

from ssl2.errors import TLSError

FILE_NAMES: Final = {
    "linux": "libboring_ssl2.so",
    "darwin": "libboring_ssl2.dylib",
    "win32": "boring_ssl2.dll",
}

type Foreign = type[
    c_char_p
    | c_int
    | c_long
    | c_size_t
    | c_ssize_t
    | c_uint
    | c_uint16
    | c_uint32
    | c_void_p
]

CertificateCompressFunction = CFUNCTYPE(c_int, c_void_p, c_void_p, c_void_p, c_size_t)
CertificateDecompressFunction = CFUNCTYPE(
    c_int, c_void_p, c_void_p, c_size_t, c_void_p, c_size_t
)
ProtocolSelectFunction = CFUNCTYPE(
    c_int, c_void_p, c_void_p, c_void_p, c_void_p, c_uint, c_void_p
)
ServerNameFunction = CFUNCTYPE(c_int, c_void_p, c_void_p, c_void_p)
NewSessionFunction = CFUNCTYPE(c_int, c_void_p, c_void_p)


class BoringSSLError(TLSError):
    def __init__(self, operation: str, reasons: tuple[str, ...]) -> None:
        super().__init__(
            f"{operation}: {'; '.join(reasons) or 'BoringSSL reported no reason'}"
        )
        self.operation: str = operation
        self.reasons: tuple[str, ...] = reasons


@final
class CertificateVerificationError(BoringSSLError):
    def __init__(self, operation: str, reasons: tuple[str, ...], verdict: str) -> None:
        super().__init__(operation, (*reasons, verdict))
        self.verdict = verdict


class Library:
    def __init__(self, path: Path) -> None:
        handle = ctypes.CDLL(str(path))

        def bind(name: str, result: Foreign | None, *arguments: Foreign):
            function = handle[name]
            function.restype = result
            function.argtypes = arguments
            return function

        self.boring_ssl_source_revision: Callable[[], bytes] = bind(
            "boring_ssl_source_revision", c_char_p
        )
        self.TLS_method: Callable[[], int] = bind("TLS_method", c_void_p)
        self.SSL_CTX_new: Callable[[int], int | None] = bind(
            "SSL_CTX_new", c_void_p, c_void_p
        )
        self.SSL_CTX_free: Callable[[int], None] = bind("SSL_CTX_free", None, c_void_p)
        self.SSL_CTX_set_min_proto_version: Callable[[int, int], int] = bind(
            "SSL_CTX_set_min_proto_version", c_int, c_void_p, c_uint16
        )
        self.SSL_CTX_set_max_proto_version: Callable[[int, int], int] = bind(
            "SSL_CTX_set_max_proto_version", c_int, c_void_p, c_uint16
        )
        self.SSL_CTX_set_strict_cipher_list: Callable[[int, bytes], int] = bind(
            "SSL_CTX_set_strict_cipher_list", c_int, c_void_p, c_char_p
        )
        self.SSL_CTX_set1_tls13_ciphers: Callable[
            [int, Array[c_uint16], None, int], int
        ] = bind(
            "SSL_CTX_set1_tls13_ciphers", c_int, c_void_p, c_void_p, c_void_p, c_size_t
        )
        self.SSL_CTX_set1_group_ids: Callable[[int, Array[c_uint16], int], int] = bind(
            "SSL_CTX_set1_group_ids", c_int, c_void_p, c_void_p, c_size_t
        )
        self.SSL_CTX_set_verify_algorithm_prefs: Callable[
            [int, Array[c_uint16], int], int
        ] = bind(
            "SSL_CTX_set_verify_algorithm_prefs", c_int, c_void_p, c_void_p, c_size_t
        )
        self.SSL_CTX_set1_extension_order: Callable[
            [int, Array[c_uint16], int], int
        ] = bind("SSL_CTX_set1_extension_order", c_int, c_void_p, c_void_p, c_size_t)
        self.SSL_CTX_set_alpn_protos: Callable[[int, bytes, int], int] = bind(
            "SSL_CTX_set_alpn_protos", c_int, c_void_p, c_char_p, c_size_t
        )
        self.SSL_CTX_set_options: Callable[[int, int], int] = bind(
            "SSL_CTX_set_options", c_uint32, c_void_p, c_uint32
        )
        self.SSL_CTX_set_grease_enabled: Callable[[int, int], None] = bind(
            "SSL_CTX_set_grease_enabled", None, c_void_p, c_int
        )
        self.SSL_CTX_set_permute_extensions: Callable[[int, int], None] = bind(
            "SSL_CTX_set_permute_extensions", None, c_void_p, c_int
        )
        self.SSL_CTX_enable_ocsp_stapling: Callable[[int], None] = bind(
            "SSL_CTX_enable_ocsp_stapling", None, c_void_p
        )
        self.SSL_CTX_enable_signed_cert_timestamps: Callable[[int], None] = bind(
            "SSL_CTX_enable_signed_cert_timestamps", None, c_void_p
        )
        self.SSL_CTX_set_verify: Callable[[int, int, None], None] = bind(
            "SSL_CTX_set_verify", None, c_void_p, c_int, c_void_p
        )
        self.SSL_CTX_load_verify_locations: Callable[
            [int, bytes | None, bytes | None], int
        ] = bind("SSL_CTX_load_verify_locations", c_int, c_void_p, c_char_p, c_char_p)
        self.SSL_CTX_get_cert_store: Callable[[int], int] = bind(
            "SSL_CTX_get_cert_store", c_void_p, c_void_p
        )
        self.X509_STORE_add_cert: Callable[[int, int], int] = bind(
            "X509_STORE_add_cert", c_int, c_void_p, c_void_p
        )
        self.SSL_CTX_use_certificate: Callable[[int, int], int] = bind(
            "SSL_CTX_use_certificate", c_int, c_void_p, c_void_p
        )
        self.SSL_CTX_use_PrivateKey: Callable[[int, int], int] = bind(
            "SSL_CTX_use_PrivateKey", c_int, c_void_p, c_void_p
        )
        self.SSL_CTX_add1_chain_cert: Callable[[int, int], int] = bind(
            "SSL_CTX_add1_chain_cert", c_int, c_void_p, c_void_p
        )
        self.SSL_CTX_add_cert_compression_alg: Callable[
            [int, int, Callable[..., int] | None, Callable[..., int] | None], int
        ] = bind(
            "SSL_CTX_add_cert_compression_alg",
            c_int,
            c_void_p,
            c_uint16,
            c_void_p,
            c_void_p,
        )
        self.SSL_CTX_set_alpn_select_cb: Callable[
            [int, Callable[..., int], None], None
        ] = bind("SSL_CTX_set_alpn_select_cb", None, c_void_p, c_void_p, c_void_p)
        self.SSL_CTX_set_tlsext_servername_callback: Callable[
            [int, Callable[..., int]], int
        ] = bind("SSL_CTX_set_tlsext_servername_callback", c_int, c_void_p, c_void_p)
        self.SSL_CTX_set_session_cache_mode: Callable[[int, int], int] = bind(
            "SSL_CTX_set_session_cache_mode", c_int, c_void_p, c_int
        )
        self.SSL_CTX_sess_set_new_cb: Callable[[int, Callable[..., int]], None] = bind(
            "SSL_CTX_sess_set_new_cb", None, c_void_p, c_void_p
        )
        self.SSL_SESSION_to_bytes: Callable[[int, object, object], int] = bind(
            "SSL_SESSION_to_bytes", c_int, c_void_p, c_void_p, c_void_p
        )
        self.SSL_SESSION_from_bytes: Callable[[bytes, int, int], int | None] = bind(
            "SSL_SESSION_from_bytes", c_void_p, c_char_p, c_size_t, c_void_p
        )
        self.SSL_SESSION_should_be_single_use: Callable[[int], int] = bind(
            "SSL_SESSION_should_be_single_use", c_int, c_void_p
        )
        self.SSL_SESSION_free: Callable[[int], None] = bind(
            "SSL_SESSION_free", None, c_void_p
        )
        self.SSL_set_session: Callable[[int, int], int] = bind(
            "SSL_set_session", c_int, c_void_p, c_void_p
        )
        self.SSL_session_reused: Callable[[int], int] = bind(
            "SSL_session_reused", c_int, c_void_p
        )
        self.SSL_get_session: Callable[[int], int | None] = bind(
            "SSL_get_session", c_void_p, c_void_p
        )
        self.SSL_SESSION_early_data_capable: Callable[[int], int] = bind(
            "SSL_SESSION_early_data_capable", c_int, c_void_p
        )
        self.SSL_set_early_data_enabled: Callable[[int, int], None] = bind(
            "SSL_set_early_data_enabled", None, c_void_p, c_int
        )
        self.SSL_in_early_data: Callable[[int], int] = bind(
            "SSL_in_early_data", c_int, c_void_p
        )
        self.SSL_early_data_accepted: Callable[[int], int] = bind(
            "SSL_early_data_accepted", c_int, c_void_p
        )
        self.SSL_reset_early_data_reject: Callable[[int], None] = bind(
            "SSL_reset_early_data_reject", None, c_void_p
        )
        self.OPENSSL_free: Callable[[int], None] = bind("OPENSSL_free", None, c_void_p)
        self.SSL_new: Callable[[int], int | None] = bind("SSL_new", c_void_p, c_void_p)
        self.SSL_free: Callable[[int], None] = bind("SSL_free", None, c_void_p)
        self.SSL_set_connect_state: Callable[[int], None] = bind(
            "SSL_set_connect_state", None, c_void_p
        )
        self.SSL_set_accept_state: Callable[[int], None] = bind(
            "SSL_set_accept_state", None, c_void_p
        )
        self.SSL_set_bio: Callable[[int, int, int], None] = bind(
            "SSL_set_bio", None, c_void_p, c_void_p, c_void_p
        )
        self.SSL_set_tlsext_host_name: Callable[[int, bytes], int] = bind(
            "SSL_set_tlsext_host_name", c_int, c_void_p, c_char_p
        )
        self.SSL_set1_host: Callable[[int, bytes], int] = bind(
            "SSL_set1_host", c_int, c_void_p, c_char_p
        )
        self.SSL_get0_param: Callable[[int], int] = bind(
            "SSL_get0_param", c_void_p, c_void_p
        )
        self.X509_VERIFY_PARAM_set1_ip_asc: Callable[[int, bytes], int] = bind(
            "X509_VERIFY_PARAM_set1_ip_asc", c_int, c_void_p, c_char_p
        )
        self.SSL_set_ex_data: Callable[[int, int, int], int] = bind(
            "SSL_set_ex_data", c_int, c_void_p, c_int, c_void_p
        )
        self.SSL_get_ex_data: Callable[[int, int], int | None] = bind(
            "SSL_get_ex_data", c_void_p, c_void_p, c_int
        )
        self.SSL_add_application_settings: Callable[
            [int, bytes, int, None, int], int
        ] = bind(
            "SSL_add_application_settings",
            c_int,
            c_void_p,
            c_char_p,
            c_size_t,
            c_char_p,
            c_size_t,
        )
        self.SSL_set_alps_use_new_codepoint: Callable[[int, int], None] = bind(
            "SSL_set_alps_use_new_codepoint", None, c_void_p, c_int
        )
        self.SSL_set1_requested_trust_anchors: Callable[[int, bytes, int], int] = bind(
            "SSL_set1_requested_trust_anchors", c_int, c_void_p, c_char_p, c_size_t
        )
        self.SSL_set_enable_ech_grease: Callable[[int, int], None] = bind(
            "SSL_set_enable_ech_grease", None, c_void_p, c_int
        )
        self.SSL_set1_client_key_shares: Callable[[int, Array[c_uint16], int], int] = (
            bind("SSL_set1_client_key_shares", c_int, c_void_p, c_void_p, c_size_t)
        )
        self.SSL_do_handshake: Callable[[int], int] = bind(
            "SSL_do_handshake", c_int, c_void_p
        )
        self.SSL_is_init_finished: Callable[[int], int] = bind(
            "SSL_is_init_finished", c_int, c_void_p
        )
        self.SSL_read: Callable[[int, Array[c_char], int], int] = bind(
            "SSL_read", c_int, c_void_p, c_void_p, c_int
        )
        self.SSL_write: Callable[[int, bytes, int], int] = bind(
            "SSL_write", c_int, c_void_p, c_void_p, c_int
        )
        self.SSL_shutdown: Callable[[int], int] = bind("SSL_shutdown", c_int, c_void_p)
        self.SSL_get_error: Callable[[int, int], int] = bind(
            "SSL_get_error", c_int, c_void_p, c_int
        )
        self.SSL_get_verify_result: Callable[[int], int] = bind(
            "SSL_get_verify_result", c_long, c_void_p
        )
        self.SSL_version: Callable[[int], int] = bind("SSL_version", c_int, c_void_p)
        self.SSL_get_current_cipher: Callable[[int], int | None] = bind(
            "SSL_get_current_cipher", c_void_p, c_void_p
        )
        self.SSL_CIPHER_get_protocol_id: Callable[[int], int] = bind(
            "SSL_CIPHER_get_protocol_id", c_uint16, c_void_p
        )
        self.SSL_CIPHER_standard_name: Callable[[int], bytes] = bind(
            "SSL_CIPHER_standard_name", c_char_p, c_void_p
        )
        self.SSL_get_cipher_by_value: Callable[[int], int | None] = bind(
            "SSL_get_cipher_by_value", c_void_p, c_uint16
        )
        self.SSL_get0_alpn_selected: Callable[[int, object, object], None] = bind(
            "SSL_get0_alpn_selected", None, c_void_p, c_void_p, c_void_p
        )
        self.SSL_get0_peer_certificates: Callable[[int], int | None] = bind(
            "SSL_get0_peer_certificates", c_void_p, c_void_p
        )
        self.SSL_get_servername: Callable[[int, int], bytes | None] = bind(
            "SSL_get_servername", c_char_p, c_void_p, c_int
        )
        self.SSL_set_SSL_CTX: Callable[[int, int], int | None] = bind(
            "SSL_set_SSL_CTX", c_void_p, c_void_p, c_void_p
        )
        self.SSL_select_next_proto: Callable[[int, int, int, int, bytes, int], int] = (
            bind(
                "SSL_select_next_proto",
                c_int,
                c_void_p,
                c_void_p,
                c_void_p,
                c_uint,
                c_char_p,
                c_uint,
            )
        )
        self.BIO_s_mem: Callable[[], int] = bind("BIO_s_mem", c_void_p)
        self.BIO_new: Callable[[int], int | None] = bind("BIO_new", c_void_p, c_void_p)
        self.BIO_new_mem_buf: Callable[[bytes, int], int | None] = bind(
            "BIO_new_mem_buf", c_void_p, c_void_p, c_ssize_t
        )
        self.BIO_free: Callable[[int], int] = bind("BIO_free", c_int, c_void_p)
        self.BIO_read: Callable[[int, Array[c_char], int], int] = bind(
            "BIO_read", c_int, c_void_p, c_void_p, c_int
        )
        self.BIO_write: Callable[[int, bytes, int], int] = bind(
            "BIO_write", c_int, c_void_p, c_void_p, c_int
        )
        self.BIO_ctrl_pending: Callable[[int], int] = bind(
            "BIO_ctrl_pending", c_size_t, c_void_p
        )
        self.OPENSSL_sk_num: Callable[[int], int] = bind(
            "OPENSSL_sk_num", c_size_t, c_void_p
        )
        self.OPENSSL_sk_value: Callable[[int, int], int] = bind(
            "OPENSSL_sk_value", c_void_p, c_void_p, c_size_t
        )
        self.CRYPTO_BUFFER_new: Callable[[bytes, int, None], int | None] = bind(
            "CRYPTO_BUFFER_new", c_void_p, c_char_p, c_size_t, c_void_p
        )
        self.CRYPTO_BUFFER_data: Callable[[int], int] = bind(
            "CRYPTO_BUFFER_data", c_void_p, c_void_p
        )
        self.CRYPTO_BUFFER_len: Callable[[int], int] = bind(
            "CRYPTO_BUFFER_len", c_size_t, c_void_p
        )
        self.CBB_add_bytes: Callable[[int, bytes, int], int] = bind(
            "CBB_add_bytes", c_int, c_void_p, c_char_p, c_size_t
        )
        self.PEM_read_bio_X509: Callable[[int, None, None, None], int | None] = bind(
            "PEM_read_bio_X509", c_void_p, c_void_p, c_void_p, c_void_p, c_void_p
        )
        self.d2i_X509: Callable[[None, object, int], int | None] = bind(
            "d2i_X509", c_void_p, c_void_p, c_void_p, c_long
        )
        self.X509_free: Callable[[int], None] = bind("X509_free", None, c_void_p)
        self.X509_check_host: Callable[[int, bytes, int, int, None], int] = bind(
            "X509_check_host", c_int, c_void_p, c_char_p, c_size_t, c_uint, c_void_p
        )
        self.X509_verify_cert_error_string: Callable[[int], bytes] = bind(
            "X509_verify_cert_error_string", c_char_p, c_long
        )
        self.PEM_read_bio_PrivateKey: Callable[[int, None, None, None], int | None] = (
            bind(
                "PEM_read_bio_PrivateKey",
                c_void_p,
                c_void_p,
                c_void_p,
                c_void_p,
                c_void_p,
            )
        )
        self.d2i_AutoPrivateKey: Callable[[None, object, int], int | None] = bind(
            "d2i_AutoPrivateKey", c_void_p, c_void_p, c_void_p, c_long
        )
        self.EVP_PKEY_free: Callable[[int], None] = bind(
            "EVP_PKEY_free", None, c_void_p
        )
        self.ERR_get_error: Callable[[], int] = bind("ERR_get_error", c_uint32)
        self.ERR_clear_error: Callable[[], None] = bind("ERR_clear_error", None)
        self.ERR_error_string_n: Callable[[int, Array[c_char], int], bytes] = bind(
            "ERR_error_string_n", c_char_p, c_uint32, c_void_p, c_size_t
        )
        self.BrotliEncoderMaxCompressedSize: Callable[[int], int] = bind(
            "BrotliEncoderMaxCompressedSize", c_size_t, c_size_t
        )
        self.BrotliEncoderCompress: Callable[
            [int, int, int, int, bytes, object, Array[c_char]], int
        ] = bind(
            "BrotliEncoderCompress",
            c_int,
            c_int,
            c_int,
            c_int,
            c_size_t,
            c_char_p,
            c_void_p,
            c_void_p,
        )
        self.BrotliDecoderDecompress: Callable[
            [int, bytes, object, Array[c_char]], int
        ] = bind(
            "BrotliDecoderDecompress", c_int, c_size_t, c_char_p, c_void_p, c_void_p
        )
        self.BrotliDecoderCreateInstance: Callable[[None, None, None], int | None] = (
            bind("BrotliDecoderCreateInstance", c_void_p, c_void_p, c_void_p, c_void_p)
        )
        self.BrotliDecoderDecompressStream: Callable[
            [int, object, object, object, object, None], int
        ] = bind(
            "BrotliDecoderDecompressStream",
            c_int,
            c_void_p,
            c_void_p,
            c_void_p,
            c_void_p,
            c_void_p,
            c_void_p,
        )
        self.BrotliDecoderDestroyInstance: Callable[[int], None] = bind(
            "BrotliDecoderDestroyInstance", None, c_void_p
        )
        self.SSL_set_min_proto_version: Callable[[int, int], int] = bind(
            "SSL_set_min_proto_version", c_int, c_void_p, c_uint16
        )
        self.SSL_set_quic_method: Callable[[int, int], int] = bind(
            "SSL_set_quic_method", c_int, c_void_p, c_void_p
        )
        self.SSL_provide_quic_data: Callable[[int, int, bytes, int], int] = bind(
            "SSL_provide_quic_data", c_int, c_void_p, c_int, c_void_p, c_size_t
        )
        self.SSL_set_quic_transport_params: Callable[[int, bytes, int], int] = bind(
            "SSL_set_quic_transport_params", c_int, c_void_p, c_char_p, c_size_t
        )
        self.SSL_get_peer_quic_transport_params: Callable[
            [int, object, object], None
        ] = bind(
            "SSL_get_peer_quic_transport_params", None, c_void_p, c_void_p, c_void_p
        )
        self.SSL_process_quic_post_handshake: Callable[[int], int] = bind(
            "SSL_process_quic_post_handshake", c_int, c_void_p
        )
        self.EVP_sha256: Callable[[], int] = bind("EVP_sha256", c_void_p)
        self.EVP_sha384: Callable[[], int] = bind("EVP_sha384", c_void_p)
        self.EVP_aead_aes_128_gcm: Callable[[], int] = bind(
            "EVP_aead_aes_128_gcm", c_void_p
        )
        self.EVP_aead_aes_256_gcm: Callable[[], int] = bind(
            "EVP_aead_aes_256_gcm", c_void_p
        )
        self.EVP_aead_chacha20_poly1305: Callable[[], int] = bind(
            "EVP_aead_chacha20_poly1305", c_void_p
        )
        self.EVP_AEAD_CTX_new: Callable[[int, bytes, int, int], int | None] = bind(
            "EVP_AEAD_CTX_new", c_void_p, c_void_p, c_char_p, c_size_t, c_size_t
        )
        self.EVP_AEAD_CTX_free: Callable[[int], None] = bind(
            "EVP_AEAD_CTX_free", None, c_void_p
        )
        self.EVP_AEAD_CTX_seal: Callable[
            [int, Array[c_char], object, int, bytes, int, bytes, int, bytes, int], int
        ] = bind(
            "EVP_AEAD_CTX_seal",
            c_int,
            c_void_p,
            c_void_p,
            c_void_p,
            c_size_t,
            c_char_p,
            c_size_t,
            c_char_p,
            c_size_t,
            c_char_p,
            c_size_t,
        )
        self.EVP_AEAD_CTX_open: Callable[
            [int, Array[c_char], object, int, bytes, int, bytes, int, bytes, int], int
        ] = bind(
            "EVP_AEAD_CTX_open",
            c_int,
            c_void_p,
            c_void_p,
            c_void_p,
            c_size_t,
            c_char_p,
            c_size_t,
            c_char_p,
            c_size_t,
            c_char_p,
            c_size_t,
        )
        self.HKDF_extract: Callable[
            [Array[c_char], object, int, bytes, int, bytes, int], int
        ] = bind(
            "HKDF_extract",
            c_int,
            c_void_p,
            c_void_p,
            c_void_p,
            c_char_p,
            c_size_t,
            c_char_p,
            c_size_t,
        )
        self.HKDF_expand: Callable[
            [Array[c_char], int, int, bytes, int, bytes, int], int
        ] = bind(
            "HKDF_expand",
            c_int,
            c_void_p,
            c_size_t,
            c_void_p,
            c_char_p,
            c_size_t,
            c_char_p,
            c_size_t,
        )
        self.AES_set_encrypt_key: Callable[[bytes, int, Array[c_char]], int] = bind(
            "AES_set_encrypt_key", c_int, c_char_p, c_uint, c_void_p
        )
        self.AES_encrypt: Callable[[bytes, Array[c_char], Array[c_char]], None] = bind(
            "AES_encrypt", None, c_char_p, c_void_p, c_void_p
        )
        self.CRYPTO_chacha_20: Callable[
            [Array[c_char], bytes, int, bytes, bytes, int], None
        ] = bind(
            "CRYPTO_chacha_20",
            None,
            c_void_p,
            c_char_p,
            c_size_t,
            c_char_p,
            c_char_p,
            c_uint32,
        )
        self.RAND_bytes: Callable[[Array[c_char], int], int] = bind(
            "RAND_bytes", c_int, c_void_p, c_size_t
        )

    @property
    def source_revision(self) -> str:
        return self.boring_ssl_source_revision().decode("ascii")

    def errors(self) -> tuple[str, ...]:
        messages: list[str] = []
        text = ctypes.create_string_buffer(256)
        while code := self.ERR_get_error():
            _ = self.ERR_error_string_n(code, text, len(text))
            messages.append(ctypes.string_at(text).decode("ascii", "replace"))
        return tuple(messages)

    def error(self, operation: str) -> BoringSSLError:
        return BoringSSLError(operation, self.errors())


LIBRARY: Final = Library(Path(__file__).with_name(FILE_NAMES[sys.platform]))
