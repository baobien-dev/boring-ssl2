from collections.abc import Callable
from ctypes import Array, c_char, c_char_p, c_int, c_long, c_size_t, c_ssize_t, c_uint, c_uint16, c_uint32, c_void_p
from functools import cached_property

from boring_ssl2.binding import Binder


class SslFunctions(Binder):
    # include/openssl/ssl.h, bio.h, stack.h, pool.h, bytestring.h and err.h, with BoringSSL's own names

    @cached_property
    def boring_ssl_source_revision(self) -> Callable[[], bytes]:
        return self.bind("boring_ssl_source_revision", c_char_p)

    @cached_property
    def TLS_method(self) -> Callable[[], int]:
        return self.bind("TLS_method", c_void_p)

    @cached_property
    def SSL_CTX_new(self) -> Callable[[int], int | None]:
        return self.bind("SSL_CTX_new", c_void_p, c_void_p)

    @cached_property
    def SSL_CTX_free(self) -> Callable[[int], None]:
        return self.bind("SSL_CTX_free", None, c_void_p)

    @cached_property
    def SSL_CTX_set_min_proto_version(self) -> Callable[[int, int], int]:
        return self.bind("SSL_CTX_set_min_proto_version", c_int, c_void_p, c_uint16)

    @cached_property
    def SSL_CTX_set_max_proto_version(self) -> Callable[[int, int], int]:
        return self.bind("SSL_CTX_set_max_proto_version", c_int, c_void_p, c_uint16)

    @cached_property
    def SSL_CTX_set_strict_cipher_list(self) -> Callable[[int, bytes], int]:
        return self.bind("SSL_CTX_set_strict_cipher_list", c_int, c_void_p, c_char_p)

    @cached_property
    def SSL_CTX_set1_tls13_ciphers(self) -> Callable[[int, Array[c_uint16], None, int], int]:
        return self.bind("SSL_CTX_set1_tls13_ciphers", c_int, c_void_p, c_void_p, c_void_p, c_size_t)

    @cached_property
    def SSL_CTX_set1_group_ids(self) -> Callable[[int, Array[c_uint16], int], int]:
        return self.bind("SSL_CTX_set1_group_ids", c_int, c_void_p, c_void_p, c_size_t)

    @cached_property
    def SSL_CTX_set_verify_algorithm_prefs(self) -> Callable[[int, Array[c_uint16], int], int]:
        return self.bind("SSL_CTX_set_verify_algorithm_prefs", c_int, c_void_p, c_void_p, c_size_t)

    @cached_property
    def SSL_CTX_set1_extension_order(self) -> Callable[[int, Array[c_uint16], int], int]:
        # added by patches/boringssl/0001-client-hello-extension-order.patch
        return self.bind("SSL_CTX_set1_extension_order", c_int, c_void_p, c_void_p, c_size_t)

    @cached_property
    def SSL_CTX_set_alpn_protos(self) -> Callable[[int, bytes, int], int]:
        return self.bind("SSL_CTX_set_alpn_protos", c_int, c_void_p, c_char_p, c_size_t)

    @cached_property
    def SSL_CTX_set_options(self) -> Callable[[int, int], int]:
        return self.bind("SSL_CTX_set_options", c_uint32, c_void_p, c_uint32)

    @cached_property
    def SSL_CTX_set_grease_enabled(self) -> Callable[[int, int], None]:
        return self.bind("SSL_CTX_set_grease_enabled", None, c_void_p, c_int)

    @cached_property
    def SSL_CTX_set_permute_extensions(self) -> Callable[[int, int], None]:
        return self.bind("SSL_CTX_set_permute_extensions", None, c_void_p, c_int)

    @cached_property
    def SSL_CTX_set_legacy_padding(self) -> Callable[[int, int], None]:
        # added by patches/boringssl/0002-legacy-client-hello-padding.patch
        return self.bind("SSL_CTX_set_legacy_padding", None, c_void_p, c_int)

    @cached_property
    def SSL_CTX_enable_ocsp_stapling(self) -> Callable[[int], None]:
        return self.bind("SSL_CTX_enable_ocsp_stapling", None, c_void_p)

    @cached_property
    def SSL_CTX_enable_signed_cert_timestamps(self) -> Callable[[int], None]:
        return self.bind("SSL_CTX_enable_signed_cert_timestamps", None, c_void_p)

    @cached_property
    def SSL_CTX_set_verify(self) -> Callable[[int, int, None], None]:
        return self.bind("SSL_CTX_set_verify", None, c_void_p, c_int, c_void_p)

    @cached_property
    def SSL_CTX_load_verify_locations(self) -> Callable[[int, bytes | None, bytes | None], int]:
        return self.bind("SSL_CTX_load_verify_locations", c_int, c_void_p, c_char_p, c_char_p)

    @cached_property
    def SSL_CTX_get_cert_store(self) -> Callable[[int], int]:
        return self.bind("SSL_CTX_get_cert_store", c_void_p, c_void_p)

    @cached_property
    def X509_STORE_add_cert(self) -> Callable[[int, int], int]:
        return self.bind("X509_STORE_add_cert", c_int, c_void_p, c_void_p)

    @cached_property
    def SSL_CTX_use_certificate(self) -> Callable[[int, int], int]:
        return self.bind("SSL_CTX_use_certificate", c_int, c_void_p, c_void_p)

    @cached_property
    def SSL_CTX_use_PrivateKey(self) -> Callable[[int, int], int]:
        return self.bind("SSL_CTX_use_PrivateKey", c_int, c_void_p, c_void_p)

    @cached_property
    def SSL_CTX_add1_chain_cert(self) -> Callable[[int, int], int]:
        return self.bind("SSL_CTX_add1_chain_cert", c_int, c_void_p, c_void_p)

    @cached_property
    def SSL_CTX_add_cert_compression_alg(self) -> Callable[[int, int, object, object], int]:
        return self.bind("SSL_CTX_add_cert_compression_alg", c_int, c_void_p, c_uint16, c_void_p, c_void_p)

    @cached_property
    def SSL_CTX_set_alpn_select_cb(self) -> Callable[[int, object, None], None]:
        return self.bind("SSL_CTX_set_alpn_select_cb", None, c_void_p, c_void_p, c_void_p)

    @cached_property
    def SSL_CTX_set_tlsext_servername_callback(self) -> Callable[[int, object], int]:
        return self.bind("SSL_CTX_set_tlsext_servername_callback", c_int, c_void_p, c_void_p)

    @cached_property
    def SSL_CTX_set_session_cache_mode(self) -> Callable[[int, int], int]:
        return self.bind("SSL_CTX_set_session_cache_mode", c_int, c_void_p, c_int)

    @cached_property
    def SSL_CTX_sess_set_new_cb(self) -> Callable[[int, object], None]:
        return self.bind("SSL_CTX_sess_set_new_cb", None, c_void_p, c_void_p)

    @cached_property
    def SSL_CTX_set_keylog_callback(self) -> Callable[[int, object], None]:
        return self.bind("SSL_CTX_set_keylog_callback", None, c_void_p, c_void_p)

    @cached_property
    def SSL_SESSION_to_bytes(self) -> Callable[[int, object, object], int]:
        return self.bind("SSL_SESSION_to_bytes", c_int, c_void_p, c_void_p, c_void_p)

    @cached_property
    def SSL_SESSION_from_bytes(self) -> Callable[[bytes, int, int], int | None]:
        return self.bind("SSL_SESSION_from_bytes", c_void_p, c_char_p, c_size_t, c_void_p)

    @cached_property
    def SSL_SESSION_should_be_single_use(self) -> Callable[[int], int]:
        return self.bind("SSL_SESSION_should_be_single_use", c_int, c_void_p)

    @cached_property
    def SSL_SESSION_free(self) -> Callable[[int], None]:
        return self.bind("SSL_SESSION_free", None, c_void_p)

    @cached_property
    def SSL_SESSION_early_data_capable(self) -> Callable[[int], int]:
        return self.bind("SSL_SESSION_early_data_capable", c_int, c_void_p)

    @cached_property
    def SSL_set_session(self) -> Callable[[int, int], int]:
        return self.bind("SSL_set_session", c_int, c_void_p, c_void_p)

    @cached_property
    def SSL_session_reused(self) -> Callable[[int], int]:
        return self.bind("SSL_session_reused", c_int, c_void_p)

    @cached_property
    def SSL_get_session(self) -> Callable[[int], int | None]:
        return self.bind("SSL_get_session", c_void_p, c_void_p)

    @cached_property
    def SSL_set_early_data_enabled(self) -> Callable[[int, int], None]:
        return self.bind("SSL_set_early_data_enabled", None, c_void_p, c_int)

    @cached_property
    def SSL_in_early_data(self) -> Callable[[int], int]:
        return self.bind("SSL_in_early_data", c_int, c_void_p)

    @cached_property
    def SSL_early_data_accepted(self) -> Callable[[int], int]:
        return self.bind("SSL_early_data_accepted", c_int, c_void_p)

    @cached_property
    def SSL_reset_early_data_reject(self) -> Callable[[int], None]:
        return self.bind("SSL_reset_early_data_reject", None, c_void_p)

    @cached_property
    def OPENSSL_free(self) -> Callable[[int], None]:
        return self.bind("OPENSSL_free", None, c_void_p)

    @cached_property
    def SSL_new(self) -> Callable[[int], int | None]:
        return self.bind("SSL_new", c_void_p, c_void_p)

    @cached_property
    def SSL_free(self) -> Callable[[int], None]:
        return self.bind("SSL_free", None, c_void_p)

    @cached_property
    def SSL_set_connect_state(self) -> Callable[[int], None]:
        return self.bind("SSL_set_connect_state", None, c_void_p)

    @cached_property
    def SSL_set_accept_state(self) -> Callable[[int], None]:
        return self.bind("SSL_set_accept_state", None, c_void_p)

    @cached_property
    def SSL_set_bio(self) -> Callable[[int, int, int], None]:
        return self.bind("SSL_set_bio", None, c_void_p, c_void_p, c_void_p)

    @cached_property
    def SSL_set_fd(self) -> Callable[[int, int], int]:
        return self.bind("SSL_set_fd", c_int, c_void_p, c_int)

    @cached_property
    def SSL_set_min_proto_version(self) -> Callable[[int, int], int]:
        return self.bind("SSL_set_min_proto_version", c_int, c_void_p, c_uint16)

    @cached_property
    def SSL_set_tlsext_host_name(self) -> Callable[[int, bytes], int]:
        return self.bind("SSL_set_tlsext_host_name", c_int, c_void_p, c_char_p)

    @cached_property
    def SSL_set1_host(self) -> Callable[[int, bytes], int]:
        return self.bind("SSL_set1_host", c_int, c_void_p, c_char_p)

    @cached_property
    def SSL_get0_param(self) -> Callable[[int], int]:
        return self.bind("SSL_get0_param", c_void_p, c_void_p)

    @cached_property
    def X509_VERIFY_PARAM_set1_ip_asc(self) -> Callable[[int, bytes], int]:
        return self.bind("X509_VERIFY_PARAM_set1_ip_asc", c_int, c_void_p, c_char_p)

    @cached_property
    def SSL_set_ex_data(self) -> Callable[[int, int, int], int]:
        return self.bind("SSL_set_ex_data", c_int, c_void_p, c_int, c_void_p)

    @cached_property
    def SSL_get_ex_data(self) -> Callable[[int, int], int | None]:
        return self.bind("SSL_get_ex_data", c_void_p, c_void_p, c_int)

    @cached_property
    def SSL_add_application_settings(self) -> Callable[[int, bytes, int, None, int], int]:
        return self.bind("SSL_add_application_settings", c_int, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t)

    @cached_property
    def SSL_set_alps_use_new_codepoint(self) -> Callable[[int, int], None]:
        return self.bind("SSL_set_alps_use_new_codepoint", None, c_void_p, c_int)

    @cached_property
    def SSL_set1_requested_trust_anchors(self) -> Callable[[int, bytes, int], int]:
        return self.bind("SSL_set1_requested_trust_anchors", c_int, c_void_p, c_char_p, c_size_t)

    @cached_property
    def SSL_set_enable_ech_grease(self) -> Callable[[int, int], None]:
        return self.bind("SSL_set_enable_ech_grease", None, c_void_p, c_int)

    @cached_property
    def SSL_set1_client_key_shares(self) -> Callable[[int, Array[c_uint16], int], int]:
        return self.bind("SSL_set1_client_key_shares", c_int, c_void_p, c_void_p, c_size_t)

    @cached_property
    def SSL_do_handshake(self) -> Callable[[int], int]:
        return self.bind("SSL_do_handshake", c_int, c_void_p)

    @cached_property
    def SSL_is_init_finished(self) -> Callable[[int], int]:
        return self.bind("SSL_is_init_finished", c_int, c_void_p)

    @cached_property
    def SSL_read(self) -> Callable[[int, Array[c_char], int], int]:
        return self.bind("SSL_read", c_int, c_void_p, c_void_p, c_int)

    @cached_property
    def SSL_write(self) -> Callable[[int, bytes, int], int]:
        return self.bind("SSL_write", c_int, c_void_p, c_void_p, c_int)

    @cached_property
    def SSL_shutdown(self) -> Callable[[int], int]:
        return self.bind("SSL_shutdown", c_int, c_void_p)

    @cached_property
    def SSL_get_error(self) -> Callable[[int, int], int]:
        return self.bind("SSL_get_error", c_int, c_void_p, c_int)

    @cached_property
    def SSL_get_verify_result(self) -> Callable[[int], int]:
        return self.bind("SSL_get_verify_result", c_long, c_void_p)

    @cached_property
    def SSL_version(self) -> Callable[[int], int]:
        return self.bind("SSL_version", c_int, c_void_p)

    @cached_property
    def SSL_get_current_cipher(self) -> Callable[[int], int | None]:
        return self.bind("SSL_get_current_cipher", c_void_p, c_void_p)

    @cached_property
    def SSL_CIPHER_get_protocol_id(self) -> Callable[[int], int]:
        return self.bind("SSL_CIPHER_get_protocol_id", c_uint16, c_void_p)

    @cached_property
    def SSL_CIPHER_standard_name(self) -> Callable[[int], bytes]:
        return self.bind("SSL_CIPHER_standard_name", c_char_p, c_void_p)

    @cached_property
    def SSL_get_cipher_by_value(self) -> Callable[[int], int | None]:
        return self.bind("SSL_get_cipher_by_value", c_void_p, c_uint16)

    @cached_property
    def SSL_get0_alpn_selected(self) -> Callable[[int, object, object], None]:
        return self.bind("SSL_get0_alpn_selected", None, c_void_p, c_void_p, c_void_p)

    @cached_property
    def SSL_get0_peer_certificates(self) -> Callable[[int], int | None]:
        return self.bind("SSL_get0_peer_certificates", c_void_p, c_void_p)

    @cached_property
    def SSL_get_servername(self) -> Callable[[int, int], bytes | None]:
        return self.bind("SSL_get_servername", c_char_p, c_void_p, c_int)

    @cached_property
    def SSL_set_SSL_CTX(self) -> Callable[[int, int], int | None]:
        return self.bind("SSL_set_SSL_CTX", c_void_p, c_void_p, c_void_p)

    @cached_property
    def SSL_select_next_proto(self) -> Callable[[int, int, int, int, bytes, int], int]:
        return self.bind("SSL_select_next_proto", c_int, c_void_p, c_void_p, c_void_p, c_uint, c_char_p, c_uint)

    @cached_property
    def SSL_set_quic_method(self) -> Callable[[int, int], int]:
        return self.bind("SSL_set_quic_method", c_int, c_void_p, c_void_p)

    @cached_property
    def SSL_provide_quic_data(self) -> Callable[[int, int, bytes, int], int]:
        return self.bind("SSL_provide_quic_data", c_int, c_void_p, c_int, c_void_p, c_size_t)

    @cached_property
    def SSL_set_quic_transport_params(self) -> Callable[[int, bytes, int], int]:
        return self.bind("SSL_set_quic_transport_params", c_int, c_void_p, c_char_p, c_size_t)

    @cached_property
    def SSL_get_peer_quic_transport_params(self) -> Callable[[int, object, object], None]:
        return self.bind("SSL_get_peer_quic_transport_params", None, c_void_p, c_void_p, c_void_p)

    @cached_property
    def SSL_process_quic_post_handshake(self) -> Callable[[int], int]:
        return self.bind("SSL_process_quic_post_handshake", c_int, c_void_p)

    @cached_property
    def BIO_s_mem(self) -> Callable[[], int]:
        return self.bind("BIO_s_mem", c_void_p)

    @cached_property
    def BIO_new(self) -> Callable[[int], int | None]:
        return self.bind("BIO_new", c_void_p, c_void_p)

    @cached_property
    def BIO_new_mem_buf(self) -> Callable[[bytes, int], int | None]:
        return self.bind("BIO_new_mem_buf", c_void_p, c_void_p, c_ssize_t)

    @cached_property
    def BIO_free(self) -> Callable[[int], int]:
        return self.bind("BIO_free", c_int, c_void_p)

    @cached_property
    def BIO_read(self) -> Callable[[int, Array[c_char], int], int]:
        return self.bind("BIO_read", c_int, c_void_p, c_void_p, c_int)

    @cached_property
    def BIO_write(self) -> Callable[[int, bytes, int], int]:
        return self.bind("BIO_write", c_int, c_void_p, c_void_p, c_int)

    @cached_property
    def BIO_ctrl_pending(self) -> Callable[[int], int]:
        return self.bind("BIO_ctrl_pending", c_size_t, c_void_p)

    @cached_property
    def OPENSSL_sk_num(self) -> Callable[[int], int]:
        return self.bind("OPENSSL_sk_num", c_size_t, c_void_p)

    @cached_property
    def OPENSSL_sk_value(self) -> Callable[[int, int], int]:
        return self.bind("OPENSSL_sk_value", c_void_p, c_void_p, c_size_t)

    @cached_property
    def CRYPTO_BUFFER_new(self) -> Callable[[bytes, int, None], int | None]:
        return self.bind("CRYPTO_BUFFER_new", c_void_p, c_char_p, c_size_t, c_void_p)

    @cached_property
    def CRYPTO_BUFFER_data(self) -> Callable[[int], int]:
        return self.bind("CRYPTO_BUFFER_data", c_void_p, c_void_p)

    @cached_property
    def CRYPTO_BUFFER_len(self) -> Callable[[int], int]:
        return self.bind("CRYPTO_BUFFER_len", c_size_t, c_void_p)

    @cached_property
    def CBB_add_bytes(self) -> Callable[[int, bytes, int], int]:
        return self.bind("CBB_add_bytes", c_int, c_void_p, c_char_p, c_size_t)

    @cached_property
    def ERR_clear_error(self) -> Callable[[], None]:
        return self.bind("ERR_clear_error", None)
