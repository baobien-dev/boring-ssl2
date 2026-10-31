from collections.abc import Callable
from ctypes import c_char_p, c_int, c_long, c_size_t, c_uint, c_void_p
from functools import cached_property

from boring_ssl2.binding import Binder


class X509Functions(Binder):
    # include/openssl/x509.h, pem.h, asn1.h and evp.h, with BoringSSL's own names

    @cached_property
    def PEM_read_bio_X509(self) -> Callable[[int, None, None, None], int | None]:
        return self.bind("PEM_read_bio_X509", c_void_p, c_void_p, c_void_p, c_void_p, c_void_p)

    @cached_property
    def d2i_X509(self) -> Callable[[None, object, int], int | None]:
        return self.bind("d2i_X509", c_void_p, c_void_p, c_void_p, c_long)

    @cached_property
    def X509_free(self) -> Callable[[int], None]:
        return self.bind("X509_free", None, c_void_p)

    @cached_property
    def X509_get_pubkey(self) -> Callable[[int], int | None]:
        return self.bind("X509_get_pubkey", c_void_p, c_void_p)

    @cached_property
    def X509_get_subject_name(self) -> Callable[[int], int]:
        return self.bind("X509_get_subject_name", c_void_p, c_void_p)

    @cached_property
    def X509_get0_serialNumber(self) -> Callable[[int], int]:
        return self.bind("X509_get0_serialNumber", c_void_p, c_void_p)

    @cached_property
    def X509_get_ext_by_NID(self) -> Callable[[int, int, int], int]:
        return self.bind("X509_get_ext_by_NID", c_int, c_void_p, c_int, c_int)

    @cached_property
    def X509_get_ext(self) -> Callable[[int, int], int | None]:
        return self.bind("X509_get_ext", c_void_p, c_void_p, c_int)

    @cached_property
    def X509_EXTENSION_get_data(self) -> Callable[[int], int]:
        return self.bind("X509_EXTENSION_get_data", c_void_p, c_void_p)

    @cached_property
    def ASN1_STRING_get0_data(self) -> Callable[[int], int]:
        return self.bind("ASN1_STRING_get0_data", c_void_p, c_void_p)

    @cached_property
    def ASN1_STRING_length(self) -> Callable[[int], int]:
        return self.bind("ASN1_STRING_length", c_int, c_void_p)

    @cached_property
    def X509_NAME_cmp(self) -> Callable[[int, int], int]:
        return self.bind("X509_NAME_cmp", c_int, c_void_p, c_void_p)

    @cached_property
    def d2i_X509_CRL(self) -> Callable[[None, object, int], int | None]:
        return self.bind("d2i_X509_CRL", c_void_p, c_void_p, c_void_p, c_long)

    @cached_property
    def X509_CRL_free(self) -> Callable[[int], None]:
        return self.bind("X509_CRL_free", None, c_void_p)

    @cached_property
    def X509_CRL_verify(self) -> Callable[[int, int], int]:
        return self.bind("X509_CRL_verify", c_int, c_void_p, c_void_p)

    @cached_property
    def X509_CRL_get_issuer(self) -> Callable[[int], int]:
        return self.bind("X509_CRL_get_issuer", c_void_p, c_void_p)

    @cached_property
    def X509_CRL_get0_nextUpdate(self) -> Callable[[int], int | None]:
        return self.bind("X509_CRL_get0_nextUpdate", c_void_p, c_void_p)

    @cached_property
    def X509_CRL_get0_by_cert(self) -> Callable[[int, object, int], int]:
        return self.bind("X509_CRL_get0_by_cert", c_int, c_void_p, c_void_p, c_void_p)

    @cached_property
    def X509_cmp_current_time(self) -> Callable[[int], int]:
        return self.bind("X509_cmp_current_time", c_int, c_void_p)

    @cached_property
    def X509_check_host(self) -> Callable[[int, bytes, int, int, None], int]:
        return self.bind("X509_check_host", c_int, c_void_p, c_char_p, c_size_t, c_uint, c_void_p)

    @cached_property
    def X509_verify_cert_error_string(self) -> Callable[[int], bytes]:
        return self.bind("X509_verify_cert_error_string", c_char_p, c_long)

    @cached_property
    def PEM_read_bio_PrivateKey(self) -> Callable[[int, None, None, None], int | None]:
        return self.bind("PEM_read_bio_PrivateKey", c_void_p, c_void_p, c_void_p, c_void_p, c_void_p)

    @cached_property
    def d2i_AutoPrivateKey(self) -> Callable[[None, object, int], int | None]:
        return self.bind("d2i_AutoPrivateKey", c_void_p, c_void_p, c_void_p, c_long)

    @cached_property
    def EVP_PKEY_free(self) -> Callable[[int], None]:
        return self.bind("EVP_PKEY_free", None, c_void_p)
