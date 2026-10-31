from collections.abc import Callable
from ctypes import Array, c_char, c_char_p, c_int, c_size_t, c_uint, c_uint32, c_void_p
from functools import cached_property

from boring_ssl2.binding import Binder


class CryptoFunctions(Binder):
    # include/openssl/aead.h, hkdf.h, aes.h, chacha.h, rand.h and brotli's encode.h and decode.h

    @cached_property
    def EVP_sha256(self) -> Callable[[], int]:
        return self.bind("EVP_sha256", c_void_p)

    @cached_property
    def EVP_sha384(self) -> Callable[[], int]:
        return self.bind("EVP_sha384", c_void_p)

    @cached_property
    def EVP_aead_aes_128_gcm(self) -> Callable[[], int]:
        return self.bind("EVP_aead_aes_128_gcm", c_void_p)

    @cached_property
    def EVP_aead_aes_256_gcm(self) -> Callable[[], int]:
        return self.bind("EVP_aead_aes_256_gcm", c_void_p)

    @cached_property
    def EVP_aead_chacha20_poly1305(self) -> Callable[[], int]:
        return self.bind("EVP_aead_chacha20_poly1305", c_void_p)

    @cached_property
    def EVP_AEAD_CTX_new(self) -> Callable[[int, bytes, int, int], int | None]:
        return self.bind("EVP_AEAD_CTX_new", c_void_p, c_void_p, c_char_p, c_size_t, c_size_t)

    @cached_property
    def EVP_AEAD_CTX_free(self) -> Callable[[int], None]:
        return self.bind("EVP_AEAD_CTX_free", None, c_void_p)

    @cached_property
    def EVP_AEAD_CTX_seal(self) -> Callable[[int, Array[c_char], object, int, bytes, int, bytes, int, bytes, int], int]:
        return self.bind(
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

    @cached_property
    def EVP_AEAD_CTX_open(self) -> Callable[[int, Array[c_char], object, int, bytes, int, bytes, int, bytes, int], int]:
        return self.bind(
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

    @cached_property
    def HKDF_extract(self) -> Callable[[Array[c_char], object, int, bytes, int, bytes, int], int]:
        return self.bind("HKDF_extract", c_int, c_void_p, c_void_p, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t)

    @cached_property
    def HKDF_expand(self) -> Callable[[Array[c_char], int, int, bytes, int, bytes, int], int]:
        return self.bind("HKDF_expand", c_int, c_void_p, c_size_t, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t)

    @cached_property
    def AES_set_encrypt_key(self) -> Callable[[bytes, int, Array[c_char]], int]:
        return self.bind("AES_set_encrypt_key", c_int, c_char_p, c_uint, c_void_p)

    @cached_property
    def AES_encrypt(self) -> Callable[[bytes, Array[c_char], Array[c_char]], None]:
        return self.bind("AES_encrypt", None, c_char_p, c_void_p, c_void_p)

    @cached_property
    def CRYPTO_chacha_20(self) -> Callable[[Array[c_char], bytes, int, bytes, bytes, int], None]:
        return self.bind("CRYPTO_chacha_20", None, c_void_p, c_char_p, c_size_t, c_char_p, c_char_p, c_uint32)

    @cached_property
    def RAND_bytes(self) -> Callable[[Array[c_char], int], int]:
        return self.bind("RAND_bytes", c_int, c_void_p, c_size_t)

    @cached_property
    def BrotliEncoderMaxCompressedSize(self) -> Callable[[int], int]:
        return self.bind("BrotliEncoderMaxCompressedSize", c_size_t, c_size_t)

    @cached_property
    def BrotliEncoderCompress(self) -> Callable[[int, int, int, int, bytes, object, Array[c_char]], int]:
        return self.bind("BrotliEncoderCompress", c_int, c_int, c_int, c_int, c_size_t, c_char_p, c_void_p, c_void_p)

    @cached_property
    def BrotliDecoderDecompress(self) -> Callable[[int, bytes, object, Array[c_char]], int]:
        return self.bind("BrotliDecoderDecompress", c_int, c_size_t, c_char_p, c_void_p, c_void_p)

    @cached_property
    def BrotliDecoderCreateInstance(self) -> Callable[[None, None, None], int | None]:
        return self.bind("BrotliDecoderCreateInstance", c_void_p, c_void_p, c_void_p, c_void_p)

    @cached_property
    def BrotliDecoderDecompressStream(self) -> Callable[[int, object, object, object, object, None], int]:
        return self.bind(
            "BrotliDecoderDecompressStream", c_int, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p
        )

    @cached_property
    def BrotliDecoderDestroyInstance(self) -> Callable[[int], None]:
        return self.bind("BrotliDecoderDestroyInstance", None, c_void_p)
