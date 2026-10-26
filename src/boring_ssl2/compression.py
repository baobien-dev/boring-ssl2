import ctypes
import zlib
from compression import zstd
from enum import IntEnum
from typing import Final, final

from ssl2.errors import ConfigurationError
from ssl2.parameters import CertificateCompressionAlgorithm

from boring_ssl2.library import (
    LIBRARY,
    CertificateCompressFunction,
    CertificateDecompressFunction,
)

BROTLI_TRUE: Final = 1
OUTPUT_CHUNK: Final = 65536


class BrotliEncoder(IntEnum):
    DEFAULT_QUALITY = 11
    DEFAULT_WINDOW = 22
    MODE_GENERIC = 0


class BrotliDecoderResult(IntEnum):
    ERROR = 0
    SUCCESS = 1
    NEEDS_MORE_INPUT = 2
    NEEDS_MORE_OUTPUT = 3


@final
class BrotliDecoder:
    def __init__(self) -> None:
        state = LIBRARY.BrotliDecoderCreateInstance(None, None, None)
        if state is None:
            raise MemoryError("brotli decoder state")
        self._state = state
        self.finished = False

    def __del__(self) -> None:
        LIBRARY.BrotliDecoderDestroyInstance(self._state)

    def decode(self, data: bytes) -> bytes:
        storage = ctypes.create_string_buffer(data, len(data))
        available_in = ctypes.c_size_t(len(data))
        next_in = ctypes.c_void_p(ctypes.addressof(storage))
        chunks: list[bytes] = []
        while True:
            output = ctypes.create_string_buffer(OUTPUT_CHUNK)
            available_out = ctypes.c_size_t(OUTPUT_CHUNK)
            next_out = ctypes.c_void_p(ctypes.addressof(output))
            result = LIBRARY.BrotliDecoderDecompressStream(
                self._state,
                ctypes.byref(available_in),
                ctypes.byref(next_in),
                ctypes.byref(available_out),
                ctypes.byref(next_out),
                None,
            )
            chunks.append(output.raw[: OUTPUT_CHUNK - available_out.value])
            match result:
                case BrotliDecoderResult.NEEDS_MORE_OUTPUT:
                    continue
                case BrotliDecoderResult.NEEDS_MORE_INPUT:
                    return b"".join(chunks)
                case BrotliDecoderResult.SUCCESS:
                    self.finished = True
                    return b"".join(chunks)
                case _:
                    raise ValueError("corrupt brotli stream")


class CertificateCompression:
    def __init__(self) -> None:
        self._callbacks: list[object] = []

    def register(
        self, handle: int, algorithm: CertificateCompressionAlgorithm, *, client: bool
    ) -> None:
        if not algorithm.is_assigned:
            raise ConfigurationError(
                f"no certificate compression codec for {algorithm.name}"
            )

        def compress(_ssl: int, out: int, data: int, length: int) -> int:
            try:
                encoded = self._encode(algorithm, ctypes.string_at(data, length))
            except ValueError, zlib.error, zstd.ZstdError:
                return 0
            return LIBRARY.CBB_add_bytes(out, encoded, len(encoded))

        def decompress(_ssl: int, out: int, size: int, data: int, length: int) -> int:
            try:
                decoded = self._decode(algorithm, ctypes.string_at(data, length), size)
            except ValueError, zlib.error, zstd.ZstdError:
                return 0
            buffer = LIBRARY.CRYPTO_BUFFER_new(decoded, len(decoded), None)
            if len(decoded) != size or buffer is None:
                return 0
            ctypes.c_void_p.from_address(out).value = buffer
            return 1

        compressor = None if client else CertificateCompressFunction(compress)
        decompressor = CertificateDecompressFunction(decompress) if client else None
        self._callbacks += (compressor, decompressor)
        if (
            LIBRARY.SSL_CTX_add_cert_compression_alg(
                handle, algorithm, compressor, decompressor
            )
            != 1
        ):
            raise LIBRARY.error("SSL_CTX_add_cert_compression_alg")

    @staticmethod
    def _encode(algorithm: CertificateCompressionAlgorithm, data: bytes) -> bytes:
        match algorithm:
            case CertificateCompressionAlgorithm.zlib:
                return zlib.compress(data)
            case CertificateCompressionAlgorithm.zstd:
                return zstd.compress(data)
            case CertificateCompressionAlgorithm.brotli:
                capacity = LIBRARY.BrotliEncoderMaxCompressedSize(len(data))
                storage = ctypes.create_string_buffer(capacity)
                size = ctypes.c_size_t(capacity)
                quality, window, mode = (
                    BrotliEncoder.DEFAULT_QUALITY,
                    BrotliEncoder.DEFAULT_WINDOW,
                    BrotliEncoder.MODE_GENERIC,
                )
                if (
                    LIBRARY.BrotliEncoderCompress(
                        quality,
                        window,
                        mode,
                        len(data),
                        data,
                        ctypes.byref(size),
                        storage,
                    )
                    != BROTLI_TRUE
                ):
                    raise ValueError("brotli compression failed")
                return storage.raw[: size.value]

    @staticmethod
    def _decode(
        algorithm: CertificateCompressionAlgorithm, data: bytes, size: int
    ) -> bytes:
        match algorithm:
            case CertificateCompressionAlgorithm.zlib:
                return zlib.decompress(data, bufsize=size)
            case CertificateCompressionAlgorithm.zstd:
                return zstd.decompress(data)
            case CertificateCompressionAlgorithm.brotli:
                storage = ctypes.create_string_buffer(size)
                decoded = ctypes.c_size_t(size)
                if (
                    LIBRARY.BrotliDecoderDecompress(
                        len(data), data, ctypes.byref(decoded), storage
                    )
                    != BrotliDecoderResult.SUCCESS
                ):
                    raise ValueError("brotli decompression failed")
                return storage.raw[: decoded.value]
