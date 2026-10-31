import ctypes
import zlib
from compression import zstd
from enum import IntEnum

from ssl2.errors import ConfigurationError
from ssl2.registry import CertificateCompressionAlgorithm

from boring_ssl2.binding import Callback
from boring_ssl2.library import Library


class BrotliEncoderSetting(IntEnum):
    # the quality, window and mode brotli's one-shot encoder takes
    QUALITY = 11
    WINDOW = 22
    MODE_GENERIC = 0


class BrotliResult(IntEnum):
    # what the one-shot calls and the stream decoder answer
    FALSE = 0
    TRUE = 1
    NEEDS_MORE_INPUT = 2
    NEEDS_MORE_OUTPUT = 3


class Size(IntEnum):
    OUTPUT_CHUNK = 65536


class BrotliDecoder:
    # a streaming decoder for brotli bodies, fed in pieces as they arrive
    def __init__(self, library: Library | None = None) -> None:
        self._library = library or Library.default()
        state = self._library.BrotliDecoderCreateInstance(None, None, None)
        if state is None:
            raise MemoryError("brotli decoder state")
        self._state = state
        self.finished = False

    def __del__(self) -> None:
        self._library.BrotliDecoderDestroyInstance(self._state)

    def decode(self, data: bytes) -> bytes:
        storage = ctypes.create_string_buffer(data, len(data))
        available_in = ctypes.c_size_t(len(data))
        next_in = ctypes.c_void_p(ctypes.addressof(storage))
        chunks: list[bytes] = []
        while True:
            output = ctypes.create_string_buffer(Size.OUTPUT_CHUNK)
            available_out = ctypes.c_size_t(Size.OUTPUT_CHUNK)
            next_out = ctypes.c_void_p(ctypes.addressof(output))
            result = self._library.BrotliDecoderDecompressStream(
                self._state,
                ctypes.byref(available_in),
                ctypes.byref(next_in),
                ctypes.byref(available_out),
                ctypes.byref(next_out),
                None,
            )
            chunks.append(output.raw[: Size.OUTPUT_CHUNK - available_out.value])
            match result:
                case BrotliResult.NEEDS_MORE_OUTPUT:
                    continue
                case BrotliResult.NEEDS_MORE_INPUT:
                    return b"".join(chunks)
                case BrotliResult.TRUE:
                    self.finished = True
                    return b"".join(chunks)
                case _:
                    raise ValueError("corrupt brotli stream")


class CertificateCompression:
    # RFC 8879: the client decompresses the server's certificate, the server compresses its own
    def __init__(self, library: Library) -> None:
        self._library = library
        self._callbacks: list[object] = []

    def register(self, handle: int, algorithm: CertificateCompressionAlgorithm, *, client: bool) -> None:
        if not algorithm.is_assigned:
            raise ConfigurationError(f"no certificate compression codec for {algorithm.name}")
        library = self._library

        def compress(_ssl: int, out: int, data: int, length: int) -> int:
            try:
                encoded = self._encode(algorithm, ctypes.string_at(data, length))
            except ValueError, zlib.error, zstd.ZstdError:
                return BrotliResult.FALSE
            return library.CBB_add_bytes(out, encoded, len(encoded))

        def decompress(_ssl: int, out: int, size: int, data: int, length: int) -> int:
            try:
                decoded = self._decode(algorithm, ctypes.string_at(data, length), size)
            except ValueError, zlib.error, zstd.ZstdError:
                return BrotliResult.FALSE
            buffer = library.CRYPTO_BUFFER_new(decoded, len(decoded), None)
            if len(decoded) != size or buffer is None:
                return BrotliResult.FALSE
            ctypes.c_void_p.from_address(out).value = buffer
            return BrotliResult.TRUE

        compressor = None if client else Callback.CERTIFICATE_COMPRESS(compress)
        decompressor = Callback.CERTIFICATE_DECOMPRESS(decompress) if client else None
        self._callbacks += (compressor, decompressor)
        library.check(
            library.SSL_CTX_add_cert_compression_alg(handle, algorithm, compressor, decompressor),
            "SSL_CTX_add_cert_compression_alg",
        )

    def _encode(self, algorithm: CertificateCompressionAlgorithm, data: bytes) -> bytes:
        match algorithm:
            case CertificateCompressionAlgorithm.zlib:
                return zlib.compress(data)
            case CertificateCompressionAlgorithm.zstd:
                return zstd.compress(data)
            case CertificateCompressionAlgorithm.brotli:
                library = self._library
                capacity = library.BrotliEncoderMaxCompressedSize(len(data))
                storage = ctypes.create_string_buffer(capacity)
                size = ctypes.c_size_t(capacity)
                accepted = library.BrotliEncoderCompress(
                    BrotliEncoderSetting.QUALITY,
                    BrotliEncoderSetting.WINDOW,
                    BrotliEncoderSetting.MODE_GENERIC,
                    len(data),
                    data,
                    ctypes.byref(size),
                    storage,
                )
                if accepted != BrotliResult.TRUE:
                    raise ValueError("brotli compression failed")
                return storage.raw[: size.value]

    def _decode(self, algorithm: CertificateCompressionAlgorithm, data: bytes, size: int) -> bytes:
        match algorithm:
            case CertificateCompressionAlgorithm.zlib:
                return zlib.decompress(data, bufsize=size)
            case CertificateCompressionAlgorithm.zstd:
                return zstd.decompress(data)
            case CertificateCompressionAlgorithm.brotli:
                storage = ctypes.create_string_buffer(size)
                decoded = ctypes.c_size_t(size)
                accepted = self._library.BrotliDecoderDecompress(len(data), data, ctypes.byref(decoded), storage)
                if accepted != BrotliResult.TRUE:
                    raise ValueError("brotli decompression failed")
                return storage.raw[: decoded.value]
