import ctypes
import sys
from collections.abc import Callable
from ctypes import (
    CFUNCTYPE,
    c_char_p,
    c_int,
    c_long,
    c_size_t,
    c_ssize_t,
    c_uint,
    c_uint8,
    c_uint16,
    c_uint32,
    c_void_p,
)
from enum import IntEnum, StrEnum
from pathlib import Path
from typing import Any

from ssl2.errors import ConfigurationError

from boring_ssl2.errors import BoringSSLError

type Foreign = type[c_char_p | c_int | c_long | c_size_t | c_ssize_t | c_uint | c_uint16 | c_uint32 | c_void_p]


class FileName(StrEnum):
    # what CMake installs next to this package on each platform
    LINUX = "libboring_ssl2.so"
    DARWIN = "libboring_ssl2.dylib"
    WINDOWS = "boring_ssl2.dll"


class Size(IntEnum):
    ERROR_STRING = 256


class Callback:
    # the C function pointer types BoringSSL and brotli call back into
    CERTIFICATE_COMPRESS = CFUNCTYPE(c_int, c_void_p, c_void_p, c_void_p, c_size_t)
    CERTIFICATE_DECOMPRESS = CFUNCTYPE(c_int, c_void_p, c_void_p, c_size_t, c_void_p, c_size_t)
    PROTOCOL_SELECT = CFUNCTYPE(c_int, c_void_p, c_void_p, c_void_p, c_void_p, c_uint, c_void_p)
    SERVER_NAME = CFUNCTYPE(c_int, c_void_p, c_void_p, c_void_p)
    NEW_SESSION = CFUNCTYPE(c_int, c_void_p, c_void_p)
    KEY_LOG = CFUNCTYPE(None, c_void_p, c_char_p)
    QUIC_SET_SECRET = CFUNCTYPE(c_int, c_void_p, c_int, c_void_p, c_void_p, c_size_t)
    QUIC_ADD_HANDSHAKE_DATA = CFUNCTYPE(c_int, c_void_p, c_int, c_void_p, c_size_t)
    QUIC_FLUSH_FLIGHT = CFUNCTYPE(c_int, c_void_p)
    QUIC_SEND_ALERT = CFUNCTYPE(c_int, c_void_p, c_int, c_uint8)


class LibraryPath:
    @staticmethod
    def bundled() -> Path:
        directory = Path(__file__).parent
        if sys.platform == "win32":
            name = FileName.WINDOWS
        elif sys.platform in ("darwin", "ios"):
            name = FileName.DARWIN
        else:
            name = FileName.LINUX
        path = directory / name
        if not path.exists():
            raise ConfigurationError(
                f"no BoringSSL build at {path}; build one with cmake (see README.md) or pass Library(path=...)"
            )
        return path


class Binder:
    # loads one shared object and binds its functions the first time each is used, so a build that lacks
    # a function fails at the call that needs it and names it
    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path is not None else LibraryPath.bundled()
        self._handle = ctypes.CDLL(str(self.path))

    def bind(self, name: str, result: Foreign | None, *arguments: Foreign) -> Callable[..., Any]:
        try:
            function = self._handle[name]
        except AttributeError:
            raise ConfigurationError(
                f"{self.path} has no {name}; this BoringSSL build predates the feature that needs it"
            ) from None
        function.restype = result
        function.argtypes = arguments
        return function

    def errors(self) -> tuple[str, ...]:
        # drains BoringSSL's error queue into readable reasons
        get_error = self.bind("ERR_get_error", c_uint32)
        error_string = self.bind("ERR_error_string_n", c_char_p, c_uint32, c_void_p, c_size_t)
        text = ctypes.create_string_buffer(Size.ERROR_STRING)
        messages: list[str] = []
        while code := get_error():
            error_string(code, text, len(text))
            messages.append(ctypes.string_at(text).decode("ascii", "replace"))
        return tuple(messages)

    def error(self, operation: str) -> BoringSSLError:
        return BoringSSLError(operation, self.errors())
