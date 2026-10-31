import ctypes
from collections.abc import Buffer, Callable
from enum import IntEnum
from typing import overload

from ssl2.errors import EarlyDataRejectedError, RaggedEOF, WantReadError, WantWriteError
from ssl2.interface import ClientContext, Limit, ServerContext
from ssl2.registry import CipherSuite, NextProtocol, ProtocolVersion, TLSVersion

from boring_ssl2.errors import BoringSSLError, CertificateVerificationError
from boring_ssl2.library import Library


class SSLErrorCode(IntEnum):
    # SSL_get_error
    NONE = 0
    SSL = 1
    WANT_READ = 2
    WANT_WRITE = 3
    SYSCALL = 5
    ZERO_RETURN = 6
    EARLY_DATA_REJECTED = 15


class VerifyResult(IntEnum):
    OK = 0


class ExDataIndex(IntEnum):
    # slot 0 is SSL_set_app_data; the new session callback reads the cache key back from it
    SESSION_KEY = 0


class CInt(IntEnum):
    # the most SSL_read and SSL_write take in one call
    MAXIMUM = 2**31 - 1


class TLSBuffer:
    def __init__(
        self,
        context: ClientContext | ServerContext,
        library: Library,
        context_handle: int,
        *,
        server: bool,
        session_key: str | None = None,
    ) -> None:
        self._context = context
        self._library = library
        handle = library.SSL_new(context_handle)
        if handle is None:
            raise library.error("SSL_new")
        self._handle = handle
        incoming, outgoing = library.BIO_new(library.BIO_s_mem()), library.BIO_new(library.BIO_s_mem())
        if incoming is None or outgoing is None:
            raise library.error("BIO_new")
        self._incoming = incoming
        self._outgoing = outgoing
        library.SSL_set_bio(handle, incoming, outgoing)
        if server:
            library.SSL_set_accept_state(handle)
        else:
            library.SSL_set_connect_state(handle)
        self._closing = False
        self._storage = ctypes.create_string_buffer(Limit.RECEIVE)
        self._session_key = None if session_key is None else ctypes.create_string_buffer(session_key.encode())
        if self._session_key is not None:
            library.check(
                library.SSL_set_ex_data(handle, ExDataIndex.SESSION_KEY, ctypes.addressof(self._session_key)),
                "SSL_set_ex_data",
            )

    def __del__(self) -> None:
        self._library.SSL_free(self._handle)

    @property
    def handle(self) -> int:
        return self._handle

    @property
    def library(self) -> Library:
        return self._library

    @property
    def context(self) -> ClientContext | ServerContext:
        return self._context

    @property
    def session_reused(self) -> bool:
        return self._library.SSL_session_reused(self._handle) == 1

    @overload
    def read(self, amount: int) -> bytes: ...

    @overload
    def read(self, amount: int, buffer: Buffer) -> int: ...

    def read(self, amount: int, buffer: Buffer | None = None) -> bytes | int:
        if buffer is None:
            size = min(amount, CInt.MAXIMUM)
            storage = (
                (ctypes.c_char * size).from_buffer(self._storage)
                if size <= Limit.RECEIVE
                else ctypes.create_string_buffer(size)
            )
            count = self._read_into(storage)
            return ctypes.string_at(storage, count)
        view = memoryview(buffer).cast("B")
        return self._read_into((ctypes.c_char * min(amount, view.nbytes, CInt.MAXIMUM)).from_buffer(view))

    def write(self, data: Buffer) -> int:
        payload = bytes(data)
        if not payload:
            # BoringSSL holds post-handshake tickets until the first write; a zero-length write releases them
            self._library.SSL_write(self._handle, payload, 0)
            return 0
        size = min(len(payload), CInt.MAXIMUM)
        return self._operate(lambda: self._library.SSL_write(self._handle, payload, size), "write")

    def attach(self, fileno: int) -> None:
        # the socket becomes BoringSSL's own BIO: records move between the kernel and the TLS state with no stop here
        self._library.check(self._library.SSL_set_fd(self._handle, fileno), "SSL_set_fd")

    def do_handshake(self) -> None:
        self._operate(lambda: self._library.SSL_do_handshake(self._handle), "handshake")

    def cipher(self) -> CipherSuite | int | None:
        cipher = self._library.SSL_get_current_cipher(self._handle)
        return None if cipher is None else CipherSuite(self._library.SSL_CIPHER_get_protocol_id(cipher))

    def negotiated_protocol(self) -> NextProtocol | bytes | None:
        data, length = ctypes.c_void_p(), ctypes.c_uint()
        self._library.SSL_get0_alpn_selected(self._handle, ctypes.byref(data), ctypes.byref(length))
        if data.value is None or not length.value:
            return None
        selected = ctypes.string_at(data.value, length.value)
        try:
            return NextProtocol(selected)
        except ValueError:
            return selected

    @property
    def negotiated_tls_version(self) -> TLSVersion | None:
        if not self._library.SSL_is_init_finished(self._handle):
            return None
        return ProtocolVersion(self._library.SSL_version(self._handle)).tls_version

    def shutdown(self) -> None:
        if not self._closing:
            self._library.ERR_clear_error()
            result = self._library.SSL_shutdown(self._handle)
            if result < 0:
                failure = self._failure(result, "shutdown")
                if failure is not None:
                    raise failure
            self._closing = True
            if result == 1:
                return
        # BoringSSL refuses application data that arrives before the peer's close_notify, so it is read away
        storage = ctypes.create_string_buffer(Limit.RECEIVE)
        while self._read_into(storage):
            pass

    def process_incoming(self, data_from_network: bytes) -> None:
        written = self._library.BIO_write(self._incoming, data_from_network, len(data_from_network))
        if written != len(data_from_network):
            raise self._library.error("BIO_write")

    def incoming_bytes_buffered(self) -> int:
        return self._library.BIO_ctrl_pending(self._incoming)

    def process_outgoing(self, amount_bytes_for_network: int) -> bytes:
        storage = ctypes.create_string_buffer(min(amount_bytes_for_network, CInt.MAXIMUM))
        count = self._library.BIO_read(self._outgoing, storage, len(storage))
        return ctypes.string_at(storage, count) if count > 0 else b""

    def outgoing_bytes_buffered(self) -> int:
        return self._library.BIO_ctrl_pending(self._outgoing)

    def getpeercert(self) -> bytes | None:
        chain = self.getpeerchain()
        return chain[0] if chain else None

    def getpeerchain(self) -> tuple[bytes, ...]:
        library = self._library
        stack = library.SSL_get0_peer_certificates(self._handle)
        if stack is None:
            return ()
        certificates: list[bytes] = []
        for index in range(library.OPENSSL_sk_num(stack)):
            item = library.OPENSSL_sk_value(stack, index)
            certificates.append(ctypes.string_at(library.CRYPTO_BUFFER_data(item), library.CRYPTO_BUFFER_len(item)))
        return tuple(certificates)

    def _read_into(self, storage: ctypes.Array[ctypes.c_char]) -> int:
        size = len(storage)
        if not size:
            return 0
        handle, library = self._handle, self._library
        total = self._operate(lambda: library.SSL_read(handle, storage, size), "read")
        # one SSL_read returns one record; the records already in the memory BIO or the kernel follow in this call.
        # An attached socket is non-blocking, so BoringSSL answers WANT_READ when they run out, never a block
        while 0 < total < size:
            rest = (ctypes.c_char * (size - total)).from_buffer(storage, total)
            more = library.SSL_read(handle, rest, size - total)
            if more <= 0:
                break
            total += more
        return total

    def _operate(self, call: Callable[[], int], operation: str) -> int:
        self._library.ERR_clear_error()
        result = call()
        if result > 0:
            return result
        failure = self._failure(result, operation)
        if failure is None:
            return 0
        raise failure

    def _failure(self, result: int, operation: str) -> Exception | None:
        library = self._library
        code = library.SSL_get_error(self._handle, result)
        reasons = library.errors()
        match code:
            case SSLErrorCode.WANT_READ:
                return WantReadError(f"{operation} needs more data from the peer")
            case SSLErrorCode.WANT_WRITE:
                return WantWriteError(f"{operation} needs the outgoing buffer drained")
            case SSLErrorCode.ZERO_RETURN:
                return None
            case SSLErrorCode.EARLY_DATA_REJECTED:
                return EarlyDataRejectedError(f"{operation}: the server declined the early data")
            case SSLErrorCode.SSL:
                verdict = library.SSL_get_verify_result(self._handle)
                if verdict != VerifyResult.OK:
                    return CertificateVerificationError(
                        operation, reasons, library.X509_verify_cert_error_string(verdict).decode("ascii")
                    )
                return BoringSSLError(operation, reasons)
            case SSLErrorCode.SYSCALL:
                # end of stream, a reset or a timeout on the socket: the connection is gone either way
                detail = f": {'; '.join(reasons)}" if reasons else ""
                return RaggedEOF(f"{operation}: the connection ended without close_notify{detail}")
            case _:
                return BoringSSLError(operation, (f"SSL_get_error={code}", *reasons))
