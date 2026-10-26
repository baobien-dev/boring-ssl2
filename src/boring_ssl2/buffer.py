import ctypes
from collections.abc import Buffer, Callable
from enum import IntEnum
from typing import overload

from ssl2.errors import EarlyDataRejected, RaggedEOF, WantReadError, WantWriteError
from ssl2.interface import RECEIVE_SIZE, ClientContext, ServerContext
from ssl2.parameters import CipherSuite, NextProtocol, ProtocolVersion, TLSVersion

from boring_ssl2.library import LIBRARY, BoringSSLError, CertificateVerificationError

INT_LIMIT = 2**31 - 1
X509_V_OK = 0
NEXT_PROTOCOLS = {protocol.value: protocol for protocol in NextProtocol}


class SSLErrorCode(IntEnum):
    SSL = 1
    WANT_READ = 2
    WANT_WRITE = 3
    SYSCALL = 5
    ZERO_RETURN = 6
    EARLY_DATA_REJECTED = 15


class TLSBuffer:
    def __init__(
        self,
        context: ClientContext | ServerContext,
        context_handle: int,
        *,
        server: bool,
        session_key: str | None = None,
    ) -> None:
        self._context = context
        handle = LIBRARY.SSL_new(context_handle)
        if handle is None:
            raise LIBRARY.error("SSL_new")
        self._handle = handle
        incoming, outgoing = (
            LIBRARY.BIO_new(LIBRARY.BIO_s_mem()),
            LIBRARY.BIO_new(LIBRARY.BIO_s_mem()),
        )
        if incoming is None or outgoing is None:
            raise LIBRARY.error("BIO_new")
        self._incoming = incoming
        self._outgoing = outgoing
        LIBRARY.SSL_set_bio(handle, incoming, outgoing)
        if server:
            LIBRARY.SSL_set_accept_state(handle)
        else:
            LIBRARY.SSL_set_connect_state(handle)
        self._closing = False
        self._storage = ctypes.create_string_buffer(RECEIVE_SIZE)
        self._session_key = (
            None
            if session_key is None
            else ctypes.create_string_buffer(session_key.encode())
        )
        # ex_data slot 0 is SSL_set_app_data; the new-session callback reads the key back from it
        if (
            self._session_key is not None
            and LIBRARY.SSL_set_ex_data(handle, 0, ctypes.addressof(self._session_key))
            != 1
        ):
            raise LIBRARY.error("SSL_set_ex_data")

    def __del__(self) -> None:
        LIBRARY.SSL_free(self._handle)

    @property
    def handle(self) -> int:
        return self._handle

    @property
    def context(self) -> ClientContext | ServerContext:
        return self._context

    @property
    def session_reused(self) -> bool:
        return LIBRARY.SSL_session_reused(self._handle) == 1

    @overload
    def read(self, amt: int) -> bytes: ...

    @overload
    def read(self, amt: int, buffer: Buffer) -> int: ...

    def read(self, amt: int, buffer: Buffer | None = None) -> bytes | int:
        if buffer is None:
            size = min(amt, INT_LIMIT)
            storage = (
                (ctypes.c_char * size).from_buffer(self._storage)
                if size <= RECEIVE_SIZE
                else ctypes.create_string_buffer(size)
            )
            count = self._read_into(storage)
            return ctypes.string_at(storage, count)
        view = memoryview(buffer).cast("B")
        return self._read_into(
            (ctypes.c_char * min(amt, view.nbytes, INT_LIMIT)).from_buffer(view)
        )

    def write(self, buf: Buffer) -> int:
        # bytes pass to BoringSSL as they are; anything else is copied once
        payload = bytes(buf)
        if not payload:
            # BoringSSL holds post-handshake tickets until the first write; a zero-length write releases them
            LIBRARY.SSL_write(self._handle, payload, 0)
            return 0
        size = min(len(payload), INT_LIMIT)
        return self._operate(
            lambda: LIBRARY.SSL_write(self._handle, payload, size), "write"
        )

    def attach(self, fileno: int) -> None:
        # the socket becomes BoringSSL's own BIO: records move between the kernel and the TLS state with no stop in Python
        if LIBRARY.SSL_set_fd(self._handle, fileno) != 1:
            raise LIBRARY.error("SSL_set_fd")

    def do_handshake(self) -> None:
        self._operate(lambda: LIBRARY.SSL_do_handshake(self._handle), "handshake")

    def cipher(self) -> CipherSuite | int | None:
        cipher = LIBRARY.SSL_get_current_cipher(self._handle)
        return (
            None
            if cipher is None
            else CipherSuite(LIBRARY.SSL_CIPHER_get_protocol_id(cipher))
        )

    def negotiated_protocol(self) -> NextProtocol | bytes | None:
        data, length = ctypes.c_void_p(), ctypes.c_uint()
        LIBRARY.SSL_get0_alpn_selected(
            self._handle, ctypes.byref(data), ctypes.byref(length)
        )
        if data.value is None or not length.value:
            return None
        selected = ctypes.string_at(data.value, length.value)
        return NEXT_PROTOCOLS.get(selected, selected)

    @property
    def negotiated_tls_version(self) -> TLSVersion | None:
        if not LIBRARY.SSL_is_init_finished(self._handle):
            return None
        return ProtocolVersion(LIBRARY.SSL_version(self._handle)).tls_version

    def shutdown(self) -> None:
        if not self._closing:
            LIBRARY.ERR_clear_error()
            result = LIBRARY.SSL_shutdown(self._handle)
            if result < 0:
                failure = self._failure(result, "shutdown")
                if failure is not None:
                    raise failure
            self._closing = True
            if result == 1:
                return
        # BoringSSL refuses application data that arrives before the peer's close_notify, so read it away
        storage = ctypes.create_string_buffer(RECEIVE_SIZE)
        while self._read_into(storage):
            pass

    def process_incoming(self, data_from_network: bytes) -> None:
        if LIBRARY.BIO_write(
            self._incoming, data_from_network, len(data_from_network)
        ) != len(data_from_network):
            raise LIBRARY.error("BIO_write")

    def incoming_bytes_buffered(self) -> int:
        return LIBRARY.BIO_ctrl_pending(self._incoming)

    def process_outgoing(self, amount_bytes_for_network: int) -> bytes:
        storage = ctypes.create_string_buffer(min(amount_bytes_for_network, INT_LIMIT))
        count = LIBRARY.BIO_read(self._outgoing, storage, len(storage))
        return ctypes.string_at(storage, count) if count > 0 else b""

    def outgoing_bytes_buffered(self) -> int:
        return LIBRARY.BIO_ctrl_pending(self._outgoing)

    def getpeercert(self) -> bytes | None:
        stack = LIBRARY.SSL_get0_peer_certificates(self._handle)
        if stack is None or LIBRARY.OPENSSL_sk_num(stack) == 0:
            return None
        leaf = LIBRARY.OPENSSL_sk_value(stack, 0)
        return ctypes.string_at(
            LIBRARY.CRYPTO_BUFFER_data(leaf), LIBRARY.CRYPTO_BUFFER_len(leaf)
        )

    def getpeerchain(self) -> tuple[bytes, ...]:
        stack = LIBRARY.SSL_get0_peer_certificates(self._handle)
        if stack is None:
            return ()
        return tuple(
            ctypes.string_at(
                LIBRARY.CRYPTO_BUFFER_data(item), LIBRARY.CRYPTO_BUFFER_len(item)
            )
            for item in (
                LIBRARY.OPENSSL_sk_value(stack, index)
                for index in range(LIBRARY.OPENSSL_sk_num(stack))
            )
        )

    def _read_into(self, storage: ctypes.Array[ctypes.c_char]) -> int:
        size = len(storage)
        if not size:
            return 0
        handle = self._handle
        total = self._operate(lambda: LIBRARY.SSL_read(handle, storage, size), "read")
        # one SSL_read returns a single record; the records already in the memory BIO or in the kernel follow in
        # the same call. An attached socket is always non-blocking, so BoringSSL answers with WANT_READ, never a block
        while 0 < total < size:
            rest = (ctypes.c_char * (size - total)).from_buffer(storage, total)
            more = LIBRARY.SSL_read(handle, rest, size - total)
            if more <= 0:
                break
            total += more
        return total

    def _operate(self, call: Callable[[], int], operation: str) -> int:
        LIBRARY.ERR_clear_error()
        result = call()
        if result > 0:
            return result
        failure = self._failure(result, operation)
        if failure is None:
            return 0
        raise failure

    def _failure(self, result: int, operation: str) -> Exception | None:
        code = LIBRARY.SSL_get_error(self._handle, result)
        reasons = LIBRARY.errors()
        match code:
            case SSLErrorCode.WANT_READ:
                return WantReadError(f"{operation} needs more data from the peer")
            case SSLErrorCode.WANT_WRITE:
                return WantWriteError(f"{operation} needs the outgoing buffer drained")
            case SSLErrorCode.ZERO_RETURN:
                return None
            case SSLErrorCode.EARLY_DATA_REJECTED:
                return EarlyDataRejected(
                    f"{operation}: the server declined the early data"
                )
            case SSLErrorCode.SSL:
                verdict = LIBRARY.SSL_get_verify_result(self._handle)
                if verdict != X509_V_OK:
                    return CertificateVerificationError(
                        operation,
                        reasons,
                        LIBRARY.X509_verify_cert_error_string(verdict).decode("ascii"),
                    )
                return BoringSSLError(operation, reasons)
            case SSLErrorCode.SYSCALL:
                # end of stream, a reset or a timeout on the socket: the connection is gone either way
                return RaggedEOF(
                    f"{operation}: the connection ended without close_notify{': ' + '; '.join(reasons) if reasons else ''}"
                )
            case _:
                return BoringSSLError(operation, (f"SSL_get_error={code}", *reasons))
