import ctypes

from boring_ssl2.library import LIBRARY

NID_CRL_DISTRIBUTION_POINTS = 103
# tags inside the extension: SEQUENCE, the [0] distributionPoint and [0] fullName wrappers, the [6] uniformResourceIdentifier name
SEQUENCE = 0x30
CONTEXT_0 = 0xA0
URI = 0x86


class ParsedCertificate:
    def __init__(self, der: bytes) -> None:
        pointer = ctypes.c_char_p(der)
        handle = LIBRARY.d2i_X509(None, ctypes.byref(pointer), len(der))
        if handle is None:
            raise LIBRARY.error("d2i_X509")
        self._handle = handle

    def __del__(self) -> None:
        LIBRARY.X509_free(self._handle)

    @property
    def handle(self) -> int:
        return self._handle

    @property
    def serial(self) -> str:
        number = LIBRARY.X509_get0_serialNumber(self._handle)
        return ctypes.string_at(
            LIBRARY.ASN1_STRING_get0_data(number), LIBRARY.ASN1_STRING_length(number)
        ).hex()

    @property
    def crl_urls(self) -> tuple[str, ...]:
        position = LIBRARY.X509_get_ext_by_NID(
            self._handle, NID_CRL_DISTRIBUTION_POINTS, -1
        )
        if position < 0:
            return ()
        extension = LIBRARY.X509_get_ext(self._handle, position)
        if extension is None:
            raise LIBRARY.error("X509_get_ext")
        data = LIBRARY.X509_EXTENSION_get_data(extension)
        body = ctypes.string_at(
            LIBRARY.ASN1_STRING_get0_data(data), LIBRARY.ASN1_STRING_length(data)
        )
        urls: list[str] = []
        for _, point in self._elements(self._elements(body)[0][1]):
            for tag, name in self._elements(point):
                if tag != CONTEXT_0:
                    continue
                for inner_tag, names in self._elements(name):
                    if inner_tag != CONTEXT_0:
                        continue
                    urls.extend(
                        value.decode("ascii")
                        for name_tag, value in self._elements(names)
                        if name_tag == URI
                    )
        return tuple(urls)

    @staticmethod
    def _elements(data: bytes) -> list[tuple[int, bytes]]:
        elements: list[tuple[int, bytes]] = []
        offset = 0
        while offset < len(data):
            tag, length = data[offset], data[offset + 1]
            offset += 2
            if length & 0x80:
                count = length & 0x7F
                length = int.from_bytes(data[offset : offset + count], "big")
                offset += count
            elements.append((tag, data[offset : offset + length]))
            offset += length
        return elements


class CertificateRevocationList:
    def __init__(self, der: bytes) -> None:
        pointer = ctypes.c_char_p(der)
        handle = LIBRARY.d2i_X509_CRL(None, ctypes.byref(pointer), len(der))
        if handle is None:
            raise LIBRARY.error("d2i_X509_CRL")
        self._handle = handle

    def __del__(self) -> None:
        LIBRARY.X509_CRL_free(self._handle)

    @property
    def current(self) -> bool:
        next_update = LIBRARY.X509_CRL_get0_nextUpdate(self._handle)
        return next_update is None or LIBRARY.X509_cmp_current_time(next_update) > 0

    def signed_by(self, issuer: ParsedCertificate) -> bool:
        if (
            LIBRARY.X509_NAME_cmp(
                LIBRARY.X509_CRL_get_issuer(self._handle),
                LIBRARY.X509_get_subject_name(issuer.handle),
            )
            != 0
        ):
            return False
        key = LIBRARY.X509_get_pubkey(issuer.handle)
        if key is None:
            raise LIBRARY.error("X509_get_pubkey")
        verdict = LIBRARY.X509_CRL_verify(self._handle, key)
        LIBRARY.EVP_PKEY_free(key)
        LIBRARY.ERR_clear_error()
        return verdict == 1

    def revokes(self, certificate: ParsedCertificate) -> bool:
        entry = ctypes.c_void_p()
        return (
            LIBRARY.X509_CRL_get0_by_cert(
                self._handle, ctypes.byref(entry), certificate.handle
            )
            == 1
        )
