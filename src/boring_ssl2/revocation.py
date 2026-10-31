import ctypes
from enum import IntEnum

from ssl2.errors import ParseError

from boring_ssl2.library import Library


class Nid(IntEnum):
    CRL_DISTRIBUTION_POINTS = 103


class DerTag(IntEnum):
    # the tags inside a CRLDistributionPoints extension, RFC 5280 section 4.2.1.13
    SEQUENCE = 0x30
    CONTEXT_0 = 0xA0
    UNIFORM_RESOURCE_IDENTIFIER = 0x86


class DerLength(IntEnum):
    LONG_FORM = 0x80
    COUNT_MASK = 0x7F


class DerReader:
    # reads the tag, length, value triplets of a DER sequence, with definite lengths only
    @classmethod
    def elements(cls, data: bytes) -> list[tuple[int, bytes]]:
        elements: list[tuple[int, bytes]] = []
        offset = 0
        while offset < len(data):
            if offset + 2 > len(data):
                raise ParseError(f"DER element header cut off at offset {offset}")
            tag, length = data[offset], data[offset + 1]
            offset += 2
            if length & DerLength.LONG_FORM:
                count = length & DerLength.COUNT_MASK
                if offset + count > len(data):
                    raise ParseError(f"DER length of {count} bytes cut off at offset {offset}")
                length = int.from_bytes(data[offset : offset + count], "big")
                offset += count
            if offset + length > len(data):
                raise ParseError(f"DER element of {length} bytes cut off at offset {offset}")
            elements.append((tag, data[offset : offset + length]))
            offset += length
        return elements


class ParsedCertificate:
    def __init__(self, der: bytes, library: Library | None = None) -> None:
        self.library = library or Library.default()
        pointer = ctypes.c_char_p(der)
        handle = self.library.d2i_X509(None, ctypes.byref(pointer), len(der))
        if handle is None:
            raise self.library.error("d2i_X509")
        self._handle = handle

    def __del__(self) -> None:
        self.library.X509_free(self._handle)

    @property
    def handle(self) -> int:
        return self._handle

    @property
    def serial(self) -> str:
        number = self.library.X509_get0_serialNumber(self._handle)
        return self._asn1_string(number).hex()

    @property
    def crl_urls(self) -> tuple[str, ...]:
        # every uniformResourceIdentifier of every fullName in the CRLDistributionPoints extension
        library = self.library
        position = library.X509_get_ext_by_NID(self._handle, Nid.CRL_DISTRIBUTION_POINTS, -1)
        if position < 0:
            return ()
        extension = library.X509_get_ext(self._handle, position)
        if extension is None:
            raise library.error("X509_get_ext")
        body = self._asn1_string(library.X509_EXTENSION_get_data(extension))
        urls: list[str] = []
        for _, point in DerReader.elements(DerReader.elements(body)[0][1]):
            for tag, name in DerReader.elements(point):
                if tag != DerTag.CONTEXT_0:
                    continue
                for inner_tag, names in DerReader.elements(name):
                    if inner_tag != DerTag.CONTEXT_0:
                        continue
                    urls.extend(
                        value.decode("ascii")
                        for name_tag, value in DerReader.elements(names)
                        if name_tag == DerTag.UNIFORM_RESOURCE_IDENTIFIER
                    )
        return tuple(urls)

    def _asn1_string(self, string: int) -> bytes:
        return ctypes.string_at(self.library.ASN1_STRING_get0_data(string), self.library.ASN1_STRING_length(string))


class CertificateRevocationList:
    def __init__(self, der: bytes, library: Library | None = None) -> None:
        self.library = library or Library.default()
        pointer = ctypes.c_char_p(der)
        handle = self.library.d2i_X509_CRL(None, ctypes.byref(pointer), len(der))
        if handle is None:
            raise self.library.error("d2i_X509_CRL")
        self._handle = handle

    def __del__(self) -> None:
        self.library.X509_CRL_free(self._handle)

    @property
    def current(self) -> bool:
        next_update = self.library.X509_CRL_get0_nextUpdate(self._handle)
        return next_update is None or self.library.X509_cmp_current_time(next_update) > 0

    def signed_by(self, issuer: ParsedCertificate) -> bool:
        library = self.library
        if (
            library.X509_NAME_cmp(
                library.X509_CRL_get_issuer(self._handle), library.X509_get_subject_name(issuer.handle)
            )
            != 0
        ):
            return False
        key = library.X509_get_pubkey(issuer.handle)
        if key is None:
            raise library.error("X509_get_pubkey")
        verdict = library.X509_CRL_verify(self._handle, key)
        library.EVP_PKEY_free(key)
        library.ERR_clear_error()
        return verdict == 1

    def revokes(self, certificate: ParsedCertificate) -> bool:
        entry = ctypes.c_void_p()
        return self.library.X509_CRL_get0_by_cert(self._handle, ctypes.byref(entry), certificate.handle) == 1
