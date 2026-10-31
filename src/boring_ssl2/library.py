import logging
from pathlib import Path
from typing import ClassVar

from boring_ssl2.crypto_functions import CryptoFunctions
from boring_ssl2.ssl_functions import SslFunctions
from boring_ssl2.x509_functions import X509Functions


class Library(SslFunctions, X509Functions, CryptoFunctions):
    # one loaded BoringSSL build: the bundled one by default, or the caller's own at the path given
    logger = logging.getLogger("boring_ssl2")
    _default: ClassVar[Library | None] = None

    def __init__(self, path: Path | str | None = None) -> None:
        super().__init__(path)
        self.logger.info("library.loaded path=%s revision=%s", self.path, self.source_revision)

    @classmethod
    def default(cls) -> Library:
        if cls._default is None:
            cls._default = cls()
        return cls._default

    @property
    def source_revision(self) -> str:
        return self.boring_ssl_source_revision().decode("ascii")

    def check(self, accepted: int, operation: str) -> None:
        # BoringSSL answers one for success on the calls this covers
        if accepted != 1:
            raise self.error(operation)
