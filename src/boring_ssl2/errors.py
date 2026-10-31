from ssl2.errors import TLSError


class BoringSSLError(TLSError):
    def __init__(self, operation: str, reasons: tuple[str, ...]) -> None:
        super().__init__(f"{operation}: {'; '.join(reasons) or 'BoringSSL reported no reason'}")
        self.operation = operation
        self.reasons = reasons


class CertificateVerificationError(BoringSSLError):
    def __init__(self, operation: str, reasons: tuple[str, ...], verdict: str) -> None:
        super().__init__(operation, (*reasons, verdict))
        self.verdict = verdict
