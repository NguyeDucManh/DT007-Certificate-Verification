"""Parse DER/PEM và trích xuất thông tin X.509 bằng cryptography."""

from dataclasses import dataclass
from datetime import datetime

from cryptography import x509

from src.crypto_info import CryptoInfo, get_crypto_info


class CertificateParseError(ValueError):
    """Nội dung certificate không parse được."""


@dataclass(frozen=True)
class CertificateInfo:
    """Metadata certificate; các ngày luôn có timezone UTC."""

    subject: str
    issuer: str
    serial_number: int
    version: str
    not_before: datetime
    not_after: datetime
    san: tuple[x509.GeneralName, ...]
    crypto: CryptoInfo


def parse_certificate(data: bytes | str) -> x509.Certificate:
    """Nhận DER bytes hoặc PEM bytes/text; trả x509.Certificate."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    if not isinstance(data, bytes) or not data:
        raise CertificateParseError("Certificate DER/PEM phải là bytes hoặc PEM text không rỗng.")
    try:
        if data.lstrip().startswith(b"-----BEGIN CERTIFICATE-----"):
            return x509.load_pem_x509_certificate(data)
        return x509.load_der_x509_certificate(data)
    except ValueError as exc:
        raise CertificateParseError("Certificate DER/PEM không hợp lệ hoặc bị thiếu nội dung.") from exc


def extract_certificate_info(certificate: x509.Certificate) -> CertificateInfo:
    """Trích xuất Subject, Issuer, SAN và crypto; SAN thiếu trả tuple rỗng."""
    try:
        san = tuple(certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
    except x509.ExtensionNotFound:
        san = ()
    return CertificateInfo(
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        serial_number=certificate.serial_number,
        version=certificate.version.name,
        not_before=certificate.not_valid_before_utc,
        not_after=certificate.not_valid_after_utc,
        san=san, crypto=get_crypto_info(certificate),
    )
