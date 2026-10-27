"""Kiểm tra DER/PEM và các trường metadata X.509."""

from collections.abc import Callable

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
import pytest

from src.certificate_parser import CertificateParseError, extract_certificate_info, parse_certificate


@pytest.mark.parametrize("encoding", [Encoding.DER, Encoding.PEM])
def test_parse_certificate(certificate: x509.Certificate, encoding: Encoding) -> None:
    assert parse_certificate(certificate.public_bytes(encoding)) == certificate


def test_pem_text(certificate: x509.Certificate) -> None:
    assert parse_certificate(certificate.public_bytes(Encoding.PEM).decode("ascii")) == certificate


def test_subject(certificate: x509.Certificate) -> None:
    assert extract_certificate_info(certificate).subject == "CN=example.com,O=DT007 Test"


def test_issuer(certificate: x509.Certificate) -> None:
    assert extract_certificate_info(certificate).issuer == "CN=example.com,O=DT007 Test"


def test_san(certificate: x509.Certificate) -> None:
    assert extract_certificate_info(certificate).san == (x509.DNSName("example.com"),)


def test_no_san(certificate_factory: Callable) -> None:
    assert extract_certificate_info(certificate_factory(include_san=False)).san == ()


def test_metadata_and_crypto(certificate: x509.Certificate) -> None:
    info = extract_certificate_info(certificate)
    assert info.serial_number == 123456 and info.version == "v3"
    assert info.not_before.utcoffset().total_seconds() == 0
    assert info.not_after.utcoffset().total_seconds() == 0
    assert info.crypto.public_key_algorithm == "RSA"
    assert info.crypto.public_key_size == 2048
    assert info.crypto.signature_algorithm_oid == "1.2.840.113549.1.1.11"
    assert info.crypto.signature_hash_algorithm == "sha256"


@pytest.mark.parametrize("data", [b"", b"bad DER", "not PEM", b"-----BEGIN CERTIFICATE-----\nbad\n-----END CERTIFICATE-----"])
def test_invalid_certificate(data: bytes | str) -> None:
    with pytest.raises(CertificateParseError):
        parse_certificate(data)
