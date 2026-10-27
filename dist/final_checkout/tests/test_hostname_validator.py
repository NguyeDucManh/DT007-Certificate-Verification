"""Kiểm tra SAN, wildcard một cấp, IP và IDNA."""

from collections.abc import Callable
import ipaddress

from cryptography import x509
import pytest

from src.hostname_validator import normalize_hostname, validate_hostname


def test_exact_hostname(certificate: x509.Certificate) -> None:
    result = validate_hostname(certificate, "example.com")
    assert result.status == "PASS" and result.san_count == 1
    assert result.requested_hostname == "example.com" and result.message


@pytest.mark.parametrize("hostname, status", [
    ("api.example.com", "PASS"), ("a.b.example.com", "FAIL"),
    ("example.com", "FAIL"), ("api.other.com", "FAIL"),
])
def test_wildcard(certificate_factory: Callable, hostname: str, status: str) -> None:
    cert = certificate_factory(san=[x509.DNSName("*.example.com")])
    assert validate_hostname(cert, hostname).status == status


def test_mismatch(certificate: x509.Certificate) -> None:
    assert validate_hostname(certificate, "other.test").status == "FAIL"


def test_case_insensitive(certificate_factory: Callable) -> None:
    cert = certificate_factory(san=[x509.DNSName("EXAMPLE.COM")])
    assert validate_hostname(cert, "ExAmPlE.cOm").status == "PASS"


def test_san_preferred_over_cn(certificate_factory: Callable) -> None:
    cert = certificate_factory(common_name="example.com", san=[x509.DNSName("other.test")])
    assert validate_hostname(cert, "example.com").status == "FAIL"


def test_missing_san(certificate_factory: Callable) -> None:
    result = validate_hostname(certificate_factory(include_san=False), "example.com")
    assert result.status == "FAIL" and result.san_count == 0
    assert "không có SAN" in result.message


@pytest.mark.parametrize("pattern", ["a*.example.com", "*.*.example.com", "*.com"])
def test_invalid_wildcard(certificate_factory: Callable, pattern: str) -> None:
    cert = certificate_factory(san=[x509.DNSName(pattern)])
    assert validate_hostname(cert, "api.example.com").status == "FAIL"


@pytest.mark.parametrize("address", ["192.0.2.1", "2001:db8::1"])
def test_ip_san(certificate_factory: Callable, address: str) -> None:
    cert = certificate_factory(san=[x509.IPAddress(ipaddress.ip_address(address))])
    assert validate_hostname(cert, address).status == "PASS"
    assert validate_hostname(cert, "192.0.2.2").status == "FAIL"


def test_ip_requires_ip_san(certificate_factory: Callable) -> None:
    cert = certificate_factory(san=[x509.DNSName("192.0.2.1")])
    assert validate_hostname(cert, "192.0.2.1").status == "FAIL"


def test_idna(certificate_factory: Callable) -> None:
    cert = certificate_factory(san=[x509.DNSName("xn--bcher-kva.example")])
    assert validate_hostname(cert, "bücher.example").status == "PASS"


def test_trailing_dot(certificate: x509.Certificate) -> None:
    assert validate_hostname(certificate, "example.com.").status == "PASS"


def test_invalid_requested_hostname(certificate: x509.Certificate) -> None:
    assert validate_hostname(certificate, "https://example.com").status == "FAIL"


def test_normalize_hostname() -> None:
    assert normalize_hostname("EXAMPLE.COM.") == "example.com"
    assert normalize_hostname("2001:0db8::1") == "2001:db8::1"
