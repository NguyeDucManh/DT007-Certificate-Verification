"""Kiểm tra TLS fetching bằng mocks; không truy cập mạng."""

import socket
import ssl
from unittest.mock import MagicMock

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
import pytest

from src.certificate_fetcher import CertificateFetchError, der_to_pem, fetch_certificate, fetch_peer_chain


@pytest.mark.parametrize("hostname", ["", "https://example.com", "bad host", "example.com:443", "-invalid.test", "a..com"])
def test_invalid_hostname(hostname: str, monkeypatch: pytest.MonkeyPatch) -> None:
    connection = MagicMock()
    monkeypatch.setattr("src.certificate_fetcher.socket.create_connection", connection)
    with pytest.raises(CertificateFetchError, match="Hostname"):
        fetch_certificate(hostname)
    connection.assert_not_called()


@pytest.mark.parametrize("error, message", [
    (socket.gaierror("unknown host"), "Không phân giải"),
    (TimeoutError("timed out"), "hết thời gian chờ"),
    (ConnectionRefusedError("refused"), "từ chối"),
    (ConnectionResetError("reset"), "Không thể kết nối"),
])
def test_connection_errors(error: OSError, message: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.certificate_fetcher.socket.create_connection", MagicMock(side_effect=error))
    with pytest.raises(CertificateFetchError, match=message):
        fetch_certificate("example.com")


@pytest.fixture
def tls_mocks(monkeypatch: pytest.MonkeyPatch) -> tuple[MagicMock, MagicMock, MagicMock]:
    connection = MagicMock()
    context = MagicMock()
    create_context = MagicMock(return_value=context)
    monkeypatch.setattr("src.certificate_fetcher.socket.create_connection", connection)
    monkeypatch.setattr("src.certificate_fetcher.ssl.create_default_context", create_context)
    return connection, context, create_context


def test_successful_fetch(certificate: x509.Certificate, tls_mocks: tuple) -> None:
    connection, context, create_context = tls_mocks
    der = certificate.public_bytes(Encoding.DER)
    tls = context.wrap_socket.return_value.__enter__.return_value
    tls.getpeercert.return_value = der
    assert fetch_certificate("EXAMPLE.COM", 8443, 3.0) == der
    create_context.assert_called_once_with()
    connection.assert_called_once_with(("example.com", 8443), timeout=3.0)
    context.wrap_socket.assert_called_once_with(connection.return_value.__enter__.return_value, server_hostname="example.com")
    tls.getpeercert.assert_called_once_with(binary_form=True)
    assert context.hostname_checks_common_name is False
    connection.return_value.__exit__.assert_called_once()
    context.wrap_socket.return_value.__exit__.assert_called_once()


@pytest.mark.parametrize("error, message", [
    (ssl.SSLError("handshake failed"), "TLS handshake"),
    (ssl.SSLCertVerificationError("untrusted"), "Xác minh certificate TLS"),
    (TimeoutError("handshake timeout"), "hết thời gian chờ"),
])
def test_handshake_errors(error: OSError, message: str, tls_mocks: tuple) -> None:
    connection, context, _ = tls_mocks
    context.wrap_socket.side_effect = error
    with pytest.raises(CertificateFetchError, match=message):
        fetch_certificate("example.com")
    connection.return_value.__exit__.assert_called_once()


def test_secure_context(monkeypatch: pytest.MonkeyPatch) -> None:
    original = ssl.create_default_context
    contexts: list[ssl.SSLContext] = []
    def record_context() -> ssl.SSLContext:
        context = original()
        contexts.append(context)
        return context
    monkeypatch.setattr("src.certificate_fetcher.ssl.create_default_context", record_context)
    monkeypatch.setattr("src.certificate_fetcher.socket.create_connection", MagicMock(side_effect=ConnectionRefusedError()))
    with pytest.raises(CertificateFetchError):
        fetch_certificate("example.com")
    assert contexts[0].verify_mode == ssl.CERT_REQUIRED
    assert contexts[0].check_hostname is True
    assert contexts[0].hostname_checks_common_name is False


def test_missing_peer_certificate(tls_mocks: tuple) -> None:
    _, context, _ = tls_mocks
    context.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = None
    with pytest.raises(CertificateFetchError, match="không cung cấp"):
        fetch_certificate("example.com")


@pytest.mark.parametrize("port", [0, 65536, True])
def test_invalid_port(port: int) -> None:
    with pytest.raises(CertificateFetchError, match="Port"):
        fetch_certificate("example.com", port=port)


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"), True])
def test_invalid_timeout(timeout: float) -> None:
    with pytest.raises(CertificateFetchError, match="Timeout"):
        fetch_certificate("example.com", timeout=timeout)


def test_der_to_pem(certificate: x509.Certificate) -> None:
    pem = der_to_pem(certificate.public_bytes(Encoding.DER))
    assert pem.startswith("-----BEGIN CERTIFICATE-----")
    assert x509.load_pem_x509_certificate(pem.encode("ascii")) == certificate


def test_invalid_der() -> None:
    with pytest.raises(ValueError, match="DER không hợp lệ"):
        der_to_pem(b"invalid")


def test_peer_chain(certificate: x509.Certificate, tls_mocks: tuple) -> None:
    _, context, _ = tls_mocks
    der = certificate.public_bytes(Encoding.DER)
    tls = context.wrap_socket.return_value.__enter__.return_value
    tls.getpeercert.return_value = der
    tls.get_verified_chain.return_value = [der]
    context.get_ca_certs.return_value = [b"independent anchor DER"]
    result = fetch_peer_chain("example.com")
    assert result.leaf_der == der and result.chain_der == (der,)
    assert result.trust_anchors_der == (b"independent anchor DER",)
    context.get_ca_certs.assert_called_once_with(binary_form=True)


def test_peer_chain_must_match_leaf(certificate: x509.Certificate, tls_mocks: tuple) -> None:
    _, context, _ = tls_mocks
    tls = context.wrap_socket.return_value.__enter__.return_value
    tls.getpeercert.return_value = certificate.public_bytes(Encoding.DER)
    tls.get_verified_chain.return_value = [b"different leaf"]
    with pytest.raises(CertificateFetchError, match="không khớp"):
        fetch_peer_chain("example.com")
