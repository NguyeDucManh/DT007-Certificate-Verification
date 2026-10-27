"""Lấy leaf certificate qua kết nối TLS có xác minh bằng socket + ssl."""

import math
from dataclasses import dataclass
import socket
import ssl

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from src.hostname_validator import normalize_hostname


class CertificateFetchError(RuntimeError):
    """Lỗi kết nối hoặc TLS có thông báo dễ hiểu cho CLI."""


@dataclass(frozen=True)
class TLSCertificates:
    """Chain DER do TLS xác minh và CA DER từ trust store độc lập."""

    leaf_der: bytes
    chain_der: tuple[bytes, ...]
    trust_anchors_der: tuple[bytes, ...]
    peer_chain_der: tuple[bytes, ...] | None = None


def _fetch_tls(hostname: str, port: int, timeout: float, include_chain: bool) -> bytes | TLSCertificates:
    """Lấy DER của leaf cert; luôn giữ CA verification và hostname verification.

    Timeout áp dụng cho thao tác socket và TLS handshake; DNS sử dụng resolver
    hệ điều hành nên không được đảm bảo kết thúc trong cùng thời hạn này.
    """
    try:
        hostname = normalize_hostname(hostname)
    except ValueError as exc:
        raise CertificateFetchError(str(exc)) from exc
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise CertificateFetchError("Port phải là số nguyên từ 1 đến 65535.")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise CertificateFetchError("Timeout phải là số giây hữu hạn lớn hơn 0.")
    target = f"{hostname}:{port}"
    try:
        context = ssl.create_default_context()
        context.hostname_checks_common_name = False
        with socket.create_connection((hostname, port), timeout=timeout) as connection:
            with context.wrap_socket(connection, server_hostname=hostname) as tls:
                certificate = tls.getpeercert(binary_form=True)
                if not certificate:
                    raise CertificateFetchError(f"Máy chủ {target} không cung cấp certificate.")
                if include_chain:
                    chain = tuple(tls.get_verified_chain())
                    if not chain or chain[0] != certificate:
                        raise CertificateFetchError("TLS verified chain thiếu leaf hoặc không khớp certificate.")
                    return TLSCertificates(certificate, chain, tuple(context.get_ca_certs(binary_form=True)),
                                           tuple(tls.get_unverified_chain()))
                return certificate
    except socket.gaierror as exc:
        raise CertificateFetchError(f"Không phân giải được hostname {hostname}: {exc}") from exc
    except TimeoutError as exc:
        raise CertificateFetchError(f"Kết nối/TLS tới {target} hết thời gian chờ ({timeout} giây).") from exc
    except ConnectionRefusedError as exc:
        raise CertificateFetchError(f"Máy chủ {target} từ chối kết nối.") from exc
    except ssl.SSLCertVerificationError as exc:
        raise CertificateFetchError(f"Xác minh certificate TLS của {target} thất bại: {exc}") from exc
    except ssl.SSLError as exc:
        raise CertificateFetchError(f"TLS handshake với {target} thất bại: {exc}") from exc
    except OSError as exc:
        raise CertificateFetchError(f"Không thể kết nối tới {target}: {exc}") from exc


def fetch_certificate(hostname: str, port: int = 443, timeout: float = 10.0) -> bytes:
    """API 2A: lấy DER leaf qua TLS có xác minh, giữ nguyên hành vi cũ."""
    result = _fetch_tls(hostname, port, timeout, include_chain=False)
    assert isinstance(result, bytes)
    return result


def fetch_peer_chain(hostname: str, port: int = 443, timeout: float = 10.0) -> TLSCertificates:
    """API 2B: lấy chain và trust store trong cùng một TLS session đã xác minh."""
    result = _fetch_tls(hostname, port, timeout, include_chain=True)
    assert isinstance(result, TLSCertificates)
    return result


def der_to_pem(certificate_der: bytes) -> str:
    """Chuyển DER hợp lệ sang PEM ASCII; từ chối DER không phải certificate."""
    try:
        return x509.load_der_x509_certificate(certificate_der).public_bytes(Encoding.PEM).decode("ascii")
    except ValueError as exc:
        raise ValueError("Không thể chuyển DER sang PEM: certificate DER không hợp lệ.") from exc
