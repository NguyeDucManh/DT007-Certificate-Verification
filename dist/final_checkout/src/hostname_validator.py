"""Kiểm tra danh tính DNS/IP trong SAN, không dựa vào Common Name."""

from dataclasses import dataclass
import ipaddress
import re

from cryptography import x509


@dataclass(frozen=True)
class HostnameResult:
    """Kết quả kiểm tra danh tính của một chứng thư."""

    status: str
    message: str
    requested_hostname: str
    san_count: int


def normalize_hostname(hostname: str) -> str:
    """Chuẩn hóa DNS bằng IDNA hoặc IP; từ chối URL, port và tên sai cú pháp."""
    if not isinstance(hostname, str) or not hostname or hostname != hostname.strip():
        raise ValueError("Hostname phải là tên DNS hoặc IP không rỗng, không chứa khoảng trắng.")
    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        pass
    try:
        name = hostname.removesuffix(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Hostname không thể chuyển sang IDNA.") from exc
    labels = name.split(".")
    if len(name) > 253 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("Hostname không hợp lệ; chỉ nhập tên DNS hoặc IP, không kèm URL/port.")
    return name


def matches_dns_name(hostname: str, pattern: str) -> bool:
    """Wildcard chỉ được là toàn bộ nhãn trái nhất và khớp đúng một cấp."""
    if pattern.startswith("*.") and pattern.count("*") == 1:
        try:
            suffix = normalize_hostname(pattern[2:])
        except ValueError:
            return False
        # Không chấp nhận wildcard quá rộng như *.com.
        if "." not in suffix:
            return False
        labels = hostname.split(".")
        return len(labels) == len(suffix.split(".")) + 1 and ".".join(labels[1:]) == suffix
    if "*" in pattern:
        return False
    try:
        return hostname == normalize_hostname(pattern)
    except ValueError:
        return False


def validate_hostname(certificate: x509.Certificate, hostname: str) -> HostnameResult:
    """So khớp SAN DNSName/IPAddress; SAN thiếu luôn FAIL, không fallback CN."""
    try:
        normalized = normalize_hostname(hostname)
    except ValueError as exc:
        return HostnameResult("FAIL", str(exc), hostname, 0)
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return HostnameResult("FAIL", "Certificate không có SAN; không sử dụng Common Name thay thế.", hostname, 0)
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        matched = any(matches_dns_name(normalized, name) for name in san.get_values_for_type(x509.DNSName))
    else:
        matched = address in san.get_values_for_type(x509.IPAddress)
    return HostnameResult(
        "PASS" if matched else "FAIL",
        "Hostname khớp SAN của certificate." if matched else "Hostname không khớp SAN của certificate.",
        hostname, len(san),
    )
