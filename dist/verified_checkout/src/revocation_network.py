"""Bounded HTTP transport for untrusted certificate URLs; no environment proxies."""
from __future__ import annotations

from dataclasses import dataclass
import http.client
import ipaddress
import math
import queue
import socket
import ssl
import threading
import time
from urllib.parse import urljoin, urlsplit


class FetchError(ValueError):
    """URL, network or response violates the download policy."""


@dataclass(frozen=True)
class FetchPolicy:
    """A total deadline includes DNS, redirects and streaming response bytes."""
    timeout: float = 8.0
    max_bytes: int = 2 * 1024 * 1024
    max_redirects: int = 2

    def __post_init__(self) -> None:
        if not math.isfinite(self.timeout) or not 0 < self.timeout <= 60:
            raise ValueError("Timeout phải nằm trong (0, 60] giây.")
        if not 0 < self.max_bytes <= 16 * 1024 * 1024 or not 0 <= self.max_redirects <= 3:
            raise ValueError("Giới hạn tải không hợp lệ.")


_DNS_SLOTS = threading.BoundedSemaphore(4)


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise FetchError("Hết thời gian tải dữ liệu thu hồi.")
    return remaining


def _resolve(host: str, port: int, deadline: float) -> list[tuple]:
    """Bound concurrent DNS workers and return without waiting past the deadline."""
    if not _DNS_SLOTS.acquire(blocking=False):
        raise FetchError("Đang có quá nhiều truy vấn DNS.")
    result: queue.Queue = queue.Queue(maxsize=1)

    def worker() -> None:
        try:
            result.put(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        except Exception as exc:
            result.put(exc)
        finally:
            _DNS_SLOTS.release()

    threading.Thread(target=worker, daemon=True).start()
    try:
        answer = result.get(timeout=_remaining(deadline))
    except queue.Empty as exc:
        raise FetchError("DNS vượt quá thời gian cho phép.") from exc
    if isinstance(answer, Exception):
        raise FetchError("Không phân giải được địa chỉ nguồn thu hồi.") from answer
    return answer


def validate_destination(url: str, deadline: float) -> tuple[str, str, int, str, list[tuple]]:
    """Reject credentials/non-public IPs and pin the validated DNS results."""
    if len(url) > 4096 or any(ord(c) <= 32 or ord(c) == 127 for c in url) or "\\" in url:
        raise FetchError("URL nguồn thu hồi không hợp lệ.")
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise ValueError("URL")
        host = parsed.hostname.encode("idna").decode("ascii")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if port != (443 if parsed.scheme == "https" else 80):
            raise ValueError("port")
    except (ValueError, UnicodeError) as exc:
        raise FetchError("Chỉ cho phép HTTP/HTTPS công khai trên cổng mặc định.") from exc
    addresses = _resolve(host, port, deadline)
    if not addresses:
        raise FetchError("DNS không trả địa chỉ.")
    for _, _, _, _, address in addresses:
        ip = ipaddress.ip_address(address[0])
        # Reject transition mechanisms, including IPv4-mapped and 6to4/Teredo.
        if not ip.is_global or ip.is_multicast or ip.is_reserved or (ip.version == 6 and (ip.ipv4_mapped or ip.sixtofour or ip.teredo)):
            raise FetchError("Chặn truy cập địa chỉ nội bộ hoặc đích mạng không được phép.")
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return parsed.scheme, host, port, path, addresses


def fetch_bytes(url: str, *, body: bytes | None = None, policy: FetchPolicy = FetchPolicy()) -> bytes:
    """GET CRL or POST OCSP; pin IP, verify HTTPS and bound all redirects/data."""
    deadline = time.monotonic() + policy.timeout
    try:
        for redirect in range(policy.max_redirects + 1):
            scheme, host, port, path, addresses = validate_destination(url, deadline)
            family, kind, proto, _, address = addresses[0]
            raw = socket.socket(family, kind, proto)
            connection = http.client.HTTPConnection(host, port, timeout=_remaining(deadline))
            close_connection = connection.close
            response = None
            try:
                raw.settimeout(_remaining(deadline))
                raw.connect(address)  # numeric sockaddr, no second DNS resolution
                if scheme == "https":
                    raw.settimeout(_remaining(deadline))
                    raw = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
                connection.sock = raw
                headers = {"Accept-Encoding": "identity", "Accept": "application/ocsp-response" if body is not None else "application/pkix-crl"}
                if body is not None:
                    headers["Content-Type"] = "application/ocsp-request"
                connection.request("POST" if body is not None else "GET", path, body=body, headers=headers)
                raw.settimeout(_remaining(deadline))
                # HTTP/1.0 / Connection: close normally closes the socket in
                # getresponse(), before bounded streaming can adjust its timeout
                # (WinError 10038). Defer closure until the response is consumed.
                connection.close = lambda: None
                response = connection.getresponse()
                if response.status in (301, 302, 303, 307, 308):
                    location = response.getheader("Location")
                    if not location or redirect == policy.max_redirects or (scheme == "https" and urlsplit(urljoin(url, location)).scheme != "https"):
                        raise FetchError("Redirect không được phép hoặc vượt giới hạn.")
                    url = urljoin(url, location)
                    continue  # retain OCSP POST body, validate every new target
                if response.status != 200:
                    raise FetchError(f"Nguồn thu hồi trả HTTP {response.status}.")
                if response.getheader("Content-Encoding", "identity").lower() != "identity":
                    raise FetchError("Không nhận dữ liệu nén từ nguồn thu hồi.")
                length = response.getheader("Content-Length")
                if length is not None and (not length.isdigit() or int(length) > policy.max_bytes):
                    raise FetchError("Kích thước phản hồi vượt giới hạn hoặc không hợp lệ.")
                data = bytearray()
                while True:
                    raw.settimeout(_remaining(deadline))
                    chunk = response.read1(min(65536, policy.max_bytes + 1 - len(data)))
                    if not chunk:
                        if length is not None and len(data) != int(length):
                            raise FetchError("Phản hồi bị cắt ngắn.")
                        return bytes(data)
                    data.extend(chunk)
                    if len(data) > policy.max_bytes:
                        raise FetchError("Kích thước phản hồi vượt giới hạn.")
            finally:
                if response is not None:
                    response.close()
                close_connection()
                raw.close()
    except FetchError:
        raise
    except (OSError, ValueError, http.client.HTTPException) as exc:
        raise FetchError("Không tải được dữ liệu thu hồi: " + str(exc)) from exc
    raise FetchError("Không tải được dữ liệu thu hồi.")
