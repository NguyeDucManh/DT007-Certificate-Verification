"""SSRF/deadline/size/redirect transport tests; no Internet required."""
import socket
import time
from unittest.mock import MagicMock
import pytest
import src.revocation_network as network


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com/x", "http://user:pass@example.com", "http://example.com:8080", "https://example.com/#x", "http://example.com/\nX", "http://example.com\\x"])
def test_reject_unsafe_url(url):
    with pytest.raises(network.FetchError):
        network.validate_destination(url, time.monotonic()+1)


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "192.168.1.1", "0.0.0.0", "100.64.0.1", "224.0.0.1", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "2002:0808:0808::1"])
def test_private_dns_and_literals_rejected(monkeypatch, ip):
    monkeypatch.setattr(network, "_resolve", lambda *args: [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, 80))])
    with pytest.raises(network.FetchError):
        network.validate_destination("http://example.com/crl", time.monotonic()+1)


def setup_transport(monkeypatch, responses):
    """Inject transport only; production URL checks still execute."""
    calls = []
    monkeypatch.setattr(network, "_resolve", lambda *args: [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 80))])
    sock = MagicMock()
    monkeypatch.setattr(network.socket, "socket", lambda *args: sock)
    def conn(*args, **kwargs):
        connection = MagicMock()
        connection.getresponse.return_value = responses.pop(0)
        calls.append(connection)
        return connection
    monkeypatch.setattr(network.http.client, "HTTPConnection", conn)
    return sock, calls


def response(status=200, headers=None, chunks=(b"abc", b"")):
    value = MagicMock(status=status)
    value.getheader.side_effect = lambda k, default=None: (headers or {}).get(k, default)
    value.read1.side_effect = chunks
    return value


def test_pinned_ip_and_no_proxy(monkeypatch):
    sock, calls = setup_transport(monkeypatch, [response()])
    assert network.fetch_bytes("http://example.com/crl") == b"abc"
    sock.connect.assert_called_once_with(("8.8.8.8", 80))
    assert calls[0].request.call_args.args[0] == "GET"


@pytest.mark.parametrize("headers,chunks", [({"Content-Length": "999"}, ()), ({"Content-Encoding": "gzip"}, ()), ({}, (b"12345",)), ({"Content-Length": "3"}, (b"a", b""))])
def test_size_compression_and_truncation(monkeypatch, headers, chunks):
    setup_transport(monkeypatch, [response(headers=headers, chunks=chunks)])
    with pytest.raises(network.FetchError):
        network.fetch_bytes("http://example.com/crl", policy=network.FetchPolicy(max_bytes=4))


def test_redirect_is_rechecked_for_ssrf(monkeypatch):
    sock, _ = setup_transport(monkeypatch, [response(302, {"Location": "http://127.0.0.1/crl"})])
    resolver = network._resolve
    monkeypatch.setattr(network, "_resolve", lambda host, *args: [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 80))] if host == "127.0.0.1" else resolver(host, *args))
    with pytest.raises(network.FetchError):
        network.fetch_bytes("http://example.com/crl")
    assert sock.connect.call_count == 1


def test_redirect_limit(monkeypatch):
    setup_transport(monkeypatch, [response(302, {"Location": "/again"})])
    with pytest.raises(network.FetchError):
        network.fetch_bytes("http://example.com/crl", policy=network.FetchPolicy(max_redirects=0))


def test_dns_timeout(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: time.sleep(.1) or [])
    with pytest.raises(network.FetchError, match="DNS"):
        network.validate_destination("http://example.com", time.monotonic()+.01)


def test_expired_deadline_and_policy():
    with pytest.raises(network.FetchError):
        network._remaining(time.monotonic()-1)
    with pytest.raises(ValueError):
        network.FetchPolicy(timeout=float("nan"))


def test_mixed_dns_answer_rejected(monkeypatch):
    monkeypatch.setattr(network, "_resolve", lambda *a: [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, 80)) for ip in ("8.8.8.8", "10.0.0.1")])
    with pytest.raises(network.FetchError):
        network.validate_destination("http://example.com", time.monotonic()+1)


def test_https_verification_and_post(monkeypatch):
    sock, calls = setup_transport(monkeypatch, [response()])
    context = MagicMock()
    context.wrap_socket.return_value = sock
    monkeypatch.setattr(network.ssl, "create_default_context", lambda: context)
    assert network.fetch_bytes("https://example.com/ocsp", body=b"request") == b"abc"
    context.wrap_socket.assert_called_once_with(sock, server_hostname="example.com")
    assert calls[0].request.call_args.args[0] == "POST"
    assert calls[0].request.call_args.kwargs["body"] == b"request"


def test_https_downgrade_rejected(monkeypatch):
    sock, _ = setup_transport(monkeypatch, [response(302, {"Location": "http://example.com/crl"})])
    context = MagicMock()
    context.wrap_socket.return_value = sock
    monkeypatch.setattr(network.ssl, "create_default_context", lambda: context)
    with pytest.raises(network.FetchError):
        network.fetch_bytes("https://example.com/crl")


def test_streaming_deadline_is_enforced(monkeypatch):
    value = response()
    def slow(_):
        time.sleep(.02)
        return b"a"
    value.read1.side_effect = slow
    setup_transport(monkeypatch, [value])
    with pytest.raises(network.FetchError, match="thời gian"):
        network.fetch_bytes("http://example.com/crl", policy=network.FetchPolicy(timeout=.01))
