"""Protocol regressions for the isolated UI evidence harness, no browser required."""
import base64
import hashlib
import pytest
from experiments.browser_smoke import CDP


class HandshakeSocket:
    def __init__(self, status, bad_accept=False):
        self.status, self.bad_accept, self.response = status, bad_accept, b""
    def sendall(self, request):
        key = request.split(b"Sec-WebSocket-Key: ")[1].split(b"\r\n")[0]
        accept = base64.b64encode(hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
        self.response = b"HTTP/1.1 " + self.status + b"\r\nSec-WebSocket-Accept: " + (b"wrong" if self.bad_accept else accept) + b"\r\n\r\n"
    def recv(self, size):
        value, self.response = self.response[:size], self.response[size:]
        return value


@pytest.mark.parametrize("status", [b"101 Switching Protocols", b"101 WebSocket Protocol Handshake"])
def test_reason_phrase_does_not_change_valid_upgrade(monkeypatch, status):
    transport = HandshakeSocket(status)
    monkeypatch.setattr("experiments.browser_smoke.socket.create_connection", lambda *a, **k: transport)
    assert CDP("ws://127.0.0.1:12345/devtools/page/test").sequence == 0


@pytest.mark.parametrize("url", ["ws://example.com:123/test", "wss://127.0.0.1:123/test", "ws://localhost:123/test"])
def test_transport_refuses_non_loopback_targets(url):
    with pytest.raises(ValueError, match="loopback"):
        CDP(url)


@pytest.mark.parametrize("status,bad", [(b"403 Forbidden", False), (b"101 Switching Protocols", True)])
def test_invalid_upgrade_cannot_be_accepted(monkeypatch, status, bad):
    monkeypatch.setattr("experiments.browser_smoke.socket.create_connection", lambda *a, **k: HandshakeSocket(status, bad))
    with pytest.raises(ValueError, match="từ chối"):
        CDP("ws://127.0.0.1:12345/devtools/page/test")
