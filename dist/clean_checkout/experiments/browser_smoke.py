"""Real Edge headless UI checks using loopback CDP and the Python standard library."""
from __future__ import annotations
import base64
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
from threading import Thread
import time
from urllib.parse import urlparse
import uuid
import requests
from werkzeug.serving import make_server

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from app import create_app


class CDP:
    """Minimal masked WebSocket transport, restricted to a local browser target."""
    def __init__(self, url: str):
        target = urlparse(url)
        if target.scheme != "ws" or target.hostname != "127.0.0.1":
            raise ValueError("CDP chỉ kết nối loopback")
        self.socket = socket.create_connection((target.hostname, target.port), timeout=15)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        self.socket.sendall((f"GET {target.path} HTTP/1.1\r\nHost: 127.0.0.1:{target.port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode("ascii"))
        buffer = b""
        while b"\r\n\r\n" not in buffer:
            chunk = self.socket.recv(4096)
            if not chunk:
                raise ConnectionError("Browser closed during handshake")
            buffer += chunk
            if len(buffer) > 16384:
                raise ValueError("Invalid WebSocket handshake")
        header, self.buffer = buffer.split(b"\r\n\r\n", 1)
        accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest())
        if header.splitlines()[0].split()[1] != b"101" or accept not in header:
            raise ValueError("WebSocket handshake bị từ chối")
        self.sequence = 0

    def read(self, size: int) -> bytes:
        while len(self.buffer) < size:
            chunk = self.socket.recv(max(4096, size - len(self.buffer)))
            if not chunk:
                raise ConnectionError("Browser closed CDP")
            self.buffer += chunk
        value, self.buffer = self.buffer[:size], self.buffer[size:]
        return value

    def send(self, payload: bytes, opcode: int = 1) -> None:
        length, mask = len(payload), os.urandom(4)
        length_bytes = bytes([128 | length]) if length < 126 else bytes([254]) + struct.pack("!H", length) if length < 65536 else bytes([255]) + struct.pack("!Q", length)
        self.socket.sendall(bytes([128 | opcode]) + length_bytes + mask + bytes(v ^ mask[i % 4] for i, v in enumerate(payload)))

    def receive(self) -> dict:
        payload = b""
        while True:
            first, second = self.read(2)
            size = second & 127
            size = struct.unpack("!H", self.read(2))[0] if size == 126 else struct.unpack("!Q", self.read(8))[0] if size == 127 else size
            if size > 16 * 1024 * 1024 or second & 128:
                raise ValueError("Unexpected CDP frame")
            chunk = self.read(size)
            opcode = first & 15
            if opcode == 8:
                raise ConnectionError("CDP closed")
            if opcode == 9:
                self.send(chunk, 10)
                continue
            if opcode not in (0, 1):
                continue
            payload += chunk
            if first & 128:
                return json.loads(payload)

    def call(self, method: str, params: dict | None = None) -> dict:
        self.sequence += 1
        self.send(json.dumps({"id": self.sequence, "method": method, "params": params or {}}).encode("utf-8"))
        while True:
            message = self.receive()
            if message.get("id") == self.sequence:
                if "error" in message:
                    raise RuntimeError(str(message["error"]))
                return message.get("result", {})

    def evaluate(self, expression: str):
        response = self.call("Runtime.evaluate", {"expression": expression, "returnByValue": True})
        if "exceptionDetails" in response:
            raise RuntimeError(str(response["exceptionDetails"]))
        return response.get("result", {}).get("value")

    def wait(self, expression: str, timeout: float = 30):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                if self.evaluate(expression):
                    return
            except RuntimeError:
                pass  # Execution context changes on navigation.
            time.sleep(.05)
        raise TimeoutError(expression)


def run(output: Path, *, advanced: bool = False) -> dict:
    """Exercise live scan, loading, accordions, batch/download and responsive layout."""
    if output.exists() and any(output.iterdir()):
        raise ValueError("Thư mục browser evidence phải trống")
    edge = Path("C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe")
    if not edge.exists():
        raise FileNotFoundError("Không tìm thấy Edge để kiểm thử browser")
    output.mkdir(parents=True, exist_ok=True)
    profile = ROOT / ".cache" / ("browser_" + uuid.uuid4().hex)
    server = make_server("127.0.0.1", 0, create_app())
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    process = subprocess.Popen([str(edge), "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check", "--disable-extensions", "--disable-background-networking", "--remote-debugging-port=0", f"--user-data-dir={profile}", "about:blank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
    result, client = {"browser": "Microsoft Edge headless, actual engine", "checks": {}, "limitations": ["Viewport emulation, not a physical phone", "No OS clipboard write, no oral/video defense verification"]}, None
    try:
        deadline = time.monotonic() + 20
        active = profile / "DevToolsActivePort"
        while not active.exists() and time.monotonic() < deadline:
            time.sleep(.1)
        port = int(active.read_text(encoding="utf-8").splitlines()[0])
        targets = requests.get(f"http://127.0.0.1:{port}/json/list", timeout=5).json()
        client = CDP(next(t["webSocketDebuggerUrl"] for t in targets if t["type"] == "page"))
        client.call("Page.enable")
        client.call("Browser.setDownloadBehavior", {"behavior": "allow", "downloadPath": str(output.resolve())})
        def navigate(path: str, ready: str):
            client.evaluate("document.body.replaceChildren()")
            client.call("Page.navigate", {"url": origin + path})
            client.wait(ready)
        def capture(name: str, width: int, height: int):
            client.call("Emulation.setDeviceMetricsOverride", {"width": width, "height": height, "deviceScaleFactor": 1, "mobile": width < 600})
            time.sleep(.15)
            no_overflow = client.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
            result["checks"][name + "_no_horizontal_overflow"] = no_overflow
            image = client.call("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": False})
            (output / (name + ".png")).write_bytes(base64.b64decode(image["data"]))
        navigate("/", "!!document.getElementById('scan-form')")
        capture("home_desktop", 1280, 900)
        if advanced:
            client.evaluate("document.querySelector('[name=advanced]').checked=true")
        loading = client.evaluate("document.getElementById('hostname').value='google.com';document.getElementById('scan-form').requestSubmit();({disabled:document.getElementById('scan-button').disabled,spinner:!document.getElementById('scan-spinner').hidden,label:document.getElementById('button-label').textContent})")
        result["checks"]["loading"] = loading["disabled"] and loading["spinner"] and "Đang kiểm tra" in loading["label"]
        client.wait("!!document.getElementById('final-result')")
        if advanced:
            result["checks"]["advanced_sections"] = client.evaluate("document.getElementById('advanced-checks').innerText.includes('Nguồn khóa CT đã xác thực') && document.getElementById('advanced-checks').innerText.includes('Xác minh chữ ký SCT')")
            result["advanced_crypto_statuses"] = client.evaluate("[...document.querySelectorAll('#advanced-checks [data-status]')].map(e=>e.dataset.status)")
        result["actual_result"] = client.evaluate("document.querySelector('#final-result [data-status]').dataset.status")
        result["checks"]["chain_timeline"] = client.evaluate("document.querySelectorAll('.chain-timeline li').length > 0")
        result["checks"]["security_score"] = client.evaluate("Number(document.getElementById('security-score').textContent) === [...document.querySelectorAll('.overview-item[data-score-scope=true] [data-status]')].reduce((s,b)=>s+(b.dataset.status==='PASS'||b.dataset.status==='VALID'?20:b.dataset.status==='WARNING'?10:0),0)")
        result["score_actual"] = client.evaluate("document.getElementById('security-score').textContent")
        count = client.evaluate("document.querySelectorAll('.sct-accordion').length")
        result["sct_count"] = count
        if count >= 2:
            client.evaluate("document.querySelectorAll('.sct-accordion summary')[0].click();document.querySelectorAll('.sct-accordion summary')[1].click()")
            time.sleep(.15)
            result["checks"]["sct_accordion"] = client.evaluate("document.querySelectorAll('.sct-accordion[open]').length === 1")
        capture("result_desktop", 1280, 900)
        capture("result_mobile", 390, 844)
        navigate("/demo", "!!document.getElementById('case-id')")
        result["checks"]["fourteen_cases"] = client.evaluate("document.getElementById('case-id').options.length === 14")
        client.evaluate("document.getElementById('demo-form').requestSubmit()")
        client.wait("!!document.getElementById('demo-comparison')")
        result["checks"]["single_execution"] = client.evaluate("document.body.innerText.includes('KHÔNG ĐẠT') && document.body.innerText.includes('THÀNH CÔNG')")
        navigate("/demo", "!!document.getElementById('case-id')")
        client.evaluate("document.querySelector('.batch-form').requestSubmit()")
        client.wait("!!document.getElementById('export-batch')")
        result["checks"]["batch_execution"] = client.evaluate("document.querySelectorAll('tbody tr').length===14 && [...document.querySelectorAll('tbody tr')].every(r=>r.innerText.includes('KIỂM THỬ THÀNH CÔNG'))")
        client.evaluate("document.querySelector('.batch-detail-link').click()")
        result["checks"]["detail_link"] = client.evaluate("document.getElementById('batch-case-1').open")
        client.evaluate("document.getElementById('export-batch').click()")
        download = output / "DT007-kiem-thu-tong-hop.csv"
        deadline = time.monotonic() + 10
        while not download.exists() and time.monotonic() < deadline:
            time.sleep(.1)
        with download.open(encoding="utf-8-sig", newline="") as stream:
            result["checks"]["csv_download"] = len(list(csv.DictReader(stream))) == 14
        capture("batch_mobile", 390, 844)
        result["all_checks_passed"] = all(result["checks"].values())
    except Exception as exc:
        result.update(error=f"{type(exc).__name__}: {exc}", all_checks_passed=False)
    finally:
        if client:
            try:
                client.call("Browser.close")
            except (ConnectionError, RuntimeError, OSError):
                pass
            client.socket.close()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=5)
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        (output / "summary.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--advanced", action="store_true", help="Kiểm tra checkbox và crypto CT trong scan thật")
    args = parser.parse_args()
    result = run(args.output_dir, advanced=args.advanced)
    print(json.dumps(result, ensure_ascii=False))
    raise SystemExit(0 if result["all_checks_passed"] else 1)
