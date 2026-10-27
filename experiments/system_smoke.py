"""Real HTTP and CLI evidence on an isolated local Flask server."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from threading import Thread
from datetime import datetime, timezone
import requests
from werkzeug.serving import make_server

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from app import create_app


def run(output: Path) -> dict:
    """Use live engine for scans; never overwrite old observations or other servers."""
    if output.exists() and any(output.iterdir()):
        raise ValueError("Thư mục bằng chứng phải trống")
    output.mkdir(parents=True, exist_ok=True)
    server = make_server("127.0.0.1", 0, create_app())
    base = f"http://127.0.0.1:{server.server_port}"
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    evidence = {"created_utc": datetime.now(timezone.utc).isoformat(), "test_url": base, "normal_web_url": "http://127.0.0.1:5000", "http": [], "cli": []}
    try:
        for name, method, path, data in [("home", "GET", "/", None), ("demo", "GET", "/demo", None), ("invalid", "POST", "/scan", {"hostname": "https://invalid.test/path"}), ("oversized", "POST", "/scan", {"hostname": "x" * 5000}), ("demo_all", "POST", "/demo", {"action": "all"})] + [(host, "POST", "/scan", {"hostname": host}) for host in ("google.com", "github.com", "cloudflare.com")]:
            response = requests.request(method, base + path, data=data, timeout=30)
            (output / f"{name}.html").write_bytes(response.content)
            evidence["http"].append({"name": name, "status": response.status_code, "sha256": hashlib.sha256(response.content).hexdigest(), "traceback_in_response": "Traceback (most recent call last)" in response.text})
        for host in (None, "google.com", "github.com", "cloudflare.com"):
            args = [sys.executable, str(ROOT / "main.py")]
            if host:
                args.extend([host, "--json", str(output / f"{host}.json"), "--html", str(output / f"{host}_report.html")])
            process = subprocess.run(args, cwd=ROOT, capture_output=True, timeout=45)
            label = host or "dataset"
            (output / f"cli_{label}.log").write_bytes(process.stdout + process.stderr)
            record = {"target": label, "exit_code": process.returncode}
            if host and (output / f"{host}.json").exists():
                result = json.loads((output / f"{host}.json").read_text(encoding="utf-8"))
                record.update(final_result=result["security"]["status"], checks=result["security"]["checks"])
            evidence["cli"].append(record)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    (output / "summary.json").write_text(json.dumps(evidence, indent=2, ensure_ascii=False), encoding="utf-8")
    return evidence


if __name__ == "__main__":
    result = run(ROOT / "reports/system_smoke/20261010")
    print("HTTP:", [(r["name"], r["status"]) for r in result["http"]])
    print("CLI:", [(r["target"], r.get("final_result"), r["exit_code"]) for r in result["cli"]])
