"""Exports preserve conclusions and escape untrusted certificate text."""
import copy
import json
from datetime import datetime, timezone
from cryptography.hazmat.primitives.serialization import Encoding
import pytest
from src.report_export import export_result
from src.certificate_fetcher import TLSCertificates
from main import main


@pytest.mark.parametrize("status", ["PASS", "WARNING", "FAIL"])
def test_original_status_and_json_survive_export(tmp_path, status):
    result = {"target": "example.test:443", "runtime_seconds": .01, "certificate": None,
              "security": {"status": status, "checks": {"Certificate Transparency": "WARNING"}, "reasons": ["SCT signatures/inclusion proofs are NOT_VERIFIED"]}}
    original = copy.deepcopy(result)
    export_result(result, json_path=tmp_path / "report.json", html_path=tmp_path / "report.html")
    assert json.loads((tmp_path / "report.json").read_text(encoding="utf-8")) == original
    assert result == original
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert f'class="{status}"' in html and "NOT_VERIFIED" in html


def test_html_escapes_hostname_and_technical_reason(tmp_path):
    payload = '<script>alert("x")</script>'
    result = {"target": payload, "runtime_seconds": .01, "certificate": None,
              "security": {"status": "FAIL", "checks": {}, "reasons": [payload]}}
    export_result(result, html_path=tmp_path / "report.html")
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "<script>" not in html and "&lt;script&gt;" in html


def test_cli_exports_one_engine_invocation_and_correct_port(chain_factory, monkeypatch, tmp_path, capsys):
    chain = chain_factory(at=datetime.now(timezone.utc))
    calls = []
    def fetch(hostname, port, timeout):
        calls.append((hostname, port))
        return TLSCertificates(chain[0].public_bytes(Encoding.DER), tuple(c.public_bytes(Encoding.DER) for c in chain), (chain[-1].public_bytes(Encoding.DER),))
    monkeypatch.setattr("main.fetch_peer_chain", fetch)
    path = tmp_path / "report.json"
    assert main(["example.com", "--port", "8443", "--json", str(path), "--html", str(tmp_path / "report.html")]) == 0
    result = json.loads(path.read_text(encoding="utf-8"))
    assert calls == [("example.com", 8443)]
    assert result["target"] == "example.com:8443"
    assert result["security"]["status"] == "WARNING"


def test_exports_require_a_hostname(tmp_path):
    with pytest.raises(SystemExit) as error:
        main(["--json", str(tmp_path / "report.json")])
    assert error.value.code == 2
    assert not (tmp_path / "report.json").exists()
