"""Kiểm tra điều phối CLI 2A/2B mà không truy cập mạng."""

from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives.serialization import Encoding
import pytest

from main import main
from src.certificate_fetcher import CertificateFetchError, TLSCertificates


def test_certificate_cli(chain_factory: Callable, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
    chain = chain_factory(at=datetime.now(timezone.utc))
    def fetch(hostname: str, port: int, timeout: float) -> TLSCertificates:
        assert (hostname, port, timeout) == ("example.com", 8443, 2.0)
        return TLSCertificates(chain[0].public_bytes(Encoding.DER), tuple(cert.public_bytes(Encoding.DER) for cert in chain),
                               (chain[-1].public_bytes(Encoding.DER),))
    monkeypatch.setattr("main.fetch_peer_chain", fetch)
    assert main(["example.com", "--port", "8443", "--timeout", "2"]) == 0
    output = capsys.readouterr().out
    for expected in ("CERTIFICATE SECURITY VERIFIER", "CN=example.com", "[Hostname]", "PASS", "[Validity]", "[Public Key]", "RSA", "[Signature]", "sha256",
                     "[Certificate Chain]", "[Algorithm Policy]", "[Certificate Transparency]", "[Security Summary]", "FINAL RESULT: WARNING"):
        assert expected in output


def test_certificate_cli_error(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
    def fail(*args: object) -> bytes:
        raise CertificateFetchError("TLS handshake thất bại")
    monkeypatch.setattr("main.fetch_peer_chain", fail)
    assert main(["example.com"]) == 1
    assert "TLS handshake thất bại" in capsys.readouterr().err


def test_missing_policy_does_not_crash(chain_factory: Callable, monkeypatch: pytest.MonkeyPatch,
                                      tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    chain = chain_factory(at=datetime.now(timezone.utc))
    fetched = TLSCertificates(chain[0].public_bytes(Encoding.DER), tuple(cert.public_bytes(Encoding.DER) for cert in chain),
                              (chain[-1].public_bytes(Encoding.DER),))
    monkeypatch.setattr("main.fetch_peer_chain", lambda *args: fetched)
    monkeypatch.setattr("main.POLICY_PATH", tmp_path / "missing.json")
    assert main(["example.com"]) == 1
    output = capsys.readouterr().out
    assert "[Security Summary]" in output and "FINAL RESULT: FAIL" in output
    assert "PolicyError" in output and "Chain Status" in output


def test_missing_ct_dataset_does_not_crash(chain_factory: Callable, monkeypatch: pytest.MonkeyPatch,
                                          tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    chain = chain_factory(at=datetime.now(timezone.utc))
    fetched = TLSCertificates(chain[0].public_bytes(Encoding.DER), tuple(cert.public_bytes(Encoding.DER) for cert in chain),
                              (chain[-1].public_bytes(Encoding.DER),))
    monkeypatch.setattr("main.fetch_peer_chain", lambda *args: fetched)
    monkeypatch.setattr("main.DATASET_PATH", tmp_path / "missing.json")
    assert main(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "FINAL RESULT: WARNING" in output and "FileNotFoundError" in output
