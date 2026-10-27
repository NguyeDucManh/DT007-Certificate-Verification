"""Run separate live revocation evidence, without touching research/Demo outputs."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from src.certificate_fetcher import fetch_peer_chain
from src.chain_validator import validate_chain
from src.revocation_checker import check_revocation, extract_sources
from src.revocation_network import fetch_bytes


def run(output: Path) -> None:
    """Fixed public targets; save actual signed bytes and unmodified validation results."""
    if output.exists() and any(output.iterdir()):
        raise ValueError("Không ghi đè thư mục bằng chứng đã có.")
    output.mkdir(parents=True, exist_ok=True)
    outcomes = []
    for host in ("google.com", "github.com", "cloudflare.com"):
        row = {"hostname": host, "checked_at": datetime.now(timezone.utc).isoformat()}
        folder = output / host
        folder.mkdir()
        try:
            tls = fetch_peer_chain(host, 443, 10)
            certs = tuple(x509.load_der_x509_certificate(der) for der in tls.chain_der)
            anchors = tuple(x509.load_der_x509_certificate(der) for der in tls.trust_anchors_der)
            chain = validate_chain(certs, anchors)
            row["chain_status"] = chain.status
            row["sources"] = vars(extract_sources(certs[0]))
            for index, cert in enumerate(certs[:2]):
                (folder / f"certificate_{index}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            downloaded = []
            def capture(url, **kwargs):
                data = fetch_bytes(url, **kwargs)
                name = f"response_{len(downloaded)+1}.bin"
                (folder / name).write_bytes(data)
                downloaded.append({"source": url, "file": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
                return data
            row["revocation"] = check_revocation(certs[0], certs[1] if len(certs) > 1 else None,
                issuer_trusted=chain.status == "PASS", online=True, fetcher=capture).to_dict()
            row["downloads"] = downloaded
        except Exception as exc:
            row["error"] = f"{type(exc).__name__}: {exc}"
        outcomes.append(row)
        print(host, row.get("revocation", {}).get("status", "ERROR"))
    (output / "results.json").write_text(json.dumps(outcomes, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    run(parser.parse_args().output_dir.resolve())
