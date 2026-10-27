"""Archive primary-source research metadata with dates and checksums."""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import requests

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    "paper_crossref.json": "https://api.crossref.org/works/10.1093/cybsec/tyaf018",
    "journal_about.html": "https://academic.oup.com/cybersecurity/pages/About",
    "ct_log_lists.md": "https://raw.githubusercontent.com/GoogleChrome/CertificateTransparency/main/log_lists.md",
    "ct_log_list_schema.json": "https://www.gstatic.com/ct/log_list/v3/log_list_schema.json",
}


def collect(output: Path) -> dict:
    """Record failures explicitly; never replace them with fabricated source content."""
    if output.exists() and any(output.iterdir()):
        raise ValueError("Thư mục nguồn phải trống để không ghi đè bằng chứng")
    output.mkdir(parents=True, exist_ok=True)
    evidence = {}
    for name, url in SOURCES.items():
        record = {"url": url, "retrieved_utc": datetime.now(timezone.utc).isoformat()}
        try:
            response = requests.get(url, timeout=30, headers={"User-Agent": "DT007 academic reproducibility review"})
            record.update(http_status=response.status_code, final_url=response.url)
            response.raise_for_status()
            (output / name).write_bytes(response.content)
            record.update(sha256=hashlib.sha256(response.content).hexdigest(), size_bytes=len(response.content))
        except requests.RequestException as exc:
            record["error"] = str(exc)
        evidence[name] = record
    (output / "sources.json").write_text(json.dumps(evidence, indent=2, ensure_ascii=False), encoding="utf-8")
    return evidence


if __name__ == "__main__":
    result = collect(ROOT / "reports/research_sources/20261010")
    print({name: record.get("http_status", "ERROR") for name, record in result.items()})
