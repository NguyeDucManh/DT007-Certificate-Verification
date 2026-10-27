"""Documents must cite real artifacts, preserve raw data and have actual pages."""
import hashlib
from pathlib import Path
from pypdf import PdfReader
import pytest
from experiments.build_scientific_report import build, junit_counts

ROOT = Path(__file__).resolve().parents[1]


def test_junit_counts_require_actual_evidence(tmp_path):
    assert junit_counts(tmp_path / "missing.xml") == {}
    path = tmp_path / "tests.xml"
    path.write_text('<testsuites><testsuite tests="8" failures="1" errors="2" skipped="1"/></testsuites>', encoding="utf-8")
    assert junit_counts(path) == {"tests": 8, "failures": 1, "errors": 2, "skipped": 1}


def test_report_is_real_20_to_30_pages_and_preserves_evidence(tmp_path):
    source = ROOT / "reports/research_expanded/post_tls_20261010/summary.json"
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    result = build(tmp_path, source, tmp_path / "no-tests.xml")
    reader = PdfReader(tmp_path / "scientific_report.pdf")
    assert 20 <= len(reader.pages) <= 30
    text = " ".join(page.extract_text() for page in reader.pages)
    assert "NOT_VERIFIED" in text and "71.4286%" in text
    assert "chưa có XML" in text
    assert result["pytest"] == {} and result["slides"] == 14
    assert before == hashlib.sha256(source.read_bytes()).hexdigest()
    assert (tmp_path / "figures/coverage.svg").exists()


def test_missing_study_is_not_replaced_with_sample(tmp_path):
    with pytest.raises(FileNotFoundError):
        build(tmp_path / "report", tmp_path / "missing.json", tmp_path / "tests.xml")
