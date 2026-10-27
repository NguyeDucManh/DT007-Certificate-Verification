"""Regression checks for independent auditing of persisted evidence."""
import csv
import hashlib
from pathlib import Path
import shutil

import pytest

from experiments.audit_research_metrics import audit, boolean
from experiments.research_evaluation import evaluate

SOURCE = Path(__file__).resolve().parents[1] / "reports/research_results"


def copy_evidence(tmp_path):
    for name in ("raw_results.csv", "config.json", "summary.json"):
        shutil.copyfile(SOURCE / name, tmp_path / name)
    return tmp_path


def mutate(directory, change):
    path = directory / "raw_results.csv"
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        fields = reader.fieldnames
        rows = list(reader)
    change(rows)
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def test_historical_metrics_and_raw_are_preserved(tmp_path):
    directory = copy_evidence(tmp_path)
    before = hashlib.sha256((directory / "raw_results.csv").read_bytes()).hexdigest()
    result = audit(directory)
    assert result["verified"] and result["observations"] == 90
    assert result["profiles"]["baseline"]["FN"] == 6
    assert result["profiles"]["baseline"]["positive_observations"] == 36
    assert result["profiles"]["extended"]["FN"] == 0
    assert result["raw_sha256"] == before == hashlib.sha256((directory / "raw_results.csv").read_bytes()).hexdigest()


def test_audit_detects_forged_agreement(tmp_path):
    directory = copy_evidence(tmp_path)
    mutate(directory, lambda rows: rows[0].update(expected_match="False"))
    assert not audit(directory)["verified"]


def test_audit_detects_duplicate_observation(tmp_path):
    directory = copy_evidence(tmp_path)
    mutate(directory, lambda rows: rows.append(rows[0].copy()))
    assert any("trùng" in issue for issue in audit(directory)["issues"])


def test_execution_error_is_not_counted_as_negative(tmp_path):
    directory = copy_evidence(tmp_path)
    mutate(directory, lambda rows: rows[0].update(execution_status="ERROR", actual="ERROR", expected_match="False", condition_detected="False"))
    result = audit(directory)
    assert not result["verified"]
    assert sum(r["errors"] for p in result["profiles"].values() for r in p["runs"]) == 1


def test_original_runner_refuses_overwriting_historical_evidence(tmp_path):
    marker = tmp_path / "evidence.json"
    marker.write_text("keep", encoding="utf-8")
    with pytest.raises(ValueError, match="ghi đè"):
        evaluate(3, tmp_path, 1)
    assert marker.read_text(encoding="utf-8") == "keep"


@pytest.mark.parametrize("value", ["false", "", "1"])
def test_reject_invalid_boolean(value):
    with pytest.raises(ValueError):
        boolean(value)
