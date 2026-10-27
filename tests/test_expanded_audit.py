"""The expanded study must not hide mismatched labels or duplicate samples."""
from pathlib import Path
import shutil
import csv
from experiments.audit_expanded_study import audit

SOURCE = Path(__file__).resolve().parents[1] / "reports/research_expanded/post_tls_20261010"


def test_actual_expanded_study():
    result = audit(SOURCE)
    assert result["verified"] and result["observations"] == 114
    assert result["profiles"]["baseline"]["FN"] == 6
    assert result["profiles"]["extended"]["controls_completed"] == 15


def test_expected_labels_cannot_be_changed_to_match_actual(tmp_path):
    for name in ("raw_results.csv", "summary.json", "config.json"):
        shutil.copyfile(SOURCE / name, tmp_path / name)
    path = tmp_path / "raw_results.csv"
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        fields, rows = reader.fieldnames, list(reader)
    row = next(r for r in rows if r["profile"] == "baseline" and r["case_type"] == "UNKNOWN_CT_LOG")
    row.update(expected="PASS", expected_match="True")
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    result = audit(tmp_path)
    assert not result["verified"]
    assert any("expected label" in problem for problem in result["problems"])
