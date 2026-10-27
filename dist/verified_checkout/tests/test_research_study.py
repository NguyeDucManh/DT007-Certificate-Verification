"""Expanded controls, resources and error accounting regression tests."""
from datetime import datetime, timezone
import json
from pathlib import Path
import pytest

from experiments.research_controls import CONTROLS, ControlLab
from experiments.resource_metrics import snapshot
from experiments.research_study import evaluate, summarize, describe
from experiments.synthetic_cases import SyntheticLab
from src.algorithm_policy import load_policy

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def lab():
    return ControlLab(datetime(2026, 10, 7, tzinfo=timezone.utc), load_policy(ROOT / "config/algorithm_policy.json"))


@pytest.mark.parametrize("spec", CONTROLS, ids=lambda s: s.case_id)
@pytest.mark.parametrize("profile,status", [("baseline", "PASS"), ("extended", "WARNING")])
def test_independently_labeled_controls_execute_engine(lab, spec, profile, status):
    result = lab.run(spec, profile)
    assert result.status == status
    assert result.evidence["oracle_verified"] is True
    assert result.evidence["mock_used"] is False
    assert result.evidence["leaf_pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert "PRIVATE KEY" not in json.dumps(result.evidence)
    assert result.evidence["checks"]["Certificate Chain"] == "PASS"


def test_resource_snapshots_are_actual_nonnegative_values():
    sample = snapshot()
    assert sample["cpu_seconds"] >= 0
    if sample["rss_bytes"] is not None:
        assert sample["rss_bytes"] > 0


def test_t_interval_is_explicitly_small_sample():
    result = describe([1., 2., 3.])
    assert result["n"] == 3 and result["mean"] == 2.
    assert result["t95_mean_interval"][0] < 0
    assert describe([1., 2.])["t95_mean_interval"] is None


def test_no_overwrite_or_under_repetition(tmp_path):
    (tmp_path / "evidence.json").write_text("preserve", encoding="utf-8")
    with pytest.raises(ValueError, match="bảo toàn"):
        evaluate(tmp_path)
    assert (tmp_path / "evidence.json").read_text() == "preserve"
    with pytest.raises(ValueError, match="3"):
        evaluate(tmp_path / "new", 2)


def test_one_case_error_remains_visible_and_outside_confusion(tmp_path, monkeypatch):
    original = SyntheticLab.run
    def fail(self, case_type, **kwargs):
        if case_type == "EXPIRED_CERTIFICATE":
            raise RuntimeError("injected research failure")
        return original(self, case_type, **kwargs)
    monkeypatch.setattr(SyntheticLab, "run", fail)
    result = evaluate(tmp_path / "run")
    assert result["observations"] == 114
    for data in result["profiles"].values():
        assert sum(r["errors"] for r in data["runs"]) == 3
        assert data["positive_completed"] == 33
        assert data["descriptive"]["coverage_percent"]["mean"] < 100
    assert "injected research failure" in (tmp_path / "run/execution.log").read_text(encoding="utf-8")
