"""Tests 3A: schema, offline ground truth, metrics và xuất file, không có network."""

import csv
from dataclasses import replace
from datetime import datetime
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments.run_experiments import (
    DEFAULT_CASES_PATH, POLICY_PATH, CSV_FIELDS, CaseResult, ExperimentCase,
    ExperimentConfigError, ExperimentPlan, Observation, calculate_metrics, export_csv,
    export_summary, load_test_cases, run_case, run_cases, run_real_case,
)
from experiments.synthetic_cases import CASE_TYPES, SyntheticLab, UnsupportedSyntheticCase
from src.algorithm_policy import load_policy


@pytest.fixture
def plan() -> ExperimentPlan:
    """Đọc manifest được dùng khi chạy experiment thật."""
    return load_test_cases(DEFAULT_CASES_PATH)


@pytest.fixture(scope="module")
def lab() -> SyntheticLab:
    """Lab offline độc lập pytest fixtures core, clock lấy từ manifest."""
    plan = load_test_cases(DEFAULT_CASES_PATH)
    return SyntheticLab(plan.synthetic_reference_time, load_policy(POLICY_PATH))


def test_load_test_cases(plan: ExperimentPlan) -> None:
    real = {case.target for case in plan.cases if case.category == "real"}
    assert {"google.com", "github.com", "cloudflare.com", "microsoft.com", "wikipedia.org"} <= real
    assert {case.case_type for case in plan.cases if case.category == "synthetic"} == CASE_TYPES
    assert plan.synthetic_reference_time.tzinfo is not None
    assert all(case.ground_truth for case in plan.cases)


@pytest.mark.parametrize("mutation", [
    "root", "version", "bool_version", "missing_real", "missing_synthetic", "wrong_group",
    "empty", "missing_id", "duplicate_id", "bad_expected", "mixed_expected", "duplicate_expected",
    "bad_timestamp", "naive_timestamp", "bad_host", "bad_synthetic_type", "nonlocal_target",
])
def test_invalid_case_schema(tmp_path: Path, mutation: str) -> None:
    data = json.loads(DEFAULT_CASES_PATH.read_text(encoding="utf-8"))
    entry = data["REAL_WEBSITES"][0]
    if mutation == "root":
        data = []
    elif mutation == "version":
        data["schema_version"] = 2
    elif mutation == "bool_version":
        data["schema_version"] = True
    elif mutation == "missing_real":
        del data["REAL_WEBSITES"]
    elif mutation == "missing_synthetic":
        del data["SYNTHETIC_NEGATIVE_CASES"]
    elif mutation == "wrong_group":
        data["REAL_WEBSITES"] = {}
    elif mutation == "empty":
        data["REAL_WEBSITES"] = data["SYNTHETIC_NEGATIVE_CASES"] = []
    elif mutation == "missing_id":
        del entry["case_id"]
    elif mutation == "duplicate_id":
        data["REAL_WEBSITES"].append(entry.copy())
    elif mutation == "bad_expected":
        entry["expected_result"] = "UNKNOWN"
    elif mutation == "mixed_expected":
        entry["expected_result"] = ["PASS", "FAIL"]
    elif mutation == "duplicate_expected":
        entry["expected_result"] = ["PASS", "PASS"]
    elif mutation == "bad_timestamp":
        data["synthetic_reference_time"] = "bad"
    elif mutation == "naive_timestamp":
        data["synthetic_reference_time"] = "2026-10-07T00:00:00"
    elif mutation == "bad_host":
        entry["target"] = "https://example.com"
    elif mutation == "bad_synthetic_type":
        data["SYNTHETIC_NEGATIVE_CASES"][0]["case_type"] = "UNSUPPORTED_TYPE"
    elif mutation == "nonlocal_target":
        data["SYNTHETIC_NEGATIVE_CASES"][0]["target"] = "external.example"
    path = tmp_path / "cases.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ExperimentConfigError):
        load_test_cases(path)


def test_invalid_case_json(tmp_path: Path) -> None:
    path = tmp_path / "cases.json"
    path.write_text("{broken", encoding="utf-8")
    with pytest.raises(ExperimentConfigError):
        load_test_cases(path)


def test_missing_case_file(tmp_path: Path) -> None:
    with pytest.raises(ExperimentConfigError):
        load_test_cases(tmp_path / "absent.json")


def test_runtime_nonnegative(plan: ExperimentPlan) -> None:
    result = run_case(plan.cases[0], lambda case: Observation("WARNING", ()))
    assert result.runtime_seconds >= 0 and result.correct is True


@pytest.fixture
def metric_rows() -> list[CaseResult]:
    """Confusion matrix TP=1,FN=1,FP=1,TN=1; runtimes 1,2,3,4."""
    specifications = [
        ("synthetic", "EXPIRED_CERTIFICATE", ("FAIL",), "FAIL", True),
        ("synthetic", "BROKEN_CHAIN", ("FAIL",), "WARNING", False),
        ("synthetic", "NO_SCT", ("WARNING",), "FAIL", False),
        ("real", "VALID_SITE", ("PASS", "WARNING"), "WARNING", None),
    ]
    rows = []
    for index, (category, kind, expected, actual, detected) in enumerate(specifications, start=1):
        case = ExperimentCase(f"metric_{index}", category, kind, "local" if category == "synthetic" else "example.com", expected, "Unit-test ground truth")
        rows.append(CaseResult(case, actual, actual in expected, float(index), ("Thông báo, có dấu phẩy",), detected, "COMPLETED", "Unit-test observation", "Metrics fixture"))
    return rows


def test_accuracy_calculation(metric_rows: list[CaseResult]) -> None:
    summary = calculate_metrics(metric_rows)
    assert summary["total_cases"] == 4 and summary["correct_cases"] == 2
    assert summary["incorrect_cases"] == 2 and summary["accuracy_percent"] == 50.0


def test_coverage_calculation(metric_rows: list[CaseResult]) -> None:
    summary = calculate_metrics(metric_rows)
    assert summary["misconfiguration_types_total"] == 3
    assert summary["misconfiguration_types_detected"] == 1
    assert summary["misconfiguration_coverage_percent"] == pytest.approx(100 / 3)
    assert summary["covered_types"] == ["EXPIRED_CERTIFICATE"]


def test_coverage_not_accuracy(metric_rows: list[CaseResult]) -> None:
    row = replace(metric_rows[2], actual_result="WARNING", correct=True, detected=False)
    summary = calculate_metrics([row])
    assert summary["accuracy_percent"] == 100.0
    assert summary["misconfiguration_coverage_percent"] == 0.0


def test_coverage_counts_types_not_rows(metric_rows: list[CaseResult]) -> None:
    summary = calculate_metrics([metric_rows[0], metric_rows[0]])
    assert summary["misconfiguration_types_total"] == 1 and summary["misconfiguration_types_detected"] == 1


def test_false_positive_calculation(metric_rows: list[CaseResult]) -> None:
    summary = calculate_metrics(metric_rows)
    assert summary["false_positives"] == 1 and summary["false_positive_rate_percent"] == 50.0
    assert summary["true_negatives"] == 1


def test_false_negative_calculation(metric_rows: list[CaseResult]) -> None:
    summary = calculate_metrics(metric_rows)
    assert summary["false_negatives"] == 1 and summary["false_negative_rate_percent"] == 50.0
    assert summary["true_positives"] == 1


def test_runtime_average(metric_rows: list[CaseResult]) -> None:
    assert calculate_metrics(metric_rows)["runtime"]["average"] == 2.5


def test_runtime_median(metric_rows: list[CaseResult]) -> None:
    assert calculate_metrics(metric_rows)["runtime"]["median"] == 2.5


def test_runtime_min_max(metric_rows: list[CaseResult]) -> None:
    runtime = calculate_metrics(metric_rows)["runtime"]
    assert runtime["min"] == 1.0 and runtime["max"] == 4.0


def test_empty_metrics_are_null() -> None:
    summary = calculate_metrics([])
    assert summary["accuracy_percent"] is None
    assert summary["false_positive_rate_percent"] is None
    assert summary["false_negative_rate_percent"] is None
    assert summary["runtime"]["average"] is None


def test_errors_and_skips_not_security_predictions(metric_rows: list[CaseResult]) -> None:
    errored = replace(metric_rows[3], actual_result="FAIL", correct=None, execution_status="ERROR")
    skipped = replace(metric_rows[1], actual_result="SKIPPED", correct=None, execution_status="SKIPPED")
    summary = calculate_metrics([metric_rows[0], errored, skipped])
    assert summary["total_cases"] == 3 and summary["evaluated_cases"] == 1
    assert summary["error_cases"] == 1 and summary["skipped_cases"] == 1
    assert summary["false_positives"] == summary["false_negatives"] == 0
    assert summary["accuracy_percent"] == 100.0
    assert summary["misconfiguration_coverage_percent"] == 50.0


def test_csv_export(tmp_path: Path, metric_rows: list[CaseResult]) -> None:
    path = tmp_path / "nested" / "results.csv"
    export_csv(metric_rows, path)
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        assert tuple(reader.fieldnames) == CSV_FIELDS
        rows = list(reader)
    assert rows[0]["correct"] == "true" and rows[1]["correct"] == "false"
    assert rows[3]["expected_result"] == "PASS|WARNING"
    assert json.loads(rows[0]["reasons"]) == list(metric_rows[0].reasons)
    assert float(rows[0]["runtime_seconds"]) == metric_rows[0].runtime_seconds


def test_json_summary_export(tmp_path: Path, metric_rows: list[CaseResult]) -> None:
    path = tmp_path / "summary.json"
    summary = calculate_metrics(metric_rows)
    export_summary(summary, path)
    assert json.loads(path.read_text(encoding="utf-8")) == summary


def test_runner_continues_after_exception(plan: ExperimentPlan) -> None:
    subset = replace(plan, cases=plan.cases[:2])
    def action(case: ExperimentCase) -> Observation:
        if case.case_id == subset.cases[0].case_id:
            raise RuntimeError("simulated timeout")
        return Observation("WARNING", ())
    rows = run_cases(subset, real_runner=action)
    assert rows[0].execution_status == "ERROR" and rows[0].correct is None
    assert "simulated timeout" in rows[0].reasons[0]
    assert rows[1].execution_status == "COMPLETED" and rows[1].correct is True
    assert all(row.runtime_seconds >= 0 for row in rows)


def test_skipped_backend_capability(plan: ExperimentPlan) -> None:
    case = next(case for case in plan.cases if case.case_type == "MD5_SIGNATURE")
    def unsupported(case: ExperimentCase) -> Observation:
        raise UnsupportedSyntheticCase("MD5 signing unavailable on this backend")
    row = run_case(case, unsupported)
    assert row.execution_status == "SKIPPED" and row.correct is None
    assert calculate_metrics([row])["misconfiguration_coverage_percent"] == 0.0


def test_network_error_is_not_false_positive(plan: ExperimentPlan, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("experiments.run_experiments.analyze_certificate", lambda *args: SimpleNamespace(
        errors={"TLS Fetch": "timeout"}, security=SimpleNamespace(status="FAIL", reasons=("timeout",))))
    row = run_case(plan.cases[0], run_real_case)
    assert row.actual_result == "FAIL" and row.execution_status == "ERROR"
    assert calculate_metrics([row])["false_positives"] == 0


def test_completed_live_failure_preserved(plan: ExperimentPlan, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("experiments.run_experiments.analyze_certificate", lambda *args: SimpleNamespace(
        errors={}, security=SimpleNamespace(status="FAIL", reasons=("Unknown CT log ID",))))
    row = run_case(plan.cases[0], run_real_case)
    assert row.execution_status == "COMPLETED" and row.correct is False
    assert calculate_metrics([row])["false_positives"] == 1


@pytest.mark.parametrize("case_type", sorted(CASE_TYPES))
def test_synthetic_ground_truth(case_type: str, plan: ExperimentPlan, lab: SyntheticLab) -> None:
    case = next(case for case in plan.cases if case.case_type == case_type)
    try:
        outcome = lab.run(case_type)
    except UnsupportedSyntheticCase as exc:
        pytest.skip(str(exc))
    assert outcome.status in case.expected_result
    assert outcome.detected is True and outcome.reasons


def test_expectations_are_not_rewritten(plan: ExperimentPlan, lab: SyntheticLab) -> None:
    case = replace(next(case for case in plan.cases if case.case_type == "RSA_1024"), expected_result=("PASS",))
    def action(case: ExperimentCase) -> Observation:
        outcome = lab.run(case.case_type)
        return Observation(outcome.status, outcome.reasons, outcome.detected)
    row = run_case(case, action)
    assert row.correct is False and row.actual_result == "FAIL"
    assert row.case.expected_result == ("PASS",)


def test_unknown_synthetic_type(lab: SyntheticLab) -> None:
    with pytest.raises(ValueError, match="Unknown synthetic"):
        lab.run("UNKNOWN_TYPE")


def test_synthetic_clock_must_be_aware() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        SyntheticLab(datetime(2026, 10, 7), {})
