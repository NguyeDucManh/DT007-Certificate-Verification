"""Chạy experiment 3A và xuất metrics thật; không sửa core hoặc expected results."""

import argparse
from collections.abc import Callable, Sequence
import csv
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import platform
import statistics
import sys
import time
from typing import Any

# Cho phép `py experiments/run_experiments.py` từ bất kỳ working directory nào.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.synthetic_cases import CASE_TYPES, SyntheticLab, UnsupportedSyntheticCase
from src.algorithm_policy import load_policy
from src.certificate_security import analyze_certificate
from src.hostname_validator import normalize_hostname

DEFAULT_CASES_PATH = PROJECT_ROOT / "experiments" / "test_cases.json"
DATASET_PATH = PROJECT_ROOT / "data" / "log_list.json"
POLICY_PATH = PROJECT_ROOT / "config" / "algorithm_policy.json"
SECURITY_STATUSES = frozenset({"PASS", "WARNING", "FAIL"})
CSV_FIELDS = (
    "case_id", "category", "case_type", "target", "expected_result", "actual_result",
    "correct", "runtime_seconds", "reasons", "detected", "execution_status",
    "evaluation_scope", "generation_method",
)


class ExperimentConfigError(ValueError):
    """File test case thiếu, JSON sai hoặc schema không hợp lệ."""


@dataclass(frozen=True)
class ExperimentCase:
    """Expectation khai báo trước chạy; một real case có thể chấp nhận nhiều status."""

    case_id: str
    category: str
    case_type: str
    target: str
    expected_result: tuple[str, ...]
    ground_truth: str


@dataclass(frozen=True)
class ExperimentPlan:
    """Danh sách case và clock local để tái lập ground truth."""

    cases: tuple[ExperimentCase, ...]
    synthetic_reference_time: datetime


@dataclass(frozen=True)
class Observation:
    """Kết quả từ module thật, tách status bảo mật khỏi lỗi thực thi."""

    actual_result: str
    reasons: tuple[str, ...]
    detected: bool | None = None
    execution_status: str = "COMPLETED"
    evaluation_scope: str = "Certificate Security Verifier"
    generation_method: str = "Live verified TLS"


@dataclass(frozen=True)
class CaseResult:
    """Bản ghi kết quả có runtime đo bằng perf_counter, không giả lập."""

    case: ExperimentCase
    actual_result: str
    correct: bool | None
    runtime_seconds: float
    reasons: tuple[str, ...]
    detected: bool | None
    execution_status: str
    evaluation_scope: str
    generation_method: str


def load_test_cases(path: Path) -> ExperimentPlan:
    """Đọc và validate schema, duplicate IDs và expectation không nhập nhằng."""
    try:
        with Path(path).open(encoding="utf-8-sig") as stream:
            data = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ExperimentConfigError(f"Không thể đọc test_cases.json {path}: {exc}") from exc
    if not isinstance(data, dict) or type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        raise ExperimentConfigError("Invalid test case schema: schema_version phải là 1.")
    try:
        clock = datetime.fromisoformat(data["synthetic_reference_time"].replace("Z", "+00:00"))
        if clock.tzinfo is None or clock.utcoffset() is None:
            raise ValueError("timestamp thiếu timezone")
        clock = clock.astimezone(timezone.utc)
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        raise ExperimentConfigError("Invalid synthetic_reference_time: cần ISO timestamp timezone-aware.") from exc
    cases: list[ExperimentCase] = []
    seen: set[str] = set()
    for group, category in (("REAL_WEBSITES", "real"), ("SYNTHETIC_NEGATIVE_CASES", "synthetic")):
        entries = data.get(group)
        if not isinstance(entries, list):
            raise ExperimentConfigError(f"Invalid test case schema: {group} phải là list.")
        for entry in entries:
            if not isinstance(entry, dict) or any(
                not isinstance(entry.get(field), str) or not entry[field].strip()
                for field in ("case_id", "case_type", "target", "ground_truth")
            ):
                raise ExperimentConfigError(f"Invalid test case schema in {group}: thiếu trường chuỗi bắt buộc.")
            if entry["case_id"] in seen:
                raise ExperimentConfigError(f"Duplicate case_id: {entry['case_id']}")
            expected = entry.get("expected_result")
            expected = [expected] if isinstance(expected, str) else expected
            if not isinstance(expected, list) or not expected or any(not isinstance(item, str) or item not in SECURITY_STATUSES for item in expected):
                raise ExperimentConfigError(f"Invalid expected_result for {entry['case_id']}")
            if len(set(expected)) != len(expected) or ("FAIL" in expected and len(expected) != 1):
                raise ExperimentConfigError("expected_result không được trộn FAIL với non-FAIL hoặc lặp status.")
            if category == "real":
                try:
                    normalize_hostname(entry["target"])
                except ValueError as exc:
                    raise ExperimentConfigError(f"Invalid real target: {entry['target']}") from exc
                if entry["case_type"] != "VALID_SITE":
                    raise ExperimentConfigError("Real case_type phải là VALID_SITE.")
            elif entry["case_type"] not in CASE_TYPES or entry["target"] != "local":
                raise ExperimentConfigError("Invalid synthetic case_type hoặc target khác local.")
            seen.add(entry["case_id"])
            cases.append(ExperimentCase(entry["case_id"], category, entry["case_type"], entry["target"], tuple(expected), entry["ground_truth"]))
    if not cases:
        raise ExperimentConfigError("Test plan phải có ít nhất một case.")
    return ExperimentPlan(tuple(cases), clock)


def run_real_case(case: ExperimentCase, timeout: float = 10.0) -> Observation:
    """Gọi pipeline hiện tại; không biến network error thành false positive."""
    analysis = analyze_certificate(case.target, 443, timeout, DATASET_PATH, POLICY_PATH)
    return Observation(analysis.security.status, analysis.security.reasons,
                       execution_status="ERROR" if analysis.errors else "COMPLETED")


def run_case(case: ExperimentCase, action: Callable[[ExperimentCase], Observation]) -> CaseResult:
    """Đo toàn bộ action và cô lập exception của từng case."""
    start = time.perf_counter()
    try:
        observation = action(case)
        if observation.execution_status not in ("COMPLETED", "ERROR", "SKIPPED"):
            raise ValueError("Unknown execution_status")
        if observation.execution_status == "COMPLETED" and observation.actual_result not in SECURITY_STATUSES:
            raise ValueError("Completed case phải có PASS/WARNING/FAIL")
    except UnsupportedSyntheticCase as exc:
        observation = Observation("SKIPPED", (str(exc),), execution_status="SKIPPED", evaluation_scope="Fixture generation", generation_method="Unavailable backend capability")
    except Exception as exc:
        observation = Observation("ERROR", (f"{type(exc).__name__}: {exc}",), execution_status="ERROR", evaluation_scope="Case execution", generation_method="See error")
    runtime = time.perf_counter() - start
    correct = observation.actual_result in case.expected_result if observation.execution_status == "COMPLETED" else None
    return CaseResult(case, observation.actual_result, correct, runtime, observation.reasons, observation.detected,
                      observation.execution_status, observation.evaluation_scope, observation.generation_method)


def run_cases(
    plan: ExperimentPlan, *, timeout: float = 10.0,
    real_runner: Callable[[ExperimentCase], Observation] | None = None,
    synthetic_runner: Callable[[ExperimentCase], Observation] | None = None,
    setup_metrics: dict[str, float] | None = None,
) -> list[CaseResult]:
    """Chạy mọi case; setup local đo riêng, lỗi một case không chặn các case sau."""
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Timeout phải hữu hạn và lớn hơn 0.")
    real_runner = (lambda case: run_real_case(case, timeout)) if real_runner is None else real_runner
    if synthetic_runner is None and any(case.category == "synthetic" for case in plan.cases):
        start = time.perf_counter()
        lab = None
        setup_error: Exception | None = None
        try:
            lab = SyntheticLab(plan.synthetic_reference_time, load_policy(POLICY_PATH))
        except Exception as exc:
            setup_error = exc
        if setup_metrics is not None:
            setup_metrics["synthetic_setup_seconds"] = time.perf_counter() - start

        def local_runner(case: ExperimentCase) -> Observation:
            """Chỉ truyền case_type cho lab, không truyền expectation."""
            if setup_error is not None:
                raise RuntimeError(f"Synthetic setup failed: {setup_error}") from setup_error
            assert lab is not None
            outcome = lab.run(case.case_type)
            return Observation(outcome.status, outcome.reasons, outcome.detected,
                               evaluation_scope=outcome.evaluation_scope, generation_method=outcome.generation_method)
        synthetic_runner = local_runner
    results: list[CaseResult] = []
    for case in plan.cases:
        action = real_runner if case.category == "real" else synthetic_runner
        assert action is not None
        results.append(run_case(case, action))
    return results


def _percent(numerator: int, denominator: int) -> float | None:
    """Không tạo số 0% giả khi mẫu số bằng 0."""
    return 100.0 * numerator / denominator if denominator else None


def calculate_metrics(results: Sequence[CaseResult]) -> dict[str, Any]:
    """Metrics trên case COMPLETED; coverage vẫn giữ types bị skip/error ở mẫu số."""
    evaluated = [row for row in results if row.execution_status == "COMPLETED"]
    correct = sum(row.correct is True for row in evaluated)
    positive = [row for row in evaluated if row.case.expected_result == ("FAIL",)]
    negative = [row for row in evaluated if row.case.expected_result != ("FAIL",)]
    false_positives = sum(row.actual_result == "FAIL" for row in negative)
    false_negatives = sum(row.actual_result != "FAIL" for row in positive)
    types = {row.case.case_type for row in results if row.case.category == "synthetic"}
    covered = {row.case.case_type for row in results if row.case.category == "synthetic"
               and row.execution_status == "COMPLETED" and row.correct is True and row.detected is True}
    runtimes = [row.runtime_seconds for row in results]
    return {
        "total_cases": len(results), "evaluated_cases": len(evaluated),
        "correct_cases": correct, "incorrect_cases": len(evaluated) - correct,
        "error_cases": sum(row.execution_status == "ERROR" for row in results),
        "skipped_cases": sum(row.execution_status == "SKIPPED" for row in results),
        "accuracy_percent": _percent(correct, len(evaluated)),
        "misconfiguration_coverage_percent": _percent(len(covered), len(types)),
        "misconfiguration_types_total": len(types), "misconfiguration_types_detected": len(covered),
        "covered_types": sorted(covered), "uncovered_types": sorted(types - covered),
        "false_positives": false_positives, "false_negatives": false_negatives,
        "true_positives": len(positive) - false_negatives, "true_negatives": len(negative) - false_positives,
        "positive_cases": len(positive), "negative_cases": len(negative),
        "false_positive_rate_percent": _percent(false_positives, len(negative)),
        "false_negative_rate_percent": _percent(false_negatives, len(positive)),
        "runtime": {
            "average": statistics.mean(runtimes) if runtimes else None,
            "median": statistics.median(runtimes) if runtimes else None,
            "min": min(runtimes) if runtimes else None,
            "max": max(runtimes) if runtimes else None,
        },
    }


def export_csv(results: Sequence[CaseResult], path: Path) -> None:
    """Ghi CSV UTF-8 với quoting chuẩn; reasons là JSON array trong một cell."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for row in results:
            writer.writerow({
                "case_id": row.case.case_id, "category": row.case.category, "case_type": row.case.case_type,
                "target": row.case.target, "expected_result": "|".join(row.case.expected_result),
                "actual_result": row.actual_result,
                "correct": "" if row.correct is None else str(row.correct).lower(),
                "runtime_seconds": repr(row.runtime_seconds),
                "reasons": json.dumps(row.reasons, ensure_ascii=False),
                "detected": "" if row.detected is None else str(row.detected).lower(),
                "execution_status": row.execution_status, "evaluation_scope": row.evaluation_scope,
                "generation_method": row.generation_method,
            })


def export_summary(summary: dict[str, Any], path: Path) -> None:
    """Ghi JSON UTF-8, null cho metric không có mẫu số."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def _number(value: float | None, unit: str) -> str:
    """Định dạng metrics khi không có số liệu."""
    return "N/A" if value is None else f"{value:.4f} {unit}"


def print_results(results: Sequence[CaseResult], summary: dict[str, Any], csv_path: Path, summary_path: Path) -> None:
    """PASS của case là expectation agreement, không phải security result."""
    border = "=" * 40
    print(f"{border}\n DT007 - EXPERIMENT RUNNER\n{border}\n")
    fields = (
        ("Total cases", summary["total_cases"]), ("Evaluated", summary["evaluated_cases"]),
        ("Correct", summary["correct_cases"]), ("Incorrect", summary["incorrect_cases"]),
        ("Errors / Skipped", f"{summary['error_cases']} / {summary['skipped_cases']}"),
        ("Accuracy", _number(summary["accuracy_percent"], "%")),
        ("Misconfiguration Coverage", _number(summary["misconfiguration_coverage_percent"], "%")),
        ("False Positives", summary["false_positives"]), ("False Negatives", summary["false_negatives"]),
        ("False Positive Rate", _number(summary["false_positive_rate_percent"], "%")),
        ("False Negative Rate", _number(summary["false_negative_rate_percent"], "%")),
        ("Runtime Average", _number(summary["runtime"]["average"], "s")),
        ("Runtime Median", _number(summary["runtime"]["median"], "s")),
        ("Runtime Min", _number(summary["runtime"]["min"], "s")),
        ("Runtime Max", _number(summary["runtime"]["max"], "s")),
    )
    for label, value in fields:
        print(f"{label:<27}: {value}")
    print(f"\nResults:\n{csv_path}\n\nSummary:\n{summary_path}\n\n{border}")
    for row in results:
        mark = row.execution_status if row.execution_status != "COMPLETED" else "PASS" if row.correct else "FAIL"
        label = row.case.target if row.case.category == "real" else row.case.case_type
        print(f"[{mark}] {row.case.case_id} {label} (actual={row.actual_result}, expected={'|'.join(row.case.expected_result)})")


def main(argv: Sequence[str] | None = None) -> int:
    """CLI mặc định chạy hai nhóm; --offline chạy local, không cần Internet."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="DT007 Giai đoạn 3A: experiments + metrics")
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES_PATH)
    parser.add_argument("--output-dir", type=Path, default=PROJECT_ROOT / "experiments")
    parser.add_argument("--offline", action="store_true", help="Chỉ chạy synthetic cases")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)
    try:
        plan = load_test_cases(args.cases)
        if args.offline:
            plan = replace(plan, cases=tuple(case for case in plan.cases if case.category == "synthetic"))
        if not plan.cases:
            raise ExperimentConfigError("Không có case trong nhóm đã chọn.")
        setup: dict[str, float] = {}
        started = datetime.now(timezone.utc)
        total_start = time.perf_counter()
        results = run_cases(plan, timeout=args.timeout, setup_metrics=setup)
        summary = calculate_metrics(results)
        summary["by_category"] = {category: calculate_metrics([row for row in results if row.case.category == category])
                                  for category in sorted({row.case.category for row in results})}
        summary["run"] = {
            "started_at_utc": started.isoformat(), "python": platform.python_version(),
            "platform": platform.platform(), "offline": args.offline,
            "synthetic_reference_time": plan.synthetic_reference_time.isoformat(),
            "timeout_seconds": args.timeout, **setup,
            "total_wall_seconds": time.perf_counter() - total_start,
            "source_sha256": {str(path.relative_to(PROJECT_ROOT)) if path.is_relative_to(PROJECT_ROOT) else str(path):
                              hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
                              for path in (args.cases.resolve(), POLICY_PATH, DATASET_PATH,
                                           PROJECT_ROOT / "src" / "chain_validator.py",
                                           Path(__file__).resolve(), PROJECT_ROOT / "experiments" / "synthetic_cases.py")},
        }
        summary["definitions"] = {
            "accuracy": "100 * correct_cases / evaluated_cases; accepted status lists count as agreement",
            "coverage": "100 * distinct synthetic types with correct outcome AND detected intended condition / all attempted synthetic types; skipped/error types remain in denominator",
            "positive": "expected_result is exactly FAIL; prediction positive is actual_result FAIL",
            "false_positive_rate": "100 * FP / evaluated expected non-FAIL cases",
            "false_negative_rate": "100 * FN / evaluated expected FAIL cases",
            "errors_and_skips": "excluded from accuracy/FP/FN; counted separately, never considered correct",
            "runtime": "perf_counter for each action, including per-case fixture creation; shared lab/key setup reported separately; includes errors/skips",
            "real_sites": "observational normal-case assumptions, not independently audited security ground truth; inspect by_category.synthetic separately",
        }
        csv_path, summary_path = args.output_dir / "results.csv", args.output_dir / "summary.json"
        export_csv(results, csv_path)
        export_summary(summary, summary_path)
    except (ExperimentConfigError, OSError, ValueError) as exc:
        print(f"Lỗi experiment runner: {exc}", file=sys.stderr)
        return 1
    print_results(results, summary, csv_path, summary_path)
    return 1 if summary["error_cases"] or summary["incorrect_cases"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
