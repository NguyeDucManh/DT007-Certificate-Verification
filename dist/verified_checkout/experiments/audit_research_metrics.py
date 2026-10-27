"""Independent, read-only audit of recorded experiment metrics."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import statistics
import sys


def boolean(value: str) -> bool:
    """Reject malformed boolean evidence instead of coercing nonempty strings."""
    if value not in ("True", "False"):
        raise ValueError(f"Giá trị boolean không hợp lệ: {value!r}")
    return value == "True"


def audit(directory: Path) -> dict:
    """Recompute metrics from CSV and the frozen plan; never alter source evidence."""
    raw = directory / "raw_results.csv"
    digest = hashlib.sha256(raw.read_bytes()).hexdigest()
    config = json.loads((directory / "config.json").read_text(encoding="utf-8"))
    summary = json.loads((directory / "summary.json").read_text(encoding="utf-8"))
    cases = config["manifest"]["SYNTHETIC_NEGATIVE_CASES"]
    plan = {c["case_id"]: c for c in cases}
    if len(plan) != len(cases):
        raise ValueError("Mã ca trùng trong cấu hình đã lưu")
    with raw.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    issues: list[str] = []
    seen: set[tuple] = set()
    profiles: dict = {}

    def compare(actual, stored, label: str) -> None:
        if isinstance(actual, (int, float)) and not isinstance(actual, bool):
            same = isinstance(stored, (int, float)) and math.isclose(actual, stored, rel_tol=1e-9, abs_tol=1e-10)
        else:
            same = actual == stored
        if not same:
            issues.append(f"{label}: tính lại={actual!r}; đã lưu={stored!r}")

    for row in rows:
        key = (int(row["repeat"]), row["profile"], row["case_id"])
        if key in seen:
            issues.append(f"Quan sát trùng: {key}")
        seen.add(key)
        if key[0] not in range(1, config["repeats"] + 1) or key[1] not in ("baseline", "extended"):
            issues.append(f"Quan sát ngoài kế hoạch: {key}")
        case = plan.get(row["case_id"])
        if case:
            expected = case["expected_result"]
            expected = [expected] if isinstance(expected, str) else expected
            compare(row["expected"], "|".join(expected), f"Kỳ vọng {key}")
            compare(row["case_type"], case["case_type"], f"Loại ca {key}")
        elif row["case_id"] != "control_valid_001":
            issues.append(f"Ca không có trong kế hoạch: {key}")
        else:
            compare(row["expected"], "PASS|WARNING", f"Kỳ vọng đối chứng {key}")
        completed = row["execution_status"] == "COMPLETED"
        matched = completed and row["actual"] in row["expected"].split("|")
        compare(boolean(row["expected_match"]), matched, f"Đối chiếu {key}")
        row["matched"] = matched
        row["detected"] = boolean(row["condition_detected"])
        row["seconds"] = float(row["runtime_seconds"])
        if not math.isfinite(row["seconds"]) or row["seconds"] < 0:
            raise ValueError(f"Runtime không hợp lệ: {key}")

    for profile in ("baseline", "extended"):
        runs = []
        fn_evidence = []
        for repeat in range(1, config["repeats"] + 1):
            sub = [r for r in rows if r["profile"] == profile and int(r["repeat"]) == repeat]
            ids = {r["case_id"] for r in sub}
            compare(ids, set(plan) | {"control_valid_001"}, f"Danh sách ca {profile}/{repeat}")
            completed = [r for r in sub if r["execution_status"] == "COMPLETED"]
            bad = [r for r in completed if r["case_id"] in plan]
            covered = {r["case_type"] for r in bad if r["matched"] and r["detected"]}
            misconfig = {c["case_type"] for c in cases if c["case_type"] != "SCT_TIMESTAMP_OUTSIDE_INTERVAL"}
            positives = [r for r in bad if r["expected"] == "FAIL"]
            controls = [r for r in completed if r["case_id"] == "control_valid_001"]
            negatives = [r for r in positives if r["actual"] != "FAIL"]
            fn_evidence.extend({"repeat": repeat, "case_id": r["case_id"], "case_type": r["case_type"], "actual": r["actual"]} for r in negatives)
            fp = sum(r["actual"] == "FAIL" for r in controls)
            result = dict(repeat=repeat, coverage_percent=100 * len(covered) / len(cases),
                          misconfiguration_coverage_percent=100 * len(covered & misconfig) / len(misconfig),
                          misconfiguration_types_total=len(misconfig), covered_types=sorted(covered),
                          agreement_percent=100 * sum(r["matched"] for r in bad) / len(cases),
                          errors=len(sub) - len(completed), valid_controls=len(controls), false_positive_fail=fp,
                          valid_control_warnings=sum(r["actual"] == "WARNING" for r in controls),
                          false_negative_fail=len(negatives), positive_cases_completed=len(positives),
                          false_negative_rate_percent=100 * len(negatives) / len(positives) if positives else None,
                          false_positive_rate_percent=100 * fp / len(controls) if controls else None,
                          mean_case_runtime_seconds=statistics.mean(r["seconds"] for r in sub) if sub else None,
                          total_case_runtime_seconds=sum(r["seconds"] for r in sub))
            stored_runs = summary["profiles"][profile]["runs"]
            stored = next((r for r in stored_runs if r["repeat"] == repeat), {})
            for field, value in result.items():
                compare(value, stored.get(field), f"{profile}/{repeat}/{field}")
            runs.append(result)
        for field in ("coverage_percent", "misconfiguration_coverage_percent", "agreement_percent", "mean_case_runtime_seconds", "false_positive_rate_percent", "false_negative_rate_percent"):
            values = [r[field] for r in runs if r[field] is not None]
            aggregate = dict(mean=statistics.mean(values), sample_std=statistics.stdev(values) if len(values) > 1 else None, min=min(values), max=max(values)) if values else None
            stored = summary["profiles"][profile].get(field)
            if aggregate and isinstance(stored, dict):
                for key, value in aggregate.items():
                    compare(value, stored.get(key), f"{profile}/{field}/{key}")
            else:
                compare(aggregate, stored, f"{profile}/{field}")
        fp = sum(r["false_positive_fail"] for r in runs)
        fn = sum(r["false_negative_fail"] for r in runs)
        compare(fp, summary["profiles"][profile]["false_positive_count"], f"{profile}/FP")
        compare(fn, summary["profiles"][profile]["false_negative_count"], f"{profile}/FN")
        profiles[profile] = {"runs": runs, "FP": fp, "FN": fn, "positive_observations": sum(r["positive_cases_completed"] for r in runs), "valid_control_observations": sum(r["valid_controls"] for r in runs), "FN_evidence": fn_evidence}
    compare(len(rows), config["repeats"] * 2 * (len(cases) + 1), "Tổng quan sát")
    compare(summary["repeats"], config["repeats"], "Số lần chạy")
    return {"source": str(directory.resolve()), "raw_sha256": digest, "observations": len(rows), "repeats": config["repeats"], "profiles": profiles, "issues": issues, "verified": not issues,
            "scope": "Kiểm chứng phép tính và kế hoạch; condition_detected là bằng chứng do engine ghi, không phải oracle độc lập."}


def main() -> int:
    """Write a separate audit artifact, preserving historical experiment outputs."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1] / "reports/research_results")
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "reports/metrics_audit")
    args = parser.parse_args()
    result = audit(args.source)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "audit.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Kiểm chứng: {result['verified']}; {result['observations']} quan sát; {len(result['issues'])} sai lệch")
    return 0 if result["verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
