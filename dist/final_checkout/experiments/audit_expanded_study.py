"""Independent CSV/config check of the expanded study's key claims."""
from __future__ import annotations
import csv
import hashlib
import json
import math
from pathlib import Path


def audit(directory: Path) -> dict:
    """Check denominators, labels, uniqueness and confusion without editing data."""
    config = json.loads((directory / "config.json").read_text(encoding="utf-8"))
    summary = json.loads((directory / "summary.json").read_text(encoding="utf-8"))
    cases = {c["case_id"]: c for c in config["manifest"]["SYNTHETIC_NEGATIVE_CASES"]}
    controls = {c["case_id"] for c in config["controls"]}
    with (directory / "raw_results.csv").open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    problems, seen, result = [], set(), {}
    def check(condition: bool, label: str) -> None:
        if not condition:
            problems.append(label)
    for row in rows:
        key = (row["repeat"], row["profile"], row["case_id"])
        check(key not in seen, f"duplicate {key}")
        seen.add(key)
        check(row["profile"] in ("baseline", "extended") and row["repeat"] in {str(i) for i in range(1, config["repeats"] + 1)}, f"outside plan {key}")
        case = cases.get(row["case_id"])
        if case:
            expected = case["expected_result"]
            expected = expected if isinstance(expected, list) else [expected]
            check(row["category"] == "synthetic" and row["case_type"] == case["case_type"], f"category/type {key}")
        else:
            check(row["case_id"] in controls and row["category"] == "control", f"unknown control {key}")
            expected = ["PASS" if row["profile"] == "baseline" else "WARNING"]
        check(row["expected"] == "|".join(expected), f"expected label {key}")
        matched = row["execution_status"] == "COMPLETED" and row["actual"] in expected
        check(row["expected_match"] == str(matched), f"expected_match {key}")
        check(row["condition_detected"] in ("True", "False"), f"boolean {key}")
        for field in ("wall_seconds", "cpu_seconds"):
            value = float(row[field])
            check(math.isfinite(value) and value >= 0, f"resource {key}/{field}")
    for profile in ("baseline", "extended"):
        total_fp, total_fn, positives, negatives = 0, 0, 0, 0
        for repeat in range(1, config["repeats"] + 1):
            group = [r for r in rows if r["profile"] == profile and r["repeat"] == str(repeat)]
            check({r["case_id"] for r in group} == set(cases) | controls, f"missing/extra {profile}/{repeat}")
            done = [r for r in group if r["execution_status"] == "COMPLETED"]
            positive = [r for r in done if r["category"] == "synthetic" and r["expected"] == "FAIL"]
            valid = [r for r in done if r["category"] == "control"]
            covered = {r["case_type"] for r in done if r["category"] == "synthetic" and r["actual"] in r["expected"].split("|") and r["condition_detected"] == "True"}
            fp, fn = sum(r["actual"] == "FAIL" for r in valid), sum(r["actual"] != "FAIL" for r in positive)
            run = next((r for r in summary["profiles"][profile]["runs"] if r["repeat"] == repeat), {})
            check(run.get("FP") == fp and run.get("FN") == fn, f"FP/FN {profile}/{repeat}")
            check(run.get("positive_completed") == len(positive) and run.get("controls_completed") == len(valid), f"denominators {profile}/{repeat}")
            check(run.get("covered_types") == sorted(covered), f"coverage types {profile}/{repeat}")
            check(math.isclose(run.get("coverage_percent", -1), 100 * len(covered) / len(cases)), f"coverage percentage {profile}/{repeat}")
            check(run.get("errors") == sum(r["execution_status"] == "ERROR" for r in group) and run.get("skipped") == sum(r["execution_status"] == "SKIPPED" for r in group), f"execution errors {profile}/{repeat}")
            total_fp += fp
            total_fn += fn
            positives += len(positive)
            negatives += len(valid)
        check(summary["profiles"][profile]["FP"] == total_fp and summary["profiles"][profile]["FN"] == total_fn, f"aggregate {profile}")
        result[profile] = {"FP": total_fp, "FN": total_fn, "positive_completed": positives, "controls_completed": negatives}
    digest = hashlib.sha256((directory / "raw_results.csv").read_bytes()).hexdigest()
    check(digest == summary["raw_sha256"], "raw checksum")
    check(len(rows) == config["repeats"] * 2 * (len(cases) + len(controls)), "observations")
    return {"verified": not problems, "problems": problems, "profiles": result, "raw_sha256": digest, "observations": len(rows), "scope": "Independent key-claim audit; recorded detection flags are not independently cryptographically reverified"}


if __name__ == "__main__":
    directory = Path(__file__).resolve().parents[1] / "reports/research_expanded/post_tls_20261010"
    result = audit(directory)
    (directory / "metrics_audit.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print("verified", result["verified"], "observations", result["observations"], "problems", len(result["problems"]))
    raise SystemExit(0 if result["verified"] else 1)
