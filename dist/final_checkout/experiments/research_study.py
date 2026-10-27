"""Expanded, instrumented CT ablation; preserves historical 90 observations."""
from __future__ import annotations
import argparse
import csv
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import random
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.run_experiments import load_test_cases, DEFAULT_CASES_PATH, POLICY_PATH
from experiments.synthetic_cases import SyntheticLab, UnsupportedSyntheticCase
from experiments.research_controls import CONTROLS, ControlLab
from experiments.resource_metrics import snapshot
from src.algorithm_policy import load_policy


def describe(values: list[float]) -> dict:
    """Descriptive variation; a t interval is provided only for exactly 3 repeats."""
    mean = statistics.mean(values)
    std = statistics.stdev(values) if len(values) > 1 else None
    margin = 4.302652729911275 * std / (3 ** .5) if len(values) == 3 else None
    return {"n": len(values), "mean": mean, "sample_std": std, "min": min(values), "max": max(values), "cv_percent": 100 * std / mean if std is not None and mean else None,
            "t95_mean_interval": [mean - margin, mean + margin] if margin is not None else None}


def summarize(rows: list[dict], repeats: int, types: set[str]) -> dict:
    """Aggregate attempted coverage and completed confusion observations separately."""
    profiles = {}
    for profile in ("baseline", "extended"):
        runs = []
        for repeat in range(1, repeats + 1):
            group = [r for r in rows if r["profile"] == profile and r["repeat"] == repeat]
            complete = [r for r in group if r["execution_status"] == "COMPLETED"]
            negatives = [r for r in complete if r["category"] == "synthetic"]
            controls = [r for r in complete if r["category"] == "control"]
            covered = {r["case_type"] for r in negatives if r["expected_match"] and r["condition_detected"]}
            positive = [r for r in negatives if r["expected"] == "FAIL"]
            fn = sum(r["actual"] != "FAIL" for r in positive)
            fp = sum(r["actual"] == "FAIL" for r in controls)
            misconfig = types - {"SCT_TIMESTAMP_OUTSIDE_INTERVAL"}
            runs.append({"repeat": repeat, "attempted": len(group), "completed": len(complete), "errors": sum(r["execution_status"] == "ERROR" for r in group), "skipped": sum(r["execution_status"] == "SKIPPED" for r in group),
                         "coverage_percent": 100 * len(covered) / len(types), "covered_types": sorted(covered),
                         "misconfiguration_coverage_percent": 100 * len(covered & misconfig) / len(misconfig),
                         "agreement_percent": 100 * sum(r["expected_match"] for r in group) / len(group),
                         "FP": fp, "FN": fn, "positive_completed": len(positive), "controls_completed": len(controls), "control_warnings": sum(r["actual"] == "WARNING" for r in controls),
                         "wall_total_seconds": sum(r["wall_seconds"] for r in group), "wall_mean_seconds": statistics.mean(r["wall_seconds"] for r in group),
                         "synthetic_wall_mean_seconds": statistics.mean(r["wall_seconds"] for r in group if r["category"] == "synthetic"),
                         "control_wall_mean_seconds": statistics.mean(r["wall_seconds"] for r in group if r["category"] == "control"),
                         "cpu_total_seconds": sum(r["cpu_seconds"] for r in group),
                         "rss_boundary_max_bytes": max((r["rss_after_bytes"] for r in group if r["rss_after_bytes"] is not None), default=None)})
        profiles[profile] = {"runs": runs, "FP": sum(r["FP"] for r in runs), "FN": sum(r["FN"] for r in runs),
                             "positive_completed": sum(r["positive_completed"] for r in runs), "controls_completed": sum(r["controls_completed"] for r in runs),
                             "descriptive": {field: describe([r[field] for r in runs]) for field in ("coverage_percent", "misconfiguration_coverage_percent", "wall_mean_seconds", "synthetic_wall_mean_seconds", "control_wall_mean_seconds", "cpu_total_seconds")}}
    return profiles


def evaluate(output: Path, repeats: int = 3, seed: int = 20261010) -> dict:
    """Run engines again and save inputs, errors and public certificate evidence."""
    if repeats < 3:
        raise ValueError("Cần ít nhất 3 lần chạy")
    if output.exists() and any(output.iterdir()):
        raise ValueError("Thư mục kết quả phải trống để bảo toàn bằng chứng cũ")
    output.mkdir(parents=True, exist_ok=True)
    plan = load_test_cases(DEFAULT_CASES_PATH)
    cases = [c for c in plan.cases if c.category == "synthetic"]
    policy = load_policy(POLICY_PATH)
    inputs = [DEFAULT_CASES_PATH, POLICY_PATH, ROOT / "data/log_list.json", *sorted((ROOT / "src").glob("*.py")), *sorted((ROOT / "experiments").glob("*.py"))]
    hashes = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    config = {"repeats": repeats, "seed_order_only": seed, "reference_time": plan.synthetic_reference_time.isoformat(), "manifest": json.loads(DEFAULT_CASES_PATH.read_text(encoding="utf-8")), "controls": [asdict(s) for s in CONTROLS], "policy": policy, "input_sha256": hashes,
              "control_label": "Locally trusted valid X.509; baseline PASS, extended WARNING for absent SCT; set before engine execution"}
    (output / "config.json").write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
    rng, rows, evidence, setups = random.Random(seed), [], [], []
    started = time.perf_counter()
    for repeat in range(1, repeats + 1):
        profiles = ["baseline", "extended"]
        rng.shuffle(profiles)
        for profile in profiles:
            before, t0 = snapshot(), time.perf_counter()
            lab, controls = SyntheticLab(plan.synthetic_reference_time, policy), ControlLab(plan.synthetic_reference_time, policy)
            after = snapshot()
            setups.append({"repeat": repeat, "profile": profile, "wall_seconds": time.perf_counter() - t0, "cpu_seconds": after["cpu_seconds"] - before["cpu_seconds"], "rss_after_bytes": after["rss_bytes"]})
            ordered = [("synthetic", c) for c in cases] + [("control", s) for s in CONTROLS]
            rng.shuffle(ordered)
            for category, case in ordered:
                expected = case.expected_result if category == "synthetic" else ("PASS",) if profile == "baseline" else ("WARNING",)
                case_type = case.case_type if category == "synthetic" else "VALID_CONTROL"
                before, t0 = snapshot(), time.perf_counter()
                try:
                    result = lab.run(case_type, profile=profile) if category == "synthetic" else controls.run(case, profile)
                    status, execution, detected, reasons = result.status, "COMPLETED", result.detected, list(result.reasons)
                    evidence.append({"repeat": repeat, "profile": profile, "case_id": case.case_id, "evidence": result.evidence})
                except UnsupportedSyntheticCase as exc:
                    status, execution, detected, reasons = "SKIPPED", "SKIPPED", False, [str(exc)]
                except Exception as exc:
                    status, execution, detected, reasons = "ERROR", "ERROR", False, [f"{type(exc).__name__}: {exc}"]
                wall, after = time.perf_counter() - t0, snapshot()
                row = {"repeat": repeat, "profile": profile, "category": category, "case_id": case.case_id, "case_type": case_type,
                       "expected": "|".join(expected), "actual": status, "execution_status": execution,
                       "expected_match": execution == "COMPLETED" and status in expected, "condition_detected": detected,
                       "wall_seconds": wall, "cpu_seconds": after["cpu_seconds"] - before["cpu_seconds"],
                       "rss_before_bytes": before["rss_bytes"], "rss_after_bytes": after["rss_bytes"], "process_peak_rss_bytes": after["process_peak_rss_bytes"], "reason": "; ".join(reasons)}
                rows.append(row)
                with (output / "execution.log").open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(row, ensure_ascii=False) + "\n")
    with (output / "raw_results.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (output / "evidence.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    summary = {"created_utc": datetime.now(timezone.utc).isoformat(), "python": platform.python_version(), "platform": platform.platform(), "repeats": repeats, "observations": len(rows), "total_wall_seconds_including_setup": time.perf_counter() - started,
               "setups": setups, "profiles": summarize(rows, repeats, {c.case_type for c in cases}),
               "raw_sha256": hashlib.sha256((output / "raw_results.csv").read_bytes()).hexdigest(),
               "limitations": ["CPU time is process-wide at case boundaries; Windows timer may quantize short cases to zero", "RSS sampled before/after; process peak is lifetime high-water mark, NOT each case peak", "Runtime includes fixture generation and oracle; setup measured separately", "Profiles have matched properties, freshly generated different keys; not byte-identical paired input", "Only 5 control types repeated 3 times; not 15 independent population samples", "t95 intervals assume independent approximately normal repeat means; n=3, descriptive only; identical fixture coverage does not prove population coverage", "Control oracle shares OpenSSL backend with engine; independent invocation and predetermined labels, not independent implementation", "CT fixtures structured placeholders, SCT signatures/inclusion proofs NOT_VERIFIED", "CT ablation is DT007 baseline; not reproduction of the governance paper's quantitative findings"]}
    (output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, allow_nan=False), encoding="utf-8")
    return summary


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seed", type=int, default=20261010)
    args = parser.parse_args()
    result = evaluate(args.output_dir, args.repeats, args.seed)
    print(f"Đã đo {result['observations']} quan sát; {args.output_dir}")
    for name, data in result["profiles"].items():
        print(name, "coverage=", data["descriptive"]["coverage_percent"]["mean"], "FP=", data["FP"], "FN=", data["FN"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
