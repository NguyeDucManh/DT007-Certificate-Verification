"""DT007 reproducible paired baseline vs extended offline study.

Runs real X.509 generation/validators, not cached CSV. No live websites.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import random
import statistics
import sys
import time
import ssl

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.run_experiments import load_test_cases, POLICY_PATH, DATASET_PATH, DEFAULT_CASES_PATH
from experiments.synthetic_cases import SyntheticLab, UnsupportedSyntheticCase
from src.algorithm_policy import load_policy

FIELDS = ("repeat", "profile", "case_id", "case_type", "ground_truth", "expected", "actual",
          "execution_status", "expected_match", "condition_detected", "runtime_seconds", "reason")


def checksum(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def evaluate(repeats: int, output: Path, seed: int) -> dict:
    if repeats < 3:
        raise ValueError("Thầy yêu cầu tối thiểu 3 lần chạy.")
    if output.exists() and any(output.iterdir()):
        raise ValueError("Thư mục kết quả phải trống để không ghi đè bằng chứng nghiên cứu cũ.")
    plan = load_test_cases(DEFAULT_CASES_PATH)
    cases = [c for c in plan.cases if c.category == "synthetic"]
    if not cases:
        raise ValueError("Không có ca synthetic trong test_cases.json")
    output.mkdir(parents=True, exist_ok=True)
    rows = []
    run_info = []
    random.seed(seed)  # Chỉ cố định thứ tự Python; OpenSSL RSA keys không thể seed bằng random.seed.
    evidence_rows = []
    (output / 'config.json').write_text(json.dumps({'repeats':repeats,'seed':seed,'manifest':json.loads(DEFAULT_CASES_PATH.read_text(encoding='utf-8')), 'policy':load_policy(POLICY_PATH)},ensure_ascii=False,indent=2),encoding='utf-8')
    log_path = output / 'execution.log'
    log_path.write_text('DT007 real offline experiment started\n',encoding='utf-8')
    for repeat in range(1, repeats + 1):
        profiles = ['baseline','extended']
        random.shuffle(profiles)
        for profile in profiles:
            start = time.perf_counter()
            lab = SyntheticLab(plan.synthetic_reference_time, load_policy(POLICY_PATH))
            setup = time.perf_counter() - start
            ordered_cases = [(c.case_id, c.case_type, c.ground_truth, c.expected_result) for c in cases]
            # Control dương: X.509 hợp lệ theo validity/hostname/chain/algorithm.
            # CT trong extended chỉ có metadata placeholder -> WARNING, không phải kết luận vi phạm.
            ordered_cases.append(("control_valid_001", "VALID_CONTROL", "Valid locally issued certificate", ("PASS", "WARNING")))
            for case_id, case_type, truth, expected in ordered_cases:
                t0 = time.perf_counter()
                try:
                    result = lab.run(case_type, profile=profile)
                    status = result.status
                    execution_status = "COMPLETED"
                    detected = result.detected
                    reason = "; ".join(result.reasons)
                    matched = status in expected
                    evidence_rows.append({'repeat':repeat,'profile':profile,'case_id':case_id,'evidence':result.evidence})
                except UnsupportedSyntheticCase as exc:
                    status, execution_status, detected, matched = 'SKIPPED', 'SKIPPED', False, False
                    reason = str(exc)
                except Exception as exc:
                    status, execution_status, detected, matched = "ERROR", "ERROR", False, False
                    reason = f"{type(exc).__name__}: {exc}"
                rows.append({"repeat": repeat, "profile": profile, "case_id": case_id, "case_type": case_type,
                             "ground_truth": truth, "expected": "|".join(expected), "actual": status,
                             "execution_status": execution_status, "expected_match": matched,
                             "condition_detected": detected, "runtime_seconds": round(time.perf_counter() - t0, 8),
                             "reason": reason})
                with log_path.open('a',encoding='utf-8') as log:
                    log.write(f'{repeat} {profile} {case_id} {execution_status} actual={status} match={matched} detected={detected}\n')
            run_info.append({"repeat": repeat, "profile": profile, "setup_seconds": setup})
    with (output / "raw_results.csv").open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    (output / 'evidence.json').write_text(json.dumps(evidence_rows,ensure_ascii=False,indent=2),encoding='utf-8')
    summary = {"study": "DT007 matched-scenario offline ablation: baseline without CT vs extended with CT",
               "created_at_utc": datetime.now(timezone.utc).isoformat(), "repeats": repeats, "seed_python_only": seed,
               "fixed_reference_time": plan.synthetic_reference_time.isoformat(),
               "python": platform.python_version(), "platform": platform.platform(),
               "openssl": ssl.OPENSSL_VERSION,
               "case_count_per_profile_repeat": len(cases) + 1,
               "inputs_sha256": {p.relative_to(ROOT).as_posix(): checksum(p) for p in (DEFAULT_CASES_PATH, POLICY_PATH, DATASET_PATH,
                                  ROOT / "experiments" / "synthetic_cases.py", Path(__file__), *sorted((ROOT/'src').glob('*.py')))},
               "setup_runs": run_info, "profiles": {},
               "limitations": ["No live website ground-truth labeling", "SCT signatures and inclusion proofs not verified",
                               "One valid control per repeat; false-positive rate not representative",
                               "Cryptographic key generation is nondeterministic even with Python random seed",
                               "Baseline is a CT ablation, not the paper's original implementation",
                               "Case SCT_TIMESTAMP_OUTSIDE_INTERVAL is a corrected semantics regression, not a misconfiguration",
                               "Profiles use freshly generated independent certificates with matched properties, not byte-identical inputs",
                               "CT matching uses synthetic metadata; pinned Google snapshot is profiled but not used as synthetic ground truth"]}
    for profile in ("baseline", "extended"):
        p = [r for r in rows if r["profile"] == profile]
        per_run = []
        for repeat in range(1, repeats + 1):
            sub = [r for r in p if r["repeat"] == repeat]
            bad = [r for r in sub if r["case_id"] != "control_valid_001"]
            completed = [r for r in bad if r["execution_status"] == "COMPLETED"]
            covered = {r["case_type"] for r in completed if r["expected_match"] and r["condition_detected"]}
            misconfiguration_types = {c.case_type for c in cases if c.case_type != 'SCT_TIMESTAMP_OUTSIDE_INTERVAL'}
            valid = [r for r in sub if r["case_id"] == "control_valid_001" and r["execution_status"] == "COMPLETED"]
            fp = sum(r["actual"] == "FAIL" for r in valid)
            positive = [r for r in completed if r['expected']=='FAIL']
            fn = sum(r['actual']!='FAIL' for r in positive)
            warnings = sum(r["actual"] == "WARNING" for r in valid)
            per_run.append({"repeat": repeat, "coverage_percent": 100 * len(covered) / len(cases),
                            "misconfiguration_coverage_percent":100 * len(covered & misconfiguration_types)/len(misconfiguration_types),
                            "misconfiguration_types_total":len(misconfiguration_types),
                            "covered_types": sorted(covered), "agreement_percent": 100 * sum(r["expected_match"] for r in completed) / len(cases),
                            "errors": sum(r["execution_status"] != "COMPLETED" for r in sub),
                            "valid_controls": len(valid), "false_positive_fail": fp, "valid_control_warnings": warnings,
                            "false_negative_fail": fn, "positive_cases_completed": len(positive),
                            "false_negative_rate_percent": 100 * fn / len(positive) if positive else None,
                            "false_positive_rate_percent": 100 * fp / len(valid) if valid else None,
                            "mean_case_runtime_seconds": statistics.mean(r["runtime_seconds"] for r in sub),
                            "total_case_runtime_seconds": sum(r["runtime_seconds"] for r in sub)})
        def aggregate(field):
            vals = [r[field] for r in per_run if r[field] is not None]
            return {"mean": statistics.mean(vals), "sample_std": statistics.stdev(vals) if len(vals) > 1 else None,
                    "min": min(vals), "max": max(vals)} if vals else None
        summary["profiles"][profile] = {"runs": per_run, "coverage_percent": aggregate("coverage_percent"),
                                         "misconfiguration_coverage_percent": aggregate("misconfiguration_coverage_percent"),
                                         "agreement_percent": aggregate("agreement_percent"),
                                         "mean_case_runtime_seconds": aggregate("mean_case_runtime_seconds"),
                                         "false_positive_rate_percent": aggregate("false_positive_rate_percent"),
                                         "false_negative_rate_percent": aggregate("false_negative_rate_percent"),
                                         "false_positive_count": sum(r['false_positive_fail'] for r in per_run),
                                         "false_negative_count": sum(r['false_negative_fail'] for r in per_run)}
    (output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    lines = ["# DT007 – Báo cáo thực nghiệm offline", "", f"Ngày chạy (UTC): {summary['created_at_utc']}",
             f"Số lần lặp: {repeats}; số điều kiện kiểm thử: {len(cases)}; ca chứng thư hợp lệ đối chứng: 1/lần lặp.", "",
             "| Profile | Coverage trung bình | Khớp kỳ vọng trung bình | Runtime trung bình/ca | FP trên control |",
             "|---|---:|---:|---:|---:|"]
    fn_lines = []
    for profile in ("baseline", "extended"):
        s = summary["profiles"][profile]
        fp_rate = s['false_positive_rate_percent']
        fp_text = f"{fp_rate['mean']:.2f}%" if fp_rate else 'N/A'
        lines.append(f"| {profile} | {s['coverage_percent']['mean']:.2f}% | {s['agreement_percent']['mean']:.2f}% | {s['mean_case_runtime_seconds']['mean']:.6f}s | {fp_text} |")
        fn_lines.append(f"{profile}: FP={s['false_positive_count']}, FN={s['false_negative_count']}.")
    lines.extend(['', *fn_lines])
    lines.extend(["", "**Định nghĩa:** Coverage = số điều kiện có kết quả khớp kỳ vọng VÀ detected=True / 14 điều kiện kiểm thử.",
                  "Chính xác hơn, 14 mục là điều kiện kiểm thử: gồm 13 lỗi/điều kiện cần lưu ý và 1 hồi quy semantics SCT. Misconfiguration coverage riêng trên 13 mục nằm trong summary.json.",
                  "FP = số chứng thư đối chứng hợp lệ bị gán FAIL / số chứng thư đối chứng đã hoàn thành. WARNING được báo riêng.",
                  "Baseline giữ validity/hostname/chain/algorithm và bỏ CT; extended thêm CT metadata matching.",
                  "", "**Không suy rộng:** Kết quả chỉ có giá trị trên fixtures của bộ thử này, không đo độ chính xác trên Internet.",
                  "", "## Giới hạn", *[f"- {x}" for x in summary["limitations"]], "",
                  "Chi tiết từng lần chạy: `raw_results.csv`; thông tin môi trường và checksum: `summary.json`."])
    (output / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="DT007: paired 3+ run baseline/extended experiment")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seed", type=int, default=20261007)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "reports" / "research_results")
    args = parser.parse_args()
    result = evaluate(args.repeats, args.output_dir, args.seed)
    print("Experiment completed. Results:", args.output_dir)
    for k, v in result["profiles"].items():
        print(k, "coverage", v["coverage_percent"]["mean"], "runtime", v["mean_case_runtime_seconds"]["mean"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
