"""CLI cho CT dataset và Certificate Security Verifier (2A + 2B)."""

import argparse
from collections.abc import Sequence
from pathlib import Path
import sys
import time

from src.certificate_fetcher import fetch_peer_chain
from src.certificate_security import analyze_certificate
from src.ct_log_analyzer import DatasetError, DatasetSummary, analyze_file
from src.security_console import print_security_analysis
from src.security_evaluator import SecurityResult
from src.certificate_service import build_view_model
from src.report_export import export_result

DATASET_PATH = Path(__file__).resolve().parent / "data" / "log_list.json"
POLICY_PATH = Path(__file__).resolve().parent / "config" / "algorithm_policy.json"


def display(value: object) -> str:
    """Hiển thị rõ các trường thiếu."""
    return "N/A" if value is None else str(value)


def print_summary(summary: DatasetSummary) -> None:
    """In thống kê và tối đa năm log theo thứ tự dataset."""
    border = "=" * 40
    print(f"{border}\n DT007 - CT LOG DATASET ANALYZER\n{border}\n")
    print(f"Dataset version     : {display(summary.version)}")
    print(f"Dataset timestamp   : {display(summary.log_list_timestamp)}")
    print(f"Total operators     : {summary.total_operators}")
    print(f"Total logs          : {summary.total_logs}")
    for title, counts in (("Logs by operator", summary.logs_by_operator),
                          ("Logs by state", summary.logs_by_state)):
        print(f"\n{title}:")
        width = max((len(name) for name in counts), default=12)
        for name, count in counts.items():
            print(f"- {name:<{width}} : {count}")
    print(f"\n{border}")
    for index, log in enumerate(summary.logs[:5], start=1):
        print(f"\nCT log #{index}")
        for label, value in (
            ("Operator", log.operator), ("Description", log.description),
            ("Log ID", log.log_id), ("State", log.state), ("MMD", log.mmd),
            ("URL / Submission URL", log.url or log.submission_url),
            ("Start", log.start_inclusive), ("End", log.end_exclusive),
        ):
            print(f"{label:<20}: {display(value)}")


def print_certificate_analysis(hostname: str, port: int, timeout: float, *, json_path: Path | None = None,
                               html_path: Path | None = None, advanced: bool = False) -> SecurityResult:
    """Điều phối và in kết quả 2A/2B, giữ xử lý lỗi ngoài các module."""
    start = time.perf_counter()
    analysis = analyze_certificate(hostname, port, timeout, DATASET_PATH, POLICY_PATH, fetcher=fetch_peer_chain, **({"advanced": True} if advanced else {}))
    runtime = time.perf_counter() - start
    print_security_analysis(analysis, hostname, port)
    for name, item in analysis.extensions.items():
        if isinstance(item, dict):
            print(f"{name}: {item.get('status')} — {item.get('reason')}")
    for name, message in analysis.errors.items():
        print(f"Lỗi [{name}]: {message}", file=sys.stderr)
    if json_path is not None or html_path is not None:
        result = build_view_model(hostname, analysis, runtime)
        result["target"] = f"{hostname}:{port}"
        export_result(result, json_path=json_path, html_path=html_path)
    return analysis.security


def main(argv: Sequence[str] = ()) -> int:
    """Chạy CLI với danh sách tham số; không tham số chạy CT dataset analyzer."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="DT007: CT dataset hoặc TLS certificate analyzer.")
    parser.add_argument("hostname", nargs="?", help="Tên DNS/IP, ví dụ google.com")
    parser.add_argument("--port", type=int, default=443, help="TLS port (mặc định 443)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Socket/TLS timeout tính bằng giây")
    parser.add_argument("--json", type=Path, help="Lưu kết quả engine dạng JSON UTF-8")
    parser.add_argument("--html", type=Path, help="Lưu báo cáo HTML độc lập để mở trong trình duyệt")
    parser.add_argument("--advanced", action="store_true", help="Bật OCSP/CRL và AIA có kiểm soát; giữ nguyên profile nghiên cứu")
    args = parser.parse_args(argv)
    if args.hostname is not None:
        try:
            result = print_certificate_analysis(args.hostname, args.port, args.timeout, json_path=args.json, html_path=args.html, **({"advanced": True} if args.advanced else {}))
        except (OSError, ValueError) as exc:
            print(f"Lỗi xuất báo cáo: {exc}", file=sys.stderr)
            return 1
        return 1 if result.status == "FAIL" else 0
    if args.json is not None or args.html is not None:
        parser.error("Cần nhập tên miền khi xuất báo cáo chứng thư")
    try:
        summary = analyze_file(DATASET_PATH)
    except (FileNotFoundError, DatasetError) as exc:
        print(f"Lỗi: {exc}", file=sys.stderr)
        return 1
    print_summary(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
