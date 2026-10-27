"""Chạy lại case giả lập có sẵn; không thay dataset hoặc engine thực tế."""

from pathlib import Path
import time
from typing import Any
from experiments.run_experiments import DEFAULT_CASES_PATH, load_test_cases
from experiments.synthetic_cases import SyntheticLab
from experiments.synthetic_cases import UnsupportedSyntheticCase
import csv
import io
from src.web_presentation import translate_status
from src.algorithm_policy import load_policy

CASE_LABELS = {
    "EXPIRED_CERTIFICATE": "Chứng thư hết hạn", "NOT_YET_VALID_CERTIFICATE": "Chứng thư chưa có hiệu lực",
    "HOSTNAME_MISMATCH": "Tên miền không khớp SAN", "RSA_1024": "Khóa RSA 1024 bit",
    "SHA1_SIGNATURE": "Chữ ký SHA1", "MD5_SIGNATURE": "Chữ ký MD5",
    "BROKEN_CHAIN": "Chuỗi sai liên kết đơn vị cấp", "INVALID_SIGNATURE": "Chữ ký không hợp lệ",
    "NON_CA_INTERMEDIATE": "Chứng thư trung gian không phải CA", "SELF_SIGNED_LEAF": "Chứng thư máy chủ tự ký",
    "UNKNOWN_CT_LOG": "CT Log không có trong dữ liệu", "RETIRED_CT_LOG": "CT Log ngừng hoạt động",
    "SCT_TIMESTAMP_OUTSIDE_INTERVAL": "Thời điểm SCT ngoài khoảng chẩn đoán", "NO_SCT": "Không có SCT nhúng",
}

CASE_DESCRIPTIONS = {
    "EXPIRED_CERTIFICATE": "Chứng thư máy chủ hết hạn một ngày trước đồng hồ giả lập.",
    "NOT_YET_VALID_CERTIFICATE": "Chứng thư máy chủ bắt đầu có hiệu lực một ngày sau đồng hồ giả lập.",
    "HOSTNAME_MISMATCH": "Yêu cầu other.example.test nhưng SAN chỉ chứa example.test.",
    "RSA_1024": "Chứng thư thật có khóa RSA 1024 bit; đối chiếu với chính sách thuật toán hiện tại.",
    "SHA1_SIGNATURE": "Chứng thư có chữ ký RSA/SHA-1 hợp lệ về toán học; kiểm tra riêng chính sách thuật toán băm.",
    "MD5_SIGNATURE": "Chứng thư có chữ ký RSA/MD5 nếu backend hỗ trợ; không tạo được thì báo chưa chạy, không giả kết quả.",
    "BROKEN_CHAIN": "Tên đơn vị cấp của chứng thư máy chủ khác chủ thể chứng thư trung gian.",
    "INVALID_SIGNATURE": "Tên đơn vị cấp đúng nhưng chứng thư được ký bằng khóa riêng khác.",
    "NON_CA_INTERMEDIATE": "Chứng thư trung gian có BasicConstraints CA=False.",
    "SELF_SIGNED_LEAF": "Chứng thư máy chủ tự ký, không thuộc chuỗi CA tin cậy của lab.",
    "UNKNOWN_CT_LOG": "Log ID trong SCT không có trong bộ dữ liệu CT giả lập.",
    "RETIRED_CT_LOG": "SCT được phát hành sau thời điểm CT Log giả lập ngừng hoạt động.",
    "SCT_TIMESTAMP_OUTSIDE_INTERVAL": "Ca hồi quy: SCT trước temporal_interval nhưng NotAfter nằm trong khoảng. Không cảnh báo timestamp theo interval; tổng CT vẫn cảnh báo vì chưa xác minh chữ ký SCT/inclusion proof.",
    "NO_SCT": "Chứng thư máy chủ không có SCT nhúng; chính sách hiện tại trả cảnh báo.",
}


def demo_cases() -> list[dict[str, str]]:
    """Lấy lựa chọn từ manifest experiments thay vì sao chép kết quả CSV."""
    return [{"id": c.case_id, "type": c.case_type, "label": CASE_LABELS.get(c.case_type, c.case_type)}
            for c in load_test_cases(DEFAULT_CASES_PATH).cases if c.category == "synthetic"]


def run_demo(case_id: str, policy_path: Path) -> dict[str, Any]:
    """Tạo chứng thư thật trong RAM và gọi SyntheticLab/validators thật offline."""
    plan = load_test_cases(DEFAULT_CASES_PATH)
    case = next((c for c in plan.cases if c.category == "synthetic" and c.case_id == case_id), None)
    if case is None:
        raise ValueError("Trường hợp demo không hợp lệ.")
    start = time.perf_counter()
    outcome = SyntheticLab(plan.synthetic_reference_time, load_policy(policy_path)).run(case.case_type)
    return {"case_id": case.case_id, "label": CASE_LABELS[case.case_type], "case_type": case.case_type,
            "description": CASE_DESCRIPTIONS[case.case_type], "ground_truth": case.ground_truth,
            "expected": case.expected_result, "matches_expected": outcome.status in case.expected_result,
            "status": outcome.status, "reasons": outcome.reasons, "detected": outcome.detected,
            "evidence": outcome.evidence,
            "test_success": outcome.status in case.expected_result and outcome.detected,
            "source": "experiments/test_cases.json (tình huống, kỳ vọng, đồng hồ) + experiments/synthetic_cases.py (tạo dữ liệu và gọi validators); chính sách từ config/algorithm_policy.json",
            "scope": "Chính sách thuật toán (kiểm tra riêng)" if outcome.evaluation_scope == "Algorithm Policy (isolated)" else "Tổng hợp validators offline: thời hạn, tên miền, chuỗi, thuật toán và CT",
            "clock": plan.synthetic_reference_time.isoformat(), "runtime": time.perf_counter() - start,
            "generation": outcome.generation_method}


def run_all_demos(policy_path: Path) -> dict[str, Any]:
    """Chạy tất cả ID synthetic trong manifest; lỗi một ca không dừng ca sau."""
    start = time.perf_counter()
    rows = []
    for case in demo_cases():
        case_start = time.perf_counter()
        try:
            row = run_demo(case['id'], policy_path)
            row['execution_status'] = 'COMPLETED'
        except Exception as exc:
            row = {'case_id': case['id'], 'label': case['label'], 'case_type': case['type'],
                   'status': None, 'detected': False, 'matches_expected': False, 'test_success': False,
                   'runtime': time.perf_counter() - case_start, 'evidence': {},
                   'execution_status': 'SKIPPED' if isinstance(exc, UnsupportedSyntheticCase) else 'ERROR',
                   'error': 'Không tạo được dữ liệu thử nghiệm trên backend này.' if isinstance(exc, UnsupportedSyntheticCase) else 'Không hoàn tất ca kiểm thử. Kiểm tra cấu hình và thử lại.',
                   'reasons': (), 'expected': next(c.expected_result for c in load_test_cases(DEFAULT_CASES_PATH).cases if c.case_id == case['id'])}
        rows.append(row)
    completed = [r for r in rows if r['execution_status'] == 'COMPLETED']
    matched = sum(r['matches_expected'] for r in completed)
    succeeded = sum(r['test_success'] for r in rows)
    return {'rows': rows, 'total': len(rows), 'success': succeeded, 'failed': len(rows) - succeeded,
            'matched': matched, 'match_rate': 100 * matched / len(rows) if rows else None,
            'completed': len(completed), 'errors': len(rows) - len(completed),
            'runtime': time.perf_counter() - start}


def batch_csv(batch: dict[str, Any]) -> str:
    """CSV UTF-8 từ đúng snapshot vừa chạy; không đọc results.csv hoặc chạy lại."""
    stream = io.StringIO(newline='')
    writer = csv.writer(stream)
    writer.writerow(['STT','Mã ca','Tên trường hợp','Module kiểm tra','Kết quả mong đợi','Kết quả thực tế',
                     'Phát hiện điều kiện','Đối chiếu','Kết luận kiểm thử','Trạng thái thực thi','Thời gian (giây)','Nguyên nhân gốc'])
    for index, row in enumerate(batch['rows'], 1):
        writer.writerow([index, row['case_id'], row['label'], '; '.join(row['evidence'].get('modules', [])),
                         '/'.join(translate_status(s) for s in row['expected']), translate_status(row['status']) if row['status'] else 'CHƯA CÓ KẾT QUẢ',
                         'Có' if row['detected'] else 'Chưa', 'ĐÚNG' if row['matches_expected'] else 'SAI',
                         'KIỂM THỬ THÀNH CÔNG' if row['test_success'] else 'KIỂM THỬ THẤT BẠI',
                         row['execution_status'], f"{row['runtime']:.6f}", '; '.join(row['reasons']) if row['reasons'] else row.get('error','')])
    return stream.getvalue()
