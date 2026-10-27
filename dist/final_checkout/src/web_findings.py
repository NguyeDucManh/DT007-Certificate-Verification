"""Giải thích kết quả cho UI, không tính lại verdict của engine."""

from typing import Any
import re
from src.web_presentation import translate_label, translate_reason


def explain_findings(result: dict[str, Any]) -> list[dict[str, str]]:
    """Tách lỗi phát hiện, chẩn đoán CT và giới hạn công cụ theo bằng chứng."""
    findings: list[dict[str, str]] = []
    sources = [("Thời hạn chứng thư", result.get("validity"), "Kiểm tra đồng hồ; gia hạn hoặc cấp lại chứng thư."),
               ("Tên miền", result.get("hostname_validation"), "Dùng đúng tên miền trong SAN hoặc cấp lại chứng thư phù hợp."),
               ("Chuỗi chứng thư", result.get("chain"), "Kiểm tra chứng thư trung gian, chữ ký và nguồn CA tin cậy."),
               ("Chính sách thuật toán", result.get("algorithm_policy"), "Cấp lại chứng thư với thuật toán và độ dài khóa đáp ứng chính sách."),
               ("Certificate Transparency", result.get("ct"), "Đối chiếu CT Log, ngày hết hạn và trạng thái nhật ký; xác minh thêm bằng công cụ CT đầy đủ.")]
    for label, component, recommendation in sources:
        if not component or component.get("status") in ("PASS", "VALID"):
            continue
        reasons = component.get("reasons") or [component.get("message", "Không có thông tin chi tiết từ thành phần kiểm tra.")]
        for reason in reasons:
            lower = reason.lower()
            limitation = "sct signatures/inclusion proofs" in lower
            diagnostic = "sct timestamp interval:" in lower
            missing = "no_sct" in lower
            insufficient = any(token in lower for token in ('unknown', 'insufficient', 'ambiguous'))
            category = "Giới hạn xác minh của công cụ" if limitation else "Dấu hiệu cần kiểm tra / dữ liệu chưa đủ" if diagnostic or missing or insufficient else "Vấn đề phát hiện khi kiểm tra"
            impact = ("Chưa có đủ bằng chứng về chữ ký SCT hoặc inclusion proof; không kết luận website mất an toàn từ giới hạn này."
                      if limitation else "Cần kiểm tra thêm; dấu hiệu này không tự chứng minh website mất an toàn."
                      if diagnostic or missing or insufficient else "Ảnh hưởng tới việc xác minh độ tin cậy của chứng thư." if component.get("status") in ("FAIL", "EXPIRED", "NOT_YET_VALID") else "Cần lưu ý theo chính sách hoặc dữ liệu hiện có.")
            findings.append({"component": label, "category": category, "cause": reason,
                             "explanation": str(translate_reason(reason)["text"]), "impact": impact,
                             "recommendation": "Xác minh chữ ký SCT và inclusion proof bằng công cụ chuyên dụng; giữ kết luận CT hiện tại." if limitation else recommendation})
    for error in result.get("errors", []):
        findings.append({"component": translate_label(error["module"]), "category": "Không hoàn tất kiểm tra",
                         "cause": error["message"], "explanation": str(translate_reason(error["message"])["text"]),
                         "impact": "Lỗi thực thi không đồng nghĩa đã xác định được lỗi chứng thư.",
                         "recommendation": "Kiểm tra kết nối, dữ liệu cấu hình và thử lại."})
    grouped: dict[tuple[str, str], dict[str, str]] = {}
    for finding in findings:
        cause = re.sub(r'^SCT #\d+: ', '', finding['cause'])
        key = (finding['component'], cause)
        if key in grouped:
            grouped[key]['cause'] += '\n' + finding['cause']
        else:
            grouped[key] = dict(finding)
    return list(grouped.values())
