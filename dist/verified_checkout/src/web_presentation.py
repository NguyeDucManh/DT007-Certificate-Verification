"""Bản dịch và điểm trình bày cho web; không thay đổi kết quả engine."""

import re
from collections.abc import Mapping

STATUSES = {
    "UNTRUSTED": "DỮ LIỆU THU THẬP CHƯA TIN CẬY",
    "GOOD": "CHƯA BỊ THU HỒI (CÓ BẰNG CHỨNG)", "REVOKED": "ĐÃ BỊ THU HỒI",
    "NOT_CHECKED": "CHƯA KIỂM TRA", "ERROR": "LỖI KIỂM TRA", "INVALID": "KHÔNG HỢP LỆ", "UNSUPPORTED": "CHƯA HỖ TRỢ",
    "NOT_APPLICABLE": "KHÔNG ÁP DỤNG",
    "PASS": "ĐẠT", "WARNING": "CẢNH BÁO", "FAIL": "KHÔNG ĐẠT",
    "VALID": "CÒN HIỆU LỰC", "EXPIRED": "HẾT HẠN",
    "NOT_YET_VALID": "CHƯA CÓ HIỆU LỰC", "NOT_VERIFIED": "CHƯA XÁC MINH",
    "NO_SCT": "KHÔNG CÓ SCT", "UNKNOWN": "CHƯA XÁC ĐỊNH",
    "usable": "Đang sử dụng", "qualified": "Đủ điều kiện", "readonly": "Chỉ đọc",
    "retired": "Ngừng hoạt động", "pending": "Đang chờ", "rejected": "Bị từ chối",
}
LABELS = {
    "Revocation": "Trạng thái thu hồi",
    "CT Cryptography": "Xác minh mật mã CT",
    "Root CA / Trust Anchor": "Chứng thư gốc / Điểm neo tin cậy",
    "Root CA": "Chứng thư gốc (CA tự ký)",
    "Intermediate Trust Anchor": "Chứng thư trung gian / Điểm neo tin cậy trực tiếp",
    "Validity": "Thời hạn chứng thư", "Hostname": "Tên miền",
    "Certificate Chain": "Chuỗi chứng thư", "Algorithm Policy": "Chính sách thuật toán",
    "Certificate Transparency": "Certificate Transparency", "TLS Fetch": "Kết nối TLS",
    "Certificate": "Chứng thư", "Leaf": "Chứng thư máy chủ",
    "Root / Trust Anchor": "Chứng thư gốc / Điểm tin cậy",
}


def translate_status(value: str | None) -> str:
    """Dịch mã trạng thái ở lớp hiển thị, mã gốc giữ trong dữ liệu HTML."""
    return STATUSES.get(value or "UNKNOWN", "CHƯA XÁC ĐỊNH")


def translate_label(value: str) -> str:
    """Dịch tên kiểm tra và vai trò chuỗi."""
    if value.startswith("Intermediate #"):
        return "Chứng thư trung gian #" + value.split("#", 1)[1]
    return LABELS.get(value, "Thành phần kiểm tra")


def presentation_score(checks: Mapping[str, str]) -> int:
    """Chấm năm hạng mục cố định cho UI; không dùng điểm để suy ra verdict."""
    return sum({"PASS": 20, "WARNING": 10}.get(checks.get(name, "UNKNOWN"), 0)
               for name in ("Validity", "Hostname", "Certificate Chain",
                            "Algorithm Policy", "Certificate Transparency"))


def translate_reason(value: str) -> dict[str, str | None]:
    """Dịch phần hiển thị và luôn giữ reason gốc để đối chiếu kỹ thuật."""
    translated = _translate_reason(value)
    translated["technical"] = value
    return translated


def _translate_reason(value: str) -> dict[str, str | None]:
    """Dịch reason nhận diện được; giữ nguyên bản chưa dịch trong vùng kỹ thuật."""
    lowered = value.lower()
    if value.startswith("Kiểm tra CT bổ sung:"):
        return {"text": value, "technical": value}
    numbered = re.match(r"SCT #(\d+): (.*)", value)
    if numbered:
        item = _translate_reason(numbered[2])
        return {"text": f"SCT #{numbered[1]}: {item['text']}", "technical": value}
    specific = [
        ("eku does not permit tls server authentication", "Quyền sử dụng mở rộng (EKU) của chứng thư không cho phép xác thực máy chủ TLS."),
        ("leaf keyusage does not permit tls server operation", "Quyền sử dụng khóa của chứng thư máy chủ không cho phép ký số, trao đổi khóa hoặc mã hóa khóa cho TLS."),
        ("ct log is retired; sct predates retirement", "CT Log hiện đã ngừng hoạt động; SCT có trước thời điểm ngừng hoạt động. Cần đối chiếu chính sách và dữ liệu lịch sử."),
        ("ct log is rejected", "CT Log có trạng thái bị từ chối theo danh sách; không đáp ứng chính sách matching."),
        ("unknown ct log state", "Chưa xác định được trạng thái CT Log trong bộ dữ liệu; cần kiểm tra thêm."),
        ("matching policy requires review", "Trạng thái CT Log cần xem xét theo chính sách matching; chưa kết luận chữ ký SCT không hợp lệ."),
        ("insufficient retirement timestamp data", "Không đủ dữ liệu thời điểm CT Log ngừng hoạt động để đối chiếu SCT; chưa kết luận SCT không hợp lệ."),
        ("ambiguous ct log id", "Log ID xuất hiện nhiều lần trong dữ liệu; chưa xác định được bản ghi CT Log duy nhất."),
        ("sct timestamp interval:", "Thời điểm SCT nằm ngoài hoặc chưa xác định được khoảng thời gian của CT Log. Đây là kiểm tra chẩn đoán; khoảng thời gian Google áp dụng cho ngày hết hạn chứng thư, không phải thời điểm phát hành SCT."),
        ("ct log is retired", "CT Log đã ngừng hoạt động; chưa chứng minh được SCT có trước thời điểm ngừng hoạt động."),
        ("missing issuer/trusted root", "Thiếu đơn vị cấp hoặc chứng thư gốc đáng tin cậy: chứng thư cuối chuỗi không phải điểm tin cậy độc lập."),
        ("missing trusted root", "Không tìm thấy chứng thư gốc đáng tin cậy để xác minh chuỗi."),
        ("missing issuer:", "Chuỗi thiếu đơn vị cấp: cần chứng thư máy chủ và chứng thư CA."),
        ("certificate validity: expired", "Chứng thư đã hết hạn."),
        ("certificate validity: not_yet_valid", "Chứng thư chưa đến thời điểm có hiệu lực."),
        ("certificate has expired", "OpenSSL từ chối chuỗi vì chứng thư đã hết hạn."),
        ("certificate is not yet valid", "OpenSSL từ chối chuỗi vì chứng thư chưa có hiệu lực hoặc đồng hồ hệ thống không đúng."),
        ("unable to get local issuer certificate", "OpenSSL không tìm được chứng thư đơn vị cấp trong chuỗi hoặc nguồn tin cậy."),
        ("certificate signature failure", "OpenSSL phát hiện chữ ký chứng thư không hợp lệ."),
        ("invalid signature", "Chữ ký hoặc đơn vị cấp của chứng thư không hợp lệ."),
        ("invalid ca certificate", "Chứng thư CA trong chuỗi không hợp lệ."),
        ("is not a ca", "Chứng thư đơn vị cấp không có ràng buộc CA hợp lệ (BasicConstraints)."),
        ("certificate expiry interval: unknown", "Không đủ dữ liệu hoặc khoảng thời gian CT Log bị lỗi để đối chiếu ngày hết hạn chứng thư; chưa kết luận SCT không hợp lệ."),
        ("certificate expiry interval: fail", "Ngày hết hạn chứng thư nằm ngoài khoảng chấp nhận của CT Log (temporal_interval)."),
    ]
    for needle, text in specific:
        if needle in lowered:
            return {"text": text, "technical": value}
    cert_validity = re.fullmatch(r"Certificate #(\d+) validity: (EXPIRED|NOT_YET_VALID)", value)
    if cert_validity:
        return {"text": f"Chứng thư #{cert_validity[1]}: {translate_status(cert_validity[2])}.", "technical": value}
    for prefix, label in [("Allowed public key algorithm: ", "Thuật toán khóa công khai được phép: "),
                          ("Allowed signature hash: ", "Thuật toán băm chữ ký được phép: "),
                          ("Blocked public key algorithm: ", "Thuật toán khóa công khai bị chặn: "),
                          ("Blocked signature hash: ", "Thuật toán băm chữ ký bị chặn: "),
                          ("Unknown/not allowed public key algorithm: ", "Thuật toán khóa công khai chưa xác định hoặc không được phép: "),
                          ("Unknown/not allowed signature hash: ", "Thuật toán băm chưa xác định hoặc không được phép: ")]:
        if value.startswith(prefix):
            return {"text": label + value[len(prefix):].upper(), "technical": None}
    minimum = re.fullmatch(r"Key size meets policy minimum \((\d+) bits\)", value)
    if minimum:
        return {"text": f"Độ dài khóa đạt mức tối thiểu của chính sách ({minimum[1]} bit).", "technical": None}
    weak = re.fullmatch(r"(\w+) key size below policy minimum \((\d+) bits\)", value)
    if weak:
        return {"text": f"Độ dài khóa {weak[1]} thấp hơn mức tối thiểu của chính sách ({weak[2]} bit).", "technical": None}
    exact = {
        "Key size rule is not applicable to this fixed-size key algorithm": "Quy tắc độ dài khóa không áp dụng cho thuật toán có độ dài khóa cố định này.",
        "Cannot evaluate key size for unknown/blocked key algorithm": "Không thể đánh giá độ dài khóa của thuật toán chưa xác định hoặc bị chặn.",
        "Signature algorithm is allowed without a separate hash parameter": "Thuật toán chữ ký được phép sử dụng mà không cần tham số băm riêng.",
        "Signature without external hash is not explicitly allowed by policy": "Chính sách chưa cho phép rõ ràng chữ ký không có tham số băm riêng.",
    }
    if value in exact:
        return {"text": exact[value], "technical": None}
    known = [
        ("sct signatures/inclusion proofs", "Chữ ký SCT và bằng chứng đưa vào nhật ký chưa được xác minh đầy đủ; kết quả Certificate Transparency hiện chỉ dựa trên việc đối chiếu CT Log trong bộ dữ liệu."),
        ("hostname mismatch", "Tên miền không khớp với SAN của chứng thư."),
        ("unknown ct log", "Không tìm thấy CT Log tương ứng trong bộ dữ liệu."),
        ("self-signed leaf", "Chứng thư máy chủ tự ký, không có chuỗi tin cậy phù hợp."),
        ("certificate expired", "Chứng thư đã hết hạn."),
        ("certificate not yet valid", "Chứng thư chưa đến thời điểm có hiệu lực."),
        ("broken issuer/subject", "Liên kết đơn vị cấp và chủ thể trong chuỗi không khớp."),
        ("invalid signature/issuer", "Xác minh chữ ký hoặc đơn vị cấp trong chuỗi không thành công."),
        ("signature verification failed", "Xác minh chữ ký số không thành công."),
        ("certificate chain invalid", "Chuỗi chứng thư không hợp lệ."),
        ("weak rsa key", "Độ dài khóa RSA không đạt chính sách an toàn."),
        ("hash algorithm is blocked", "Thuật toán băm đang nằm trong danh sách bị chặn."),
        ("sct timestamp is in the future", "Thời điểm SCT nằm trong tương lai."),
        ("no_sct", "Không có SCT nhúng trong chứng thư để đối chiếu."),
        ("timeout", "Kết nối vượt quá thời gian chờ cho phép."),
        ("timed out", "Kết nối vượt quá thời gian chờ cho phép."),
        ("name resolution", "Không phân giải được tên miền qua DNS."),
        ("getaddrinfo", "Không phân giải được tên miền qua DNS."),
        ("connection refused", "Máy chủ từ chối kết nối qua cổng 443."),
    ]
    for needle, text in known:
        if needle in lowered:
            # Giữ chi tiết vị trí và dữ liệu gốc khi bản dịch là lời giải thích tổng quát.
            return {"text": text, "technical": None if needle == "sct signatures/inclusion proofs" else value}
    if re.search(r"[\u00c0-\u1ef9]", value):
        # Message tiếng Việt sẵn có được giữ nếu không có tiền tố tiếng Anh của engine.
        if not re.match(r"^[A-Za-z ]+:", value):
            return {"text": value, "technical": None}
    return {"text": "Thông tin kiểm tra cần được đối chiếu thêm. Xem nội dung gốc trong Chi tiết kỹ thuật.",
            "technical": value}
