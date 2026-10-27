"""Portable JSON/HTML export of the existing engine result, without re-evaluation."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from jinja2 import Environment
from src.web_presentation import translate_reason, translate_status, translate_label

HTML = """<!doctype html><html lang="vi"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>DT007 — Báo cáo chứng thư</title>
<style>body{font:16px system-ui;max-width:1000px;margin:2rem auto;padding:1rem;color:#153447;background:#f3f7fa}section{padding:1rem;background:white;margin:1rem 0;border-radius:12px}table{width:100%;border-collapse:collapse}td,th{padding:.6rem;text-align:left;border-bottom:1px solid #ddd}.PASS{color:#167340}.WARNING{color:#935400}.FAIL{color:#b02020}pre{white-space:pre-wrap;overflow-wrap:anywhere}h1{font-size:1.7rem}@media print{body{background:white;margin:0}}</style>
<h1>Trình xác minh an toàn chứng thư số</h1><p>Tên miền kiểm tra: {{ result.target }}</p>
<section><h2>Kết quả cuối cùng: <span class="{{ result.security.status }}">{{ result.security.status|status }}</span></h2>
<p>Thời gian xử lý: {{ '%.6f'|format(result.runtime_seconds) }} giây</p>
<table><tr><th>Thành phần kiểm tra</th><th>Kết quả</th></tr>{% for name,value in result.security.checks.items() %}<tr><td>{{ name|label }}</td><td class="{{ value }}">{{ value|status }}</td></tr>{% endfor %}</table>
<h3>Lý do</h3>{% for reason in result.security.reasons %}<p>{{ (reason|reason_vi).text }}</p>{% endfor %}</section>
{% if result.certificate %}<section><h2>Thông tin chứng thư</h2><p>Chủ thể: {{ result.certificate.subject }}</p><p>Đơn vị cấp: {{ result.certificate.issuer }}</p><p>Số sê-ri: {{ result.certificate.serial_number }}</p><p>Có hiệu lực từ: {{ result.certificate.not_before }}</p><p>Có hiệu lực đến: {{ result.certificate.not_after }}</p></section>{% endif %}
{% if result.extensions %}<section><h2>Kiểm tra bổ sung</h2>{% for key,item in result.extensions.items() %}{% if item is mapping %}<p>{{ key }}: {{ 'HỢP LỆ' if item.status == 'VALID' and key in ('ct_key_source','inclusion') else item.status|status }} — {{ item.reason }}</p>{% endif %}{% endfor %}<p>Điểm trình bày năm thành phần lịch sử không bao gồm thu hồi; điểm cao không phủ định FAIL.</p></section>{% endif %}
<section><h2>Giới hạn diễn giải</h2><p>Kết quả kiểm tra chứng thư không xác nhận độ an toàn của nội dung hoặc hoạt động kinh doanh website. NOT_VERIFIED về chữ ký SCT/inclusion proof là giới hạn xác minh; không tự kết luận SCT không hợp lệ.</p></section>
<section><h2>Chi tiết kỹ thuật — dữ liệu gốc</h2><p>Các mã trạng thái và lý do gốc được giữ nguyên để đối chiếu engine.</p><pre>{{ technical }}</pre></section>
<footer>DT007 — Trình xác minh chuỗi chứng thư số và chính sách thuật toán</footer></html>"""


def export_result(result: dict[str, Any], *, json_path: Path | None = None, html_path: Path | None = None) -> None:
    """Write UTF-8 artifacts; preserve security codes and escape untrusted strings."""
    technical = json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False)
    if json_path is not None:
        Path(json_path).parent.mkdir(parents=True, exist_ok=True)
        Path(json_path).write_text(technical + "\n", encoding="utf-8")
    if html_path is not None:
        environment = Environment(autoescape=True)
        environment.filters.update(status=translate_status, label=translate_label, reason_vi=translate_reason)
        html = environment.from_string(HTML).render(result=result, technical=technical)
        Path(html_path).parent.mkdir(parents=True, exist_ok=True)
        Path(html_path).write_text(html, encoding="utf-8")
