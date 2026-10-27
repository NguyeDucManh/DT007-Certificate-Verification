from pathlib import Path
import re

old = Path('reports/ui_refresh/original_templates/result.html').read_text(encoding='utf-8')
macros = old[old.index('{% macro badge'):old.index('{% block content %}')]
sections = {}
for match in re.finditer(r'<section class="card[^>]* id="([^"]+)"[^>]*>(.*?)</section>', old, re.S):
    sections[match[1]] = match[0]

def body(name):
    text = sections[name]
    text = re.sub(r'^<section[^>]*>', '', text)
    text = text.removesuffix('</section>')
    return re.sub(r'^<div class="card-heading">.*?</div>', '', text, count=1, flags=re.S)

def sub(name):
    return '<section class="subsection" id="'+name+'">'+sections[name].split('>',1)[1]

header = '''{% extends 'base.html' %}
{% block title %}{{ result.hostname }} · Kết quả xác minh · DT007{% endblock %}
'''+macros+'''
{% macro panel(id, number, title, description, status, icon) -%}
<details class="detail-panel" id="{{ id }}">
  <summary><span class="panel-icon" aria-hidden="true">{{ icon }}</span><span class="panel-label"><span class="panel-title">{{ title }}</span><span class="panel-description">{{ description }}</span></span>{{ badge(status) }}<span class="panel-chevron" aria-hidden="true">⌄</span></summary>
  <div class="panel-body">{{ caller() }}</div>
</details>
{%- endmacro %}
{% block content %}
{% set score = result.security.checks|presentation_score %}
{% set ext = result.extensions or {} %}
<div class="result-toolbar"><a class="back-link" href="{{ url_for('index') }}">← Kiểm tra tên miền khác</a><span class="eyebrow">KẾT QUẢ XÁC MINH</span></div>
<section class="result-hero" aria-labelledby="result-title">
  <div><p class="eyebrow">CHỨNG THƯ TLS · CỔNG 443</p><h1 id="result-title">{{ result.hostname }}</h1><p class="runtime">Thời gian xử lý <span class="mono">{{ '%.4f'|format(result.runtime_seconds) }} giây</span>{% if result.validity %}<span class="checked-at"> · {{ result.validity.current_time }}</span>{% endif %}</p></div>
  <div class="final-block"><span class="eyebrow">KẾT QUẢ CUỐI CÙNG</span><span id="final-result" class="final-result">{{ badge(result.security.status) }}</span></div>
</section>
{% if result.scan_error %}<div class="notice notice-error" role="alert"><strong>Không thể kiểm tra chứng thư của tên miền này.</strong>{{ message(result.scan_error) }}<a href="{{ url_for('index') }}">Thử tên miền khác</a></div>{% endif %}
<div class="overview-grid">
  <section class="card score-card" aria-labelledby="score-title"><h2 id="score-title">Điểm đánh giá</h2><div class="score-value"><strong id="security-score">{{ score }}</strong><span>/ 100</span></div><meter min="0" max="100" value="{{ score }}" aria-label="Điểm đánh giá">{{ score }}/100</meter><p>Năm hạng mục · Đạt 20 / Cảnh báo 10 / Khác 0 điểm.</p></section>
  <section class="card certificate-overview"><p class="eyebrow">CHỨNG THƯ MÁY CHỦ</p>{% if result.certificate %}<h2>{{ result.certificate.subject }}</h2><dl class="kv-list">{{ row('Đơn vị cấp',result.certificate.issuer) }}{{ row('Có hiệu lực đến',result.certificate.not_after) }}</dl>{% else %}<h2>Chưa thu thập được chứng thư</h2><p>Xem nguyên nhân kết nối và bằng chứng bên dưới.</p>{% endif %}</section>
  <section class="card export-card"><p class="eyebrow">BÁO CÁO KIỂM TRA</p><h2>Lưu kết quả này</h2><p>Xuất đúng dữ liệu của lần kiểm tra vừa chạy.</p><div class="export-actions"><button class="button button-secondary" data-export="json" type="button">↓ Xuất JSON</button><button class="button button-secondary" data-export="html" type="button">↓ Xuất HTML</button></div><p id="export-status" class="input-help" role="status" aria-live="polite"></p></section>
</div>
<div class="verdict-note notice notice-{{ 'error' if result.security.status == 'FAIL' else 'warning' if result.security.status == 'WARNING' else 'info' }}"><span class="notice-symbol" aria-hidden="true">{{ '!' if result.security.status != 'PASS' else '✓' }}</span><div>
{% if result.security.status != 'PASS' %}<strong>Vì sao điểm {{ score }}/100 nhưng kết quả {{ result.security.status|translate_status }}?</strong><p>{% if ext.get('revocation',{}).get('status') == 'REVOKED' %}Chứng thư đã bị thu hồi theo bằng chứng từ engine. Điểm năm hạng mục không bao gồm thu hồi.{% elif ext.get('revocation',{}).get('status') in ('ERROR','UNKNOWN','NOT_CHECKED') and 'Revocation' in result.security.checks %}Kiểm tra thu hồi chưa đủ bằng chứng kết luận. Điểm năm hạng mục không bao gồm thu hồi.{% elif findings %}{{ findings[0].explanation }}{% elif result.security.reasons %}{{ (result.security.reasons[0]|translate_reason).text }}{% else %}Một hoặc nhiều thành phần chưa đạt hoặc chưa đủ bằng chứng xác minh. Xem chi tiết kết quả engine bên dưới.{% endif %}</p>{% else %}<strong>Các hạng mục kiểm tra đều đạt yêu cầu.</strong>{% endif %}
<p>Điểm số chỉ dùng để trực quan hóa, không phải chứng nhận an toàn tiêu chuẩn. <strong>90/100 không có nghĩa website thiếu 10% an toàn.</strong> Điểm không thay đổi trạng thái cuối cùng.</p></div></div>
<section class="overview" aria-label="Tổng quan kiểm tra"><div class="summary-checks">{% for label,status in result.security.checks.items() %}<div class="overview-item" data-score-scope="{{ 'true' if label in ('Validity','Hostname','Certificate Chain','Algorithm Policy','Certificate Transparency') else 'false' }}"><span>{{ label|translate_label }}</span>{{ badge(status) }}</div>{% endfor %}</div></section>
<div class="section-heading"><div><p class="eyebrow">BẰNG CHỨNG & PHÂN TÍCH</p><h2>Chi tiết xác minh</h2></div><span class="input-help">Mở từng nhóm để xem dữ liệu đầy đủ</span></div>
<div class="result-grid">
'''
parts = [header]
parts += ["{% call panel('certificate','01','Thông tin chứng thư X.509','Chủ thể, đơn vị cấp và định danh chứng thư', 'PASS' if result.certificate else 'UNKNOWN', '▤') %}"+body('certificate')+"{% endcall %}"]
parts += ["{% call panel('identity-checks','02','Thời hạn và hostname / SAN','Kiểm tra thời gian và danh tính được bảo vệ', result.security.checks.get('Hostname','UNKNOWN'), '⌖') %}"+sub('hostname')+sub('validity')+"{% endcall %}"]
parts += ["{% call panel('chain','03','Chuỗi chứng thư và CA','Đường dẫn tới điểm neo tin cậy độc lập', result.chain.status if result.chain else 'UNKNOWN', '♧') %}"+body('chain')+"{% endcall %}"]
parts += ["{% call panel('algorithm-checks','04','Chính sách thuật toán mật mã','Thuật toán, độ dài khóa và chữ ký số', result.algorithm_policy.status if result.algorithm_policy else 'UNKNOWN', '⚙') %}"+sub('cryptography')+sub('policy')+"{% endcall %}"]
parts += ["{% call panel('ct','05','Certificate Transparency','Đối chiếu CT Log, SCT và bằng chứng inclusion', result.ct.status if result.ct else 'UNKNOWN', '◎') %}"+body('ct')+'''
<div id="advanced-checks"><h3>Nguồn khóa CT đã xác thực</h3>{% set item=ext.get('ct_key_source',{}) %}{{ badge(item.get('status','NOT_CHECKED'),true) }}<p>{{ item.get('reason','Chưa yêu cầu kiểm tra nguồn khóa CT.') }}</p><details class="technical-details"><summary>Bằng chứng nguồn khóa</summary><pre>{{ item|tojson(indent=2) }}</pre></details>
<h3>Xác minh chữ ký SCT</h3>{% for item in ext.get('sct_verification',[]) %}<p>{{ badge(item.status,true) }} {{ item.reason }}</p><details class="technical-details"><summary>Log ID và bằng chứng chữ ký</summary><pre>{{ item|tojson(indent=2) }}</pre></details>{% else %}<p>Chưa có SCT để xác minh.</p>{% endfor %}
<h3>Bằng chứng đưa vào CT Log</h3>{% set item=ext.get('inclusion',{}) %}{{ badge(item.get('status','NOT_VERIFIED'),true) }}<p>{{ item.get('reason','Chưa có inclusion proof được xác minh.') }}</p><details class="technical-details"><summary>STH, Merkle path và consistency</summary><pre>{{ item|tojson(indent=2) }}</pre></details></div>
{% endcall %}
{% call panel('revocation','06','Thu hồi OCSP / CRL','Trạng thái thu hồi và phạm vi bằng chứng', ext.get('revocation',{}).get('status','NOT_CHECKED'), '◷') %}
{% set item=ext.get('revocation',{}) %}{{ badge(item.get('status','NOT_CHECKED')) }}<p>{{ item.get('reason','Chưa bật kiểm tra OCSP/CRL cho lần quét này.') }}</p><p>Điểm số chỉ gồm năm thành phần lịch sử, không bao gồm thu hồi. Điểm cao không phủ định kết quả KHÔNG ĐẠT do chứng thư bị thu hồi.</p><pre>{{ item|tojson(indent=2) }}</pre>
{% endcall %}
{% call panel('aia','07','AIA và nguồn chứng thư','Bổ sung chuỗi và nguồn dữ liệu TLS', ext.get('aia',{}).get('status','NOT_CHECKED'), '⇄') %}
{% for key,title in [('aia','Bổ sung chuỗi qua AIA'),('tls_collection','Nguồn thu thập TLS')] %}{% set item=ext.get(key,{}) %}<h3>{{ title }}</h3>{{ badge(item.get('status','NOT_CHECKED')) }}<p>{{ item.get('reason','Chưa yêu cầu kiểm tra bổ sung.') }}</p><pre>{{ item|tojson(indent=2) }}</pre>{% endfor %}
{% endcall %}
{% call panel('evidence','08','Chi tiết kỹ thuật và bằng chứng','Nguyên nhân, tổng hợp và toàn bộ dữ liệu gốc', result.security.status, '≡') %}
''']
parts.append(sections['detected-findings'])
parts.append("{% if result.errors %}"+sections['module-errors']+"{% endif %}")
parts.append(sections['security-summary'])
parts.append('''<details class="technical-details"><summary>Toàn bộ dữ liệu phân tích (JSON)</summary><pre id="raw-result">{{ result|tojson(indent=2) }}</pre></details>
{% endcall %}
</div>
<p class="result-bottom"><span>Kết quả phản ánh chứng thư tại thời điểm kiểm tra; không xác nhận an toàn nội dung website.</span><a class="back-link" href="{{ url_for('index') }}">Kiểm tra tên miền khác →</a></p>
<script type="application/json" id="result-data">{{ result|tojson }}</script>
{% endblock %}
''')
Path('templates/result.html').write_text('\n'.join(parts),encoding='utf-8')

# Keep existing demo evidence and all forms/IDs used by the routes and tests.
old = Path('reports/ui_refresh/original_templates/demo.html').read_text(encoding='utf-8')
start=old.index('<section class="home-hero">')
end=old.index('{% if outcome %}')
old=old[:start]+'''<section class="page-heading"><p class="eyebrow">DỮ LIỆU GIẢ LẬP – PHỤC VỤ KIỂM THỬ</p><h1>Phòng Demo chứng thư số</h1><p class="hero-description">14 tình huống có kiểm soát. Chạy từng ca để khám phá, hoặc kiểm tra toàn bộ trong một lượt.</p><span class="visually-hidden">PHÒNG KIỂM THỬ CHỨNG THƯ SỐ</span></section>
<section class="demo-controls scan-card"><div><h2>Chạy bộ kiểm thử</h2><p>Mỗi lần chạy tạo chứng thư mới và gọi các bộ xác minh thực.</p></div><form method="post" action="{{ url_for('demo') }}" class="batch-form"><input type="hidden" name="action" value="all"><button class="button button-primary batch-run" type="submit">CHẠY TOÀN BỘ 14 CA KIỂM THỬ</button><p class="batch-progress" role="status" hidden>Đang thực thi tất cả các ca trong manifest. Vui lòng đợi...</p></form>
{% if error %}<div class="notice notice-error" role="alert">{{ error }}</div>{% endif %}
<details class="quick-select"><summary>Chọn nhanh một ca kiểm thử</summary><form method="post" action="{{ url_for('demo') }}" id="demo-form"><label for="case-id">Trường hợp kiểm thử</label><div class="input-row"><select id="case-id" name="case_id" required>{% for case in cases %}<option value="{{ case.id }}" {% if outcome and outcome.case_id == case.id %}selected{% endif %}>{{ case.label }}</option>{% endfor %}</select><button class="button button-secondary" type="submit" id="demo-button">CHẠY KIỂM THỬ</button></div><p id="demo-progress" role="status" hidden>Đang tạo dữ liệu giả lập và chạy kiểm tra...</p></form></details></section>
<div class="notice notice-info"><span class="notice-symbol" aria-hidden="true">ⓘ</span><p><strong>Hai kết quả, hai ý nghĩa.</strong> Chứng thư cố tình sai có thể <strong>KHÔNG ĐẠT</strong> bảo mật nhưng bài kiểm thử vẫn <strong>THÀNH CÔNG</strong> khi công cụ phát hiện đúng điều kiện khảo sát.</p></div>
{% if outcome %}<div class="demo-verdicts"><div class="card"><p class="eyebrow">KẾT QUẢ BẢO MẬT CHỨNG THƯ</p><span class="badge status-{{ 'fail' if outcome.status == 'FAIL' else 'warning' if outcome.status == 'WARNING' else 'pass' if outcome.status == 'PASS' else 'neutral' }}" data-status="{{ outcome.status }}">{{ outcome.status|translate_status }}</span></div><div class="card"><p class="eyebrow">KẾT QUẢ BÀI KIỂM THỬ</p><span class="badge status-{{ 'pass' if outcome.test_success else 'fail' }}">{{ '✓ KIỂM THỬ THÀNH CÔNG' if outcome.test_success else '× KIỂM THỬ THẤT BẠI' }}</span></div></div>{% endif %}
<div class="section-heading"><div><p class="eyebrow">BỘ CA CÓ KIỂM SOÁT</p><h2>Chọn một tình huống</h2></div><span class="input-help">14 ca · Thực thi offline</span></div>
{% set descriptions={
'EXPIRED_CERTIFICATE':'Chứng thư đã hết hạn tại đồng hồ giả lập.',
'NOT_YET_VALID_CERTIFICATE':'Chứng thư chưa tới thời điểm có hiệu lực.',
'HOSTNAME_MISMATCH':'Tên miền yêu cầu không khớp danh sách SAN.',
'RSA_1024':'Khóa RSA ngắn hơn mức tối thiểu trong policy.',
'SHA1_SIGNATURE':'Đối chiếu chữ ký SHA-1 với chính sách thuật toán.',
'MD5_SIGNATURE':'Kiểm tra chính sách chữ ký MD5 khi backend hỗ trợ.',
'BROKEN_CHAIN':'Liên kết giữa đơn vị cấp và chủ thể không khớp.',
'INVALID_SIGNATURE':'Chữ ký chứng thư không được xác minh bởi issuer.',
'NON_CA_INTERMEDIATE':'Chứng thư trung gian không có quyền CA.',
'SELF_SIGNED_LEAF':'Chứng thư tự ký không thuộc chuỗi tin cậy lab.',
'UNKNOWN_CT_LOG':'Log ID của SCT không có trong dữ liệu giả lập.',
'RETIRED_CT_LOG':'SCT được ghi nhận sau khi CT Log ngừng hoạt động.',
'SCT_TIMESTAMP_OUTSIDE_INTERVAL':'Ca hồi quy phân biệt thời điểm SCT và khoảng hết hạn.',
'NO_SCT':'Chứng thư không có SCT nhúng để đối chiếu.'} %}
<div class="demo-case-grid">{% for case in cases %}<article class="case-card"><div class="case-top"><span class="case-number">{{ '%02d'|format(loop.index) }}</span><span class="case-category">{{ 'Minh bạch CT' if case.type in ('UNKNOWN_CT_LOG','RETIRED_CT_LOG','SCT_TIMESTAMP_OUTSIDE_INTERVAL','NO_SCT') else 'Chứng thư X.509' }}</span></div><h3>{{ case.label }}</h3><p>{{ descriptions.get(case.type,'Tạo dữ liệu và đối chiếu kết quả thực thi.') }}</p><form method="post" action="{{ url_for('demo') }}" class="case-form"><input type="hidden" name="case_id" value="{{ case.id }}"><button class="button button-secondary" type="submit">Chạy ca này <span aria-hidden="true">→</span></button><p class="case-progress input-help" role="status" hidden>Đang chạy kiểm thử…</p></form></article>{% endfor %}</div>
'''+old[end:]
# Collapse verbose single-case evidence, while keeping separate security and test results above.
old=old.replace('<section class="card demo-result" id="lab-evidence">', '<details class="detail-panel" id="lab-evidence"><summary><span class="panel-icon" aria-hidden="true">≡</span><span class="panel-label"><span class="panel-title">Bằng chứng thực thi</span><span class="panel-description">Chứng thư, nguồn dữ liệu và module đã chạy</span></span><span class="panel-chevron" aria-hidden="true">⌄</span></summary><div class="panel-body">')
old=old.replace('</section>\n{% endif %}\n{% if batch %}', '</div></details>\n{% endif %}\n{% if batch %}')
Path('templates/demo.html').write_text(old,encoding='utf-8')
