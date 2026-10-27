# DT007 — Báo cáo hoàn thiện và bằng chứng

## 1. Kiểm chứng metrics

Audit độc lập 90 quan sát lịch sử: **0 sai lệch**, 3 lần × 2 profiles × 15 ca.
Baseline coverage 10/14 = 71,428571%, coverage lỗi/cần lưu ý 10/13 = 76,923077%.
FN=6/36: UNKNOWN_CT_LOG và RETIRED_CT_LOG, mỗi loại 3 lần.
Extended coverage 14/14 và FN=0/36. FP lịch sử 0/3 đối chứng mỗi profile.
14 mục gồm một hồi quy semantics, không phải 14 lỗ hổng. ERROR/SKIPPED tách
khỏi confusion, không được coi là negative; vẫn ở mẫu số coverage kế hoạch.
Mẫu số, aggregates, runtime scope và hash: `metrics_audit/report.md`, `audit.json`.

## 2. Nghiên cứu mới sau sửa engine

**114 quan sát thực**, 3 × 2 × (14 ca giữ nguyên + 5 loại control), lưu riêng
`research_expanded/post_tls_20261010/`. Audit key claims: verified=true, 0 sai lệch.

| Chỉ số | Baseline | Extended |
|---|---:|---:|
| Coverage 14 điều kiện | 71,428571% | 100% |
| Coverage 13 lỗi/cần lưu ý | 76,923077% | 100% |
| FP / controls hoàn thành | 0/15 | 0/15 |
| FN / ca kỳ vọng FAIL hoàn thành | 6/36 | 0/36 |
| Runtime mean/14 ca (ms) | 2,712493 | 3,038060 |
| CPU time mean/lượt 19 ca, chưa setup (s) | 0,130208 | 0,197917 |
| RSS boundary max (MiB) | 36,984375 | 37,035156 |

Control X.509 có nhãn thuộc tính trước engine, OpenSSL oracle invocation riêng,
PEM public và module/checks trong evidence. Không chia sẻ private key. Nhãn
không lấy từ actual; oracle vẫn cùng backend OpenSSL, không là triển khai độc lập.
Năm loại control lặp 3 lần không là 15 tình huống population độc lập.
CPU time không phải utilization, RSS sampled không phải peak mỗi ca.
Mean/SD/CV/min/max/t95 n=3 mô tả biến thiên, không chứng minh ý nghĩa thống kê.
CT ablation không tái lập thống kê quản trị WebPKI của bài báo gốc.

Ba lượt live+synthetic mới trong `final_experiments/run_1..3`: mỗi lượt 19/19
khớp kỳ vọng, 0 errors/skips, đủ 14 ca; 5 website observational normal case.
Không lấy 100% agreement này làm accuracy Internet.

## 3. Lỗi và chức năng đã hoàn thiện

- Sửa chain offline chấp nhận EKU chỉ clientAuth hoặc KU không cho TLS: 4
  negative tests tái hiện trước sửa; sau sửa 7/7 purpose tests PASS. Khi usage
  FAIL, trust FAIL, không có anchor đã xác minh. Không dùng private pyOpenSSL API.
- Thêm CLI `--json/--html`: một lần fetch/engine, giữ security codes/reasons,
  đúng target port, UTF-8, HTML autoescape và mở độc lập bằng browser.
- Thêm hai auditor, 5 controls, đo process resources, archived sources/schema,
  quality checks, runner validation/import và builder báo cáo/biểu đồ.
- Runner nghiên cứu cũ/mới từ chối output không trống để giữ evidence.
- Giữ CT signature/inclusion NOT_VERIFIED, không đổi WARNING thành PASS.
- Hash xác nhận `synthetic_cases.py`, manifest 14 ca, policy và snapshot Google
  không đổi so với nghiên cứu lịch sử: `preservation_check.json`.

## 4. Kiểm thử và giao diện

Kết quả full suite/import cuối trong `final_validation/final_browser_20261010/`:
**426 PASS, 0 FAIL, 0 ERROR, 0 SKIP; 37 modules import thành công, 0 lỗi**.
Số lượng thực từ pytest.xml/validation.json; log UTF-8 lưu đầy đủ.
Các lượt checkpoint trước (381, 400, 413, 419 tests) không thay cho kết quả cuối.

HTTP thật + CLI: google.com/github.com/cloudflare.com đều WARNING, HTTP 200,
CLI exit 0; input sai 400, request quá lớn 413, không traceback.
Edge headless thật: **13 UI checks đạt**, score 90, 2 SCT của google.com tại lần
scan, timeline, loading/disabled, accordion, single/batch 14 ca, detail link,
CSV download và desktop/390px không overflow. Screenshots đã xem trực quan.
Hai lần harness lỗi được giữ; sửa handshake/selector của bộ kiểm tra, không
sửa engine/UI để làm đẹp kết quả. Clipboard OS/điện thoại vật lý chưa kiểm tra.

## 5. Tài liệu và file thay đổi

File hiện có đã sửa: `main.py`, `src/chain_validator.py`,
`src/certificate_service.py`, `src/web_presentation.py`,
`experiments/research_evaluation.py`, `README.md`, `.gitignore`,
`reports/paper_review.md`. Không sửa `synthetic_cases.py`, policy, CT engine,
hostname/validity modules, manifest 14 ca hoặc tests cũ trước phiên này.

Mã mới: `src/report_export.py`; `experiments/audit_research_metrics.py`,
`audit_expanded_study.py`, `research_controls.py`, `resource_metrics.py`,
`research_study.py`, `collect_research_sources.py`, `validate_ct_snapshot.py`,
`system_smoke.py`, `browser_smoke.py`, `run_validation.py`,
`build_scientific_report.py`; 8 file tests mới tương ứng.

Environment: `requirements-research.txt` và `requirements-lock.txt`.
Tài liệu mới: `metrics_audit/`, `research_sources/`, `research_expanded/`,
`ct_snapshot_validation.json`, `system_review.md`, `system_smoke/`,
`browser_smoke/`, `final_experiments/`, `final_validation/`,
`requirements_traceability.md`, `demo_script.md`, `scientific/` và báo cáo này.
Báo cáo khoa học PDF **27 trang thực**, HTML cùng nội dung, 2 biểu đồ PNG/SVG,
14 slide HTML. Hashes/số trang/test counts tại `scientific/document_validation.json`.

## 6. Những mục chưa được xác nhận/không được tuyên bố hoàn thành

1. Q1: Oxford JIF 2025 rank 14/275 thuộc 25% đầu, có cơ sở suy ra Q1;
   chưa bản JCR trực tiếp hoặc xác nhận cơ sở giảng viên chấp nhận. Requests
   tải Oxford bị 403; Crossref/schema/policy tải thật, failures lưu nguyên.
2. Quyền tái phân phối snapshot CT cụ thể chưa xác nhận; Acceptable Use Policy
   chính thức đã lưu. Không tự gán Apache license cho dataset.
3. Acquisition time gốc và detached signature của snapshot không có; không
   phục dựng/bịa. Checksum/schema/SPKI-ID không thay chữ ký publisher.
4. SCT signatures/inclusion, OCSP/CRL/AIA, Internet ground truth và peak RAM
   riêng mỗi ca không nằm trong phần đã xác minh. Không suy website mất an toàn
   từ giới hạn công cụ hoặc score 90.
5. Báo cáo là dự thảo kỹ thuật; cần điền sinh viên/giảng viên và đối chiếu mẫu
   trường. Slide/kịch bản có; video, bảo vệ và nghiệm thu chưa thực hiện.
6. Chưa kiểm tra điện thoại vật lý/clipboard OS; Edge viewport có evidence.

Không đánh dấu hoàn thành 100% trong khi những mục cần xác nhận còn tồn tại.
