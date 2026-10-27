# DT007 — Tiến độ rà soát 10/10/2026

Hoàn thành bốn giai đoạn công việc kỹ thuật trong phiên, chưa tuyên bố yêu cầu
giảng viên đạt 100% vì còn các xác nhận bên ngoài. Xem reports/final_review.md
và reports/requirements_traceability.md trước khi tiếp tục; không đọc .venv/cache.

- Cuối phiên: 426 pytest PASS, 0 fail/error/skip; 37 imports, 0 lỗi.
  Evidence: reports/final_validation/final_browser_20261010/pytest.xml,
  pytest.log, validation.json. 374 tests trước phiên được giữ; thêm 52.
- Audit 90 quan sát lịch sử: verified true, 0 sai lệch; raw không đổi.
  Baseline 10/14=71,428571%; coverage 13 mục=76,923077%; FN6/36, FP0/3.
  Extended 14/14, FN0/36. Hai FN/lượt là UNKNOWN_CT_LOG/RETIRED_CT_LOG.
- Nghiên cứu mới sau sửa TLS: reports/research_expanded/post_tls_20261010,
  114 quan sát=3×2×(14+5 controls), FP0/15 mỗi profile, FN baseline6/36,
  extended0/36. Audited verified true. Wall/CPU/RSS/SD/CV/t95 lưu raw/summary;
  resource scope khác CPU utilization/peak RAM từng ca, không suy rộng Internet.
- Sửa src/chain_validator.py: mục đích TLS EKU/KU, trust FAIL/anchor None khi
  không cho TLS server. Test 4 failures trước, 7 PASS sau. Không đổi CT/policy.
- CLI thêm --json/--html, cùng một lần engine, autoescape; lệnh cũ giữ nguyên.
- 3 live+synthetic runs mới: reports/final_experiments/run_1..3, mỗi19/19khớp.
  google/github/cloudflare CLI và HTTP đều WARNING; CT crypto NOT_VERIFIED.
- Edge headless actual engine: reports/browser_smoke/final_20261010,
  13 UI checks đạt, screenshots desktop/390px đã xem, CSV download14ca.
  Hai lần harness lỗi đầu lưu riêng; sửa transport/selector, không sửa security.
- Báo cáo PDF27trang, HTML, biểu đồ PNG/SVG và14slideHTML ở reports/scientific;
  document_validation.json có hashes và426testcounts. Demo_script.md sẵn có.
- requirements-lock.txt thực pip freeze; requirements-research.txt thêm công cụ
  schema/plots/report, không frontend framework/database/login mới.
- Hash preservation_check.json: synthetic_cases.py,14case manifest,policy,
  Google dataset không đổi. Không ghi đè raw/evidence lịch sử.

Việc còn cần xác nhận: Q1 trực tiếp/cơ sở thầy chấp nhận (Oxford JIF2025 rank
14/275 đã kiểm chứng; Crossref DOI/date đã lưu); quyền tái phân phối CT snapshot;
acquisition gốc/detached signature đúng snapshot chưa có; template trường và
tên sinh viên/giảng viên; oral/video defense; điện thoại vật lý/clipboard OS.
Không có SCT cryptographic verification/inclusion proofs, OCSP/CRL/AIA hoặc
Internet labeled ground truth; không giả hoàn thành các giới hạn này.

Chạy tiếp bằng .venv\Scripts\python.exe hoặc activate venv; py ngoài venv có
thể mặc định Python2.7. Research/validation runners yêu cầu output directory
MỚI/trống. Không dùng lại tên thư mục cũ, không sao chép số liệu mẫu addon.
Mỗi sửa ảnh hưởng security phải có regression và remeasure output mới.
