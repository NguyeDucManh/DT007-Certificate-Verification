# Đối chiếu yêu cầu giảng viên và bằng chứng DT007

**Kiểm toán hiện tại 18/10/2026:** xem [../FINAL_ACCEPTANCE.md](../FINAL_ACCEPTANCE.md).
539 pytest PASS/0 FAIL/0 ERROR/0 SKIP, Demo 14/14; evidence thực chạy ở
`submission_audit/workspace_verified/` và `submission_audit/workspace_live/`.
CLI mặc định/advanced, JSON/HTML và Flask localhost đạt. PDF hiện có giữ nguyên.
Trusted signed Google registry + precert reconstruction + SCT/STH/Merkle proof
đã nối pipeline advanced; bằng chứng bytes live ở `code_validation/ct_live/`.
Consistency không có checkpoint độc lập trong scan nên vẫn NOT_VERIFIED.
Tiled/static proof chưa hỗ trợ. AIA integration TLS/HTTP cục bộ có thực chạy;
chưa public live missing-intermediate. Các số 515/508 ở checkpoint khác là lịch sử.

| Nhóm yêu cầu gốc | Đối chiếu bàn giao hiện tại |
|---|---|
| 1. Bài báo nền | `paper_review.md`: phương pháp, nguồn/metrics, 7 hạn chế; không tái lập nghiên cứu quản trị; Q1 còn cần chứng cứ đúng cơ sở/năm |
| 2. Google CT | Snapshot/schema/EDA/hash nguyên vẹn; chữ ký snapshot gốc và quyền tái phân phối chưa xác nhận; `../DATA_NOTICE.md` |
| 3. Môi trường | Python 3.14 Windows, requirements + lock, seed/config/machine; README tạo venv mới; clean validation lưu riêng |
| 4. Dữ liệu/rủi ro | `research_protocol.md`: EDA, threat model, trust boundary, leakage, imbalance, privacy; không áp đặt train/test ML cho rule-based |
| 5. Cốt lõi | X.509/time/SAN/hostname/chain/signature/trust/policy/CT, Baseline/Extended, JSON/HTML, 539 tests và 14 Demo |
| 6. Thực nghiệm | Raw90/raw114 giữ nguyên; chạy mới 3 repeats seed20261010 ở `submission_audit/research_rerun`, CPU/RSS đo đúng phạm vi |
| 7. Đánh giá | Coverage/FP/FN/runtime/ablation/SD/CV/t95 n=3, audit số học cũ không sai lệch; cỡ mẫu nhỏ, không suy rộng Internet |
| 8. Tái lập/bàn giao | Source/tests/evidence/PDF giữ; ZIP loại cache/env/temp; chưa thể tuyên bố dataset đã được cấp phép phân phối rộng rãi |

## Ma trận checkpoint nghiên cứu và phát triển 10/10/2026 (lịch sử)

Các mô tả chưa tích hợp SCT/inclusion trong bảng cũ dưới đây là lịch sử;
trạng thái triển khai hiện tại được nêu phía trên. Không thay số liệu nghiên cứu cũ.

Bổ sung sau nâng cấp: [security_extensions_completion.md](security_extensions_completion.md)
đối chiếu OCSP/CRL, AIA và CT crypto theo bốn mức triển khai/offline/live/chưa hỗ trợ.
Suite mới 508 PASS (final_verified_20261010); các dòng/bằng chứng trước dưới đây
là trạng thái nghiên cứu trước nâng cấp, không sửa hoặc thay thế số liệu lịch sử.

Phạm vi đối chiếu: mô tả đề tài DT007 trong ảnh/tin nhắn đã cung cấp và các yêu cầu bổ sung của người dùng. “Đã có” nghĩa có mã/tài liệu/bằng chứng thực thi, không phải được giảng viên nghiệm thu. Không tự bổ sung nhiệm vụ ML/database/login.

| Yêu cầu | Mã/tài liệu | Bằng chứng | Trạng thái và giới hạn |
|---|---|---|---|
| X.509, SAN, hostname, thời hạn | src/certificate_parser.py, hostname_validator.py, validity_checker.py | tests tương ứng; system_smoke/20261010 | Đã có; không xác minh nội dung website |
| Chuỗi, chữ ký, CA, trust anchor | src/chain_validator.py, certificate_fetcher.py | test_chain_validator.py, test_chain_provenance.py, test_tls_chain_purpose.py | Đã có; không AIA/OCSP/CRL |
| Thuật toán/key size/hash | src/algorithm_policy.py, config/algorithm_policy.json | test_algorithm_policy.py; 14 ca thực thi | Đã có; không tuyên bố compliance mọi chuẩn browser |
| CT dataset nguồn/version/schema/hash/chất lượng | data/log_list.json, ct_dataset_profile.json, ct_snapshot_validation.json | schema gốc trong research_sources/20261010; 69 SPKI/ID | Đã kiểm tra; acquisition gốc, detached signature chưa có |
| Điều khoản/giấy phép CT data | research_sources/verification.md, ct_log_lists.md | URL/chính sách/hash trong sources.json | Có điều khoản sử dụng; quyền tái phân phối snapshot chưa xác nhận |
| CT/SCT metadata, state, thời gian | src/ct_validator.py, sct_parser.py | test_ct_validator.py; ct_interval_review.md | Đã có; chữ ký SCT/inclusion proof NOT_VERIFIED |
| Baseline + biến thể hợp lý | synthetic_cases.py profile; security_evaluator.py | research_expanded/post_tls_20261010 | Đã có CT ablation; không phải baseline thuật toán của bài báo quản trị |
| Ít nhất 3 lần chạy, seed/log/config/raw | experiments/research_study.py, run_experiments.py | post_tls_20261010 và final_experiments/run_1..3 | Đã có; seed chỉ thứ tự, không seed RSA |
| Coverage, FP/FN, runtime | audit_research_metrics.py, research_study.py | metrics_audit/audit.json; raw/summary mới | Đã đo; FP/FN không đại diện Internet |
| CPU/RAM | resource_metrics.py | raw CSV, setup metrics, machine.json | CPU time/RSS boundary/process peak; không peak mỗi ca hoặc CPU utilization |
| Ổn định/CI/ablation phù hợp | research_study.describe; nghiên cứu mở rộng | mean/SD/CV/t95 trong summary | Có mô tả n=3; không kết luận có ý nghĩa thống kê/population |
| Nhãn đối chứng độc lập với actual | experiments/research_controls.py | PEM/oracle_verified trong evidence | 5 loại, 3 lần; oracle chia sẻ OpenSSL, không mật mã độc lập |
| Bài báo DOI/phương pháp/dữ liệu/≥5 hạn chế | paper_review.md, research_sources/verification.md | Crossref gốc; bản tác giả/nguồn Oxford | Đã có; chưa tái lập thống kê quản trị của paper |
| Q1 đúng năm/cơ sở | research_sources/verification.md | Oxford JIF 2025 rank 14/275 | Suy ra nhóm 25% đầu; thiếu bản JCR trực tiếp/cơ sở được thầy chấp nhận |
| EDA/threat model/leakage/class imbalance/privacy | research_protocol.md, báo cáo khoa học | dữ liệu và mục giới hạn | Đã phân tích; rule-based nên không train/test ML |
| CLI/Web/Demo giữ đủ 14 ca | main.py, app.py, demo_service.py | pytest; system_smoke; browser_smoke/final_20261010; final_experiments | HTTP/engine và Edge headless đạt; chưa điện thoại vật lý/clipboard OS |
| JSON/HTML | src/report_export.py; main.py --json/--html | test_report_export.py; live artifacts | Đã có, cùng engine, Unicode và XSS escaping |
| Unit/integration/negative/regression | tests/ | final_validation thư mục cuối, pytest.xml/pytest.log | Số lượng cuối lấy từ kết quả thực chạy |
| Dependency lock/môi trường/tái lập | requirements-lock.txt, requirements-research.txt, README.md | pip freeze máy này; config/hashes | Đã ghi; lock Windows/Python 3.14, nền tảng khác cần kiểm tra |
| Báo cáo 20–30 trang/bảng/biểu đồ/limitations | reports/scientific/scientific_report.pdf/html; experiments/build_scientific_report.py | scientific/document_validation.json: 27 trang | PDF thực đã kiểm tra; thông tin sinh viên/định dạng trường cần điền/đối chiếu |
| Demo/slides/video ngắn | scientific/defense_slides.html, demo_script.md | 14 slide dựa summary/evidence | Slide/kịch bản có; video thuyết trình và nộp/duyệt bởi thầy chưa thực hiện |

Không đánh dấu hoàn thành 100% khi các mục có giới hạn/chưa xác nhận ở trên còn tồn tại.
