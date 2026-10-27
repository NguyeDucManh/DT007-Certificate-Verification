# DT007 — Kiểm toán và tổng kết phiên bản cuối

## Trạng thái bàn giao hiện tại — 18/10/2026

**539 PASS, 0 FAIL, 0 ERROR, 0 SKIP**, 1 cảnh báo backend cho fixture chứng thư.
Evidence thực chạy: `reports/submission_audit/workspace_verified/pytest.xml`,
`pytest.log`, `validation.json`. Tất cả module import thành công. Lượt đầu dùng
`.pytest_tmp` cũ gặp WinError 5 (480 passed/59 errors); evidence được giữ tại
`workspace_suite`. Runner đã sửa để dùng thư mục tạm riêng cho mỗi lần chạy;
không sửa tests hoặc xóa tests để đạt PASS.

Demo **14/14**; CLI `google.com` mặc định và `--advanced`, JSON/HTML và Flask
HTTP localhost (trang chủ, Demo batch, đầu vào sai 400) đều thực chạy thành công:
`reports/submission_audit/workspace_live/`. Lượt sandbox bị chặn socket 10013
được giữ riêng ở `workspace_smoke`; không gọi lỗi môi trường là lỗi chứng thư.

CT hiện tại dùng `ct_registry.py` kiểm chữ ký list Google với public key pin;
`ct_signed_input.py` dựng precert input; `ct_crypto.py` xác minh chữ ký SCT;
`ct_inclusion.py` bind leaf, chữ ký STH/freshness và Merkle path RFC6962.
Evidence live lịch sử có bytes/chains/download hashes trong
`reports/code_validation/ct_live/{google.com,github.com,cloudflare.com}/`.
Ba website trong bộ evidence đó có SCT và inclusion VALID tại thời điểm thu thập;
không suy ra mọi website đều có proof. `tests/test_ct_pipeline.py` kiểm positive,
negative, RSA/ECDSA, registry giả/sai chữ ký/stale, binding và checkpoint.
Không có checkpoint độc lập trong scan thông thường: consistency/gossip
**NOT_VERIFIED**. Tiled/static proof chưa hỗ trợ. Nguồn registry live không
xác thực ngược snapshot gốc. AIA có TLS/HTTP integration cục bộ thực trong
`tests/test_aia_local_tls.py`; chưa chứng minh cứu live public missing-intermediate.

Giữ nguyên source cốt lõi, 14 ca, policy/ground truth/metric, snapshot và raw
90/114. SHA256 trước/sau ở `reports/submission_audit/preservation_*.json`:
127 file kiểm tra, chỉ `experiments/run_validation.py` thay đổi theo dự kiến.
PDF/HTML khoa học và dữ liệu nghiên cứu cũ không đổi. Ba lần thực nghiệm mới
seed 20261010 ở `research_rerun/`: 114 quan sát; Baseline coverage 71,43%,
FP=0/FN=6; Extended 100%, FP=0/FN=0. Đây là xác nhận riêng, không thay thế raw cũ.
CPU process time; RSS tại biên ca, peak lifetime; t95 n=3 chỉ mô tả.

Đóng gói qua `experiments/package_submission.py`; phân loại A/B/C/D từng file
và các cây môi trường trong `reports/submission_audit/file_inventory.json`.
Không xóa source; loại môi trường/cache/temp/private fixture keys, slides và
bản báo cáo khoa học trùng khỏi ZIP. Các module mở rộng đang dùng được giữ.
Kiểm chứng bản giải nén với môi trường Python mới cài lock: **539 PASS**, 0 lỗi,
49 imports thành công, Demo **14/14**, CLI mặc định/advanced + JSON/HTML đạt,
Flask localhost đạt. `clean_isolation.json` xác nhận 47 module nguồn thực sự nạp
từ thư mục giải nén, không từ workspace gốc. Evidence ở
`reports/submission_audit/clean_*`; thông tin ZIP cuối ở `dist/package_summary.json`.
Không có ZIP trước đó trong workspace nên không có dung lượng ZIP cũ để so sánh.

Các mục chưa đủ bằng chứng: quyền tái phân phối snapshot (xem `DATA_NOTICE.md`),
Q1 theo năm/cơ sở được giảng viên chấp nhận, acquisition/chữ ký snapshot gốc,
CT consistency độc lập/gossip/static proof và AIA cứu website công khai.
Không đánh dấu hoàn tất 100%; không tạo PowerPoint/video hoặc dựng lại báo cáo.

## Checkpoint nghiệm thu 10/10/2026 — lịch sử trước nâng cấp CT

Các số 515 và mô tả CT dưới đây chỉ phản ánh checkpoint cũ. Trạng thái hiện tại
ở phần trên; không áp dụng các giới hạn triển khai cũ cho pipeline mới.

Ngày 2026-10-10. Không tuyên bố hoàn thiện 100%. Kết quả dưới đây phân biệt code có tồn tại, code được gọi trong scan, offline và live.

## Chức năng đã hoàn thành và luồng gọi

| Chức năng | Web/CLI thực sự gọi | Offline | Live và giới hạn |
|---|---|---|---|
| OCSP/CRL | Có khi checkbox/--advanced; cùng CertificateAnalysis đi vào JSON/HTML | GOOD/REVOKED/UNKNOWN/NOT_CHECKED/ERROR; chữ ký/issuer/stale/network/SSRF | CRL google/cloudflare GOOD; OCSP github ERROR do freshness 24h (evidence phase2). CLI google mới GOOD, final WARNING |
| AIA | Có khi advanced; chỉ tải nếu đường dẫn chưa PASS | Intermediate thật, sai CA/chữ ký/issuer, dữ liệu lỗi, vòng lặp, thiếu anchor, timeout | Website đầy đủ chain không cần tải; chưa có live missing-intermediate được cứu |
| TLS inspection riêng | Có khi advanced và verified handshake lỗi issuer code20/21 | Recovery gate; hostname sai và thiếu anchor vẫn FAIL | Chưa có handshake lỗi issuer thực được phục hồi live; luồng chính vẫn verified TLS |
| SCT signature | verify_sct được gọi trong scan, nhưng trusted_keys hiện rỗng | Chữ ký EC thật, entry X.509, input precert rõ; sai chữ ký, thiếu dữ liệu và unsupported; nhánh CT RSA có code nhưng chưa có test riêng | NOT_VERIFIED. Chưa cấu hình nguồn khóa được xác thực độc lập, chưa tái dựng precert từ chứng thư cuối |
| STH/inclusion | Chưa được gọi trong scan; kết quả inclusion luôn NOT_VERIFIED | STH signature và Merkle path 1/3 lá có primitive/tests | Chưa tự truy vấn endpoint, bind leaf/STH hoặc xác minh freshness/consistency/tiled/static CT |

TLS recovery nằm trong src/untrusted_tls.py, không sửa certificate_fetcher.py. DNS/public-IP pin và timeout dùng transport đã có; chỉ cổng443, peer chain tối đa8/256KiB. Một context inspection riêng không xác minh handshake chỉ để lấy dữ liệu chưa tin cậy; anchors được lấy trước từ context hệ thống độc lập. Dữ liệu không được dùng làm anchor. certificate_security.py vẫn chạy hostname/thời hạn/CA/chữ ký/policy và validate_chain trước khi kết luận. Recovery chỉ thử code20/21; hết hạn hoặc lỗi khác không được tự bypass. Các lỗi mạng/thu hồi không bị biến thành GOOD.

Sửa lỗi provenance khi AIA được gọi: giữ peer_certificates để giao diện không mất nguồn chuỗi máy chủ gửi. Kiểm thử recovery kiểm tra cả thuộc tính này.

## Nhất quán đầu ra và điểm số

Web, CLI và JSON/HTML cùng pipeline; không chạy engine khác để tạo actual. GOOD thu hồi không xóa CT WARNING; REVOKED kéo FAIL; ERROR/UNKNOWN/NOT_CHECKED kéo WARNING khi bật advanced. Mặc định profile cũ giữ nguyên và hiển thị NOT_CHECKED rõ.

Điểm vẫn dựa năm hạng mục lịch sử, không gồm thu hồi. Đã thêm giải thích ở Web và HTML: điểm cao không phủ định FAIL do revocation. Không diễn giải 90/100 là thiếu 10% an toàn. Score không được dùng để sửa engine result.

## Kiểm thử thực chạy

- **515 PASS, 0 FAIL, 0 ERROR, 0 SKIP**; 43 modules import thành công. Evidence cuối: reports/final_acceptance/validation_final/{pytest.xml,pytest.log,validation.json}. Checkpoint trước cũng giữ tại validation/.
- 89 kiểm thử liên quan OCSP/CRL/AIA/CT/recovery đạt trước full suite. Bảy tests mới cuối kiểm tra recovery opt-in, gating, thiếu trust anchor, hostname mismatch, giới hạn port và CA=false. Fixture/mock recovery kiểm tra orchestration; không giả là TLS live.
- Edge headless 13/13 checks đạt; 14 ca Demo, chạy single/batch/CSV, loading, timeline, SCT accordion, score, desktop và viewport390px. reports/final_acceptance/browser/summary.json và screenshots. Đây là viewport giả lập, chưa điện thoại vật lý; browser harness chạy scan mặc định, lựa chọn advanced được kiểm tra bằng Flask test client live.
- CLI google.com --advanced: CRL GOOD, final WARNING. live_google.json/live_google.html/live_cli.log tại reports/final_acceptance/.
- Flask live cloudflare.com advanced HTTP200, có phần extensions; input sai HTTP400. live_web.html/web_checks.json cùng thư mục.
- Không có test biến việc mất kết nối toàn máy thành GOOD. Offline fixtures và timeout/SSRF transport tests kiểm tra riêng, không cần Internet. Chưa có chứng thư revoked thật trên Internet được xác nhận trong lượt này.

## Bảo toàn trước/sau và nghiên cứu

preservation_before.json/preservation_after.json tại reports/final_acceptance/ ghi SHA256 và xác nhận synthetic_cases.py, test_cases.json, policy, CT snapshot, raw90 và raw114 không đổi. 14 ca Demo không thêm/xóa. Không bật extensions vào synthetic Baseline/Extended; không chạy lại nghiên cứu lớn và không sửa summary/raw cũ.

PDF đã cập nhật **27 trang**, nội dung thu hồi/AIA, CT primitives, opt-in, offline/live và giới hạn. Canonical: reports/scientific/scientific_report.pdf; bản mới dựng cùng HTML/slides tại reports/final_acceptance/scientific_final/. document_validation.json ghi pages/tests/hashes. Bản trước giữ nguyên tại reports/final_acceptance/before_scientific/. Không đổi số liệu nghiên cứu để phù hợp với chức năng mới.

## Chức năng còn thiếu

1. Live proof cho website thiếu intermediate được cứu bằng recovery AIA; hiện mới kiểm thử orchestration/offline, không được tuyên bố đã kiểm chứng live.
2. Registry khóa CT có nguồn tin cậy xác thực; key/LogID khớp trong snapshot không đủ thay thế bước này.
3. Tái dựng precertificate TBS và xử lý preissuer chính xác; hiện chỉ xác minh khi caller có input chính xác.
4. Endpoint STH/proof, kiểm tra binding/freshness/consistency và static/tiled API. Giữ NOT_VERIFIED trong scan.
5. Các giới hạn OCSP/CRL đã ghi ở revocation_phase2.md: nonce, stapling, delegate thiếu noCheck, delta/indirect/reason scopes. Không claim browser compliance đầy đủ.

Không bổ sung tính năng giả hoặc tự đổi NOT_VERIFIED thành VALID để che các mục này.

## File thay đổi trong lượt kiểm toán

Mới: src/untrusted_tls.py, tests/test_final_acceptance.py, FINAL_ACCEPTANCE.md và reports/final_acceptance/.
Sửa: src/certificate_security.py, src/aia_completion.py, src/report_export.py, src/web_presentation.py, templates/result.html, experiments/build_scientific_report.py, README.md, reports/requirements_traceability.md; cập nhật PDF/HTML/slides/figures/document_validation trong reports/scientific/ sau khi giữ bản cũ. Không thêm dependency.

## Demo trước giảng viên

Trong PowerShell tại project, dùng Python .venv:

```powershell
.\.venv\Scripts\python.exe app.py
.\.venv\Scripts\python.exe main.py google.com --advanced --json reports/demo_acceptance.json --html reports/demo_acceptance.html
.\.venv\Scripts\python.exe -m pytest tests/test_final_acceptance.py tests/test_security_extensions.py tests/test_revocation_checker.py tests/test_revocation_network.py -v
```

Mở http://127.0.0.1:5000, chọn kiểm tra bổ sung, xem revocation/AIA/nguồn TLS và giới hạn CT; giải thích final WARNING dù CRL GOOD. Mở /demo, chạy toàn bộ14, phân biệt chứng thư FAIL và test PASS. Mở HTML xuất và PDF27trang cập nhật. Trình diễn AIA/SCT offline qua pytest, nói rõ chưa live verified. Không giả một website thực bị revoked hoặc cứu AIA nếu chưa có bằng chứng.
