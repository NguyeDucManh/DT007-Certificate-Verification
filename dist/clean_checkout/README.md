# DT007 – Trình xác minh chuỗi chứng thư số và chính sách thuật toán

## Chạy nhanh trên Windows — bản bàn giao 18/10/2026

Giải nén ZIP, mở PowerShell tại thư mục có `main.py`. Cài Python 3.14 x64;
tạo môi trường mới, không sao chép `.venv` từ máy khác. Các lệnh dưới dùng trực
tiếp Python trong môi trường nên không cần thay execution policy PowerShell.

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
.\.venv\Scripts\python.exe -X utf8 main.py
.\.venv\Scripts\python.exe -X utf8 main.py google.com --json reports/check.json --html reports/check.html
.\.venv\Scripts\python.exe -X utf8 experiments/run_validation.py --output-dir reports/my_validation
.\.venv\Scripts\python.exe -X utf8 -c "from pathlib import Path; from src.demo_service import run_all_demos; r=run_all_demos(Path('config/algorithm_policy.json')); print(r['success'], '/', r['total']); assert r['success']==r['total']==14"
```

Tên miền thật cần Internet và trust store hệ thống; lỗi mạng trả FAIL kèm nguyên
nhân, không phải kết luận chứng thư từ xa bị sai. Dataset/Demo/tests dùng dữ liệu
cục bộ. Full suite cần lock nghiên cứu, không chỉ `requirements.txt` tối thiểu.
Runner dùng thư mục tạm mới trong thư mục bằng chứng để tránh lỗi quyền của
`.pytest_tmp` cũ. Thư mục đầu ra phải mới để giữ nguyên evidence.

**Kiểm thử mã hiện tại:** 539 PASS, 0 FAIL/ERROR/SKIP, 1 cảnh báo từ backend
chứng thư fixture; `reports/submission_audit/workspace_verified/pytest.xml`.
Import toàn bộ module thành công; Demo 14/14; CLI mặc định/advanced, JSON/HTML,
Flask localhost đã chạy thật tại `reports/submission_audit/workspace_live/`.
Số 515/508 ở các checkpoint bên dưới là lịch sử, không phải kết quả hiện tại.

Tái chạy thực nghiệm cố định (raw mới, không ghi đè 90/114 quan sát lịch sử):

```powershell
.\.venv\Scripts\python.exe -X utf8 experiments/research_study.py --repeats 3 --seed 20261010 --output-dir reports/my_research
```

Lượt thực chạy mới ở `reports/submission_audit/research_rerun/`: 114 quan sát,
Baseline coverage 71,43%, FP=0/FN=6; Extended 100%, FP=0/FN=0. Đây là bộ kiểm
soát nhỏ, không suy rộng xác suất an toàn Internet. CPU là process time ở biên
ca; RAM là RSS trước/sau và peak toàn tiến trình, không peak từng ca.

Chức năng mở rộng tùy chọn:

```powershell
.\.venv\Scripts\python.exe -X utf8 main.py google.com --advanced --json reports/advanced.json --html reports/advanced.html
.\.venv\Scripts\python.exe app.py
# http://127.0.0.1:5000/demo — giao diện localhost, không cần hosting
```

SCT/inclusion live đã có bằng chứng ở `reports/code_validation/ct_live/`:
signed Google registry + publisher key pin; tái dựng precert TBS, xác minh SCT,
STH và Merkle path. Không có checkpoint độc lập trong scan nên consistency/gossip
vẫn NOT_VERIFIED. Static/tiled proof chưa hỗ trợ; không đổi giới hạn thành PASS.
Snapshot nghiên cứu gốc khác registry live và chưa có chữ ký nguồn tương ứng.

Xem [FINAL_ACCEPTANCE.md](FINAL_ACCEPTANCE.md),
[đối chiếu 8 yêu cầu](reports/requirements_traceability.md) và
[tình trạng quyền dữ liệu](DATA_NOTICE.md). Chưa xác nhận quyền tái phân phối
snapshot rộng rãi; không tuyên bố dữ liệu đã được cấp phép đầy đủ.
PDF khoa học hiện có được giữ nguyên; không dựng lại PDF/slides/video trong lượt này.

## Các checkpoint phát triển trước bàn giao (lịch sử)

## Chạy code nâng cấp AIA/CT/OCSP

`--advanced` hoặc checkbox Web hiện xác thực **danh sách CT mới** bằng chữ ký
Google và publisher key đã pin trong `config/ct_log_list_pubkey.pem`; không sửa
`data/log_list.json` dùng trong nghiên cứu. Chỉ khớp Log ID không đủ xác thực nguồn.
Code dựng precertificate TBS từ final leaf hoặc precertificate/preissuer được
cung cấp đúng, rồi xác minh chữ ký SCT. RFC6962 được truy vấn STH và inclusion
proof tối đa hai SCT mỗi scan. Static/tiled chưa hỗ trợ endpoint proof nên trả
UNSUPPORTED; lỗi mạng/thiếu dữ liệu giữ NOT_VERIFIED. Consistency được API
`check_inclusion(..., previous_sth=...)` kiểm tra khi có checkpoint; scan thông
thường không có checkpoint nên không tuyên bố consistency/gossip đã xác minh.
Final WARNING được giữ khi còn giới hạn; điểm UI không thay đổi chính sách.

```powershell
.\.venv\Scripts\python.exe app.py
.\.venv\Scripts\python.exe main.py google.com --advanced --json reports/check_new.json --html reports/check_new.html
.\.venv\Scripts\python.exe -m pytest tests/test_aia_local_tls.py tests/test_ct_pipeline.py tests/test_revocation_checker.py -v
.\.venv\Scripts\python.exe experiments/ct_live_probe.py --output-dir reports/my_new_ct_probe
```

Thư mục probe phải mới/trống; lưu chứng thư, signed list, STH, proof và kết quả
thực tế để đối chiếu. Test AIA dùng TLS/HTTP server cục bộ thật; việc cho phép
loopback chỉ được tiêm trong test, không có tùy chọn tắt chống SSRF của production.
OCSP API hỗ trợ `check_revocation(..., use_nonce=True)`; nonce thiếu trả UNKNOWN,
nonce sai trả ERROR. Web/CLI mặc định giữ chế độ freshness để tương thích responder
cache. Chưa thu thập TLS stapling, chưa hợp nhất delta/indirect/reason-scoped CRL.
Các mục kiểm toán/PDF trước bên dưới phản ánh checkpoint cũ; lượt code này không
viết lại báo cáo hoặc sửa kết quả nghiên cứu.

## Kiểm toán phiên bản cuối

Checkpoint 10/10/2026 có 515 pytest đạt, evidence lịch sử
trong `reports/final_acceptance/`; PDF 27 trang đã cập nhật khi đó, bản trước giữ ở
`reports/final_acceptance/before_scientific/`.
Chế độ `--advanced` có thu thập TLS chưa tin cậy **riêng** khi luồng xác minh
mặc định báo thiếu issuer (20/21). Chỉ sau khi kiểm tra lại đường dẫn với trust
store độc lập, hostname, thời hạn, CA và thuật toán mới dùng kết quả; không đổi
TLS verification mặc định. Chỉ hỗ trợ recovery cổng 443/đích công khai.
Chưa có kiểm chứng live website thiếu intermediate được cứu thành công.
Mô tả CT tại checkpoint này đã được thay bằng pipeline và bằng chứng ở phần
chạy nhanh/nâng cấp phía trên; không dùng checkpoint này để mô tả code hiện tại.

## Bổ sung OCSP/CRL — Giai đoạn 2

**Cập nhật sau tích hợp:** dùng `--advanced` ở CLI hoặc chọn ô kiểm tra bổ sung
trên trang chủ Web để bật OCSP/CRL và AIA. Nếu không bật, kết quả thu hồi hiển thị
NOT_CHECKED. CT chưa có khóa tin cậy độc lập/đủ dữ liệu vẫn NOT_VERIFIED.
Chi tiết trạng thái triển khai: [reports/security_extensions_completion.md](reports/security_extensions_completion.md).

```powershell
.\.venv\Scripts\python.exe -X utf8 main.py google.com --advanced --json reports/my_result.json --html reports/my_result.html
.\.venv\Scripts\python.exe app.py
```

Truy cập `http://127.0.0.1:5000`, chọn kiểm tra bổ sung; `/demo` vẫn giữ 14 ca.
Chạy các kiểm thử offline mới bằng `python -m pytest tests/test_security_extensions.py
tests/test_revocation_checker.py tests/test_revocation_network.py -v` trong .venv.
Chưa có phòng Demo riêng cho các fixture AIA/SCT mới; dùng pytest để trình diễn
các module đó, không nhầm với kết quả website thật.

Module độc lập `src/revocation_checker.py` hỗ trợ phản hồi OCSP và CRL có chữ ký thực;
`src/revocation_network.py` kiểm soát truy vấn mạng. Baseline/Extended không bật các
chức năng mới: các kết quả lịch sử giữ nguyên. Chain PASS không
có nghĩa trạng thái thu hồi đã được kiểm tra.

API `check_revocation(cert)` mặc định offline, trả `NOT_CHECKED` cùng giải thích;
muốn kiểm tra cần truyền issuer từ đường dẫn đã được xác minh độc lập và
`issuer_trusted=True`. Offline nhận `fixtures={"OCSP": (der_bytes,), "CRL": (der_or_pem_bytes,)}`;
online cần `online=True`. `result.to_dict()` cung cấp trạng thái, nguyên nhân và
bằng chứng sẵn cho JSON/HTML, không thay đổi final result của engine hiện tại.

Trạng thái: `GOOD`, `REVOKED`, `UNKNOWN`, `NOT_CHECKED`, `ERROR`. GOOD chỉ là bằng
chứng trạng thái thu hồi trong phạm vi/thời gian phản hồi, không chứng nhận website an toàn.
Lỗi mạng, thiếu dữ liệu và bằng chứng không hợp lệ không được chuyển thành GOOD.

Chạy kiểm thử offline (PowerShell tại thư mục dự án):

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_revocation_checker.py tests/test_revocation_network.py -v --basetemp=.pytest_revocation -p no:cacheprovider
```

Thu thập bằng chứng thực tế từ ba website công khai, dùng thư mục đầu ra **mới**:

```powershell
.\.venv\Scripts\python.exe -X utf8 experiments/revocation_probe.py --output-dir reports/security_extensions/my_new_probe
```

Giới hạn và kết quả thực chạy: [reports/revocation_phase2.md](reports/revocation_phase2.md).
Không có nút OCSP/CRL mới trên phòng Demo 14 ca; bật kiểm tra trên trang website thật.

## Rà soát nghiên cứu và hệ thống — 10/10/2026

Kiểm chứng dữ liệu cũ: 90 quan sát, 0 sai lệch số học; coverage Baseline
10/14 = 71,43%, FN=6/36. Không đổi raw/evidence cũ. Nghiên cứu mới sau sửa
EKU/KU TLS: 114 quan sát, 3 lần × 2 profile × (14 ca + 5 đối chứng).
Baseline FP=0/15, FN=6/36; Extended FP=0/15, FN=0/36. Đây là kết quả bộ
thử có kiểm soát, không phải độ chính xác hoặc xác suất an toàn Internet.

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-lock.txt
python experiments/audit_research_metrics.py
python experiments/audit_expanded_study.py
python -m experiments.validate_ct_snapshot
# Chọn thư mục MỚI; runner từ chối ghi đè bằng chứng.
python experiments/research_study.py --repeats 3 --output-dir reports/research_expanded/my_new_run
python experiments/run_validation.py --output-dir reports/final_validation/my_new_validation
python -m pytest -v --basetemp=.pytest_tmp -p no:cacheprovider
python experiments/build_scientific_report.py --junit reports/final_validation/my_new_validation/pytest.xml
```

`requirements-lock.txt` chốt phiên bản thực cài trên Windows/Python 3.14.
Nếu cần giải dependencies lại: cài `requirements-research.txt`. Bốn công cụ
nghiên cứu bổ sung là jsonschema (schema chính thức), matplotlib (biểu đồ),
reportlab (báo cáo) và pypdf (kiểm chứng số trang); không dùng database/login.
`requirements.txt` cho web/CLI vẫn giữ nguyên. Full suite mới cần môi trường
research vì có kiểm thử schema và tài liệu.

CPU time và RSS trước/sau được đo, không gọi RSS sampled là peak mỗi ca.
Mean/SD/CV/khoảng t95 n=3 là mô tả, không suy rộng FPR hoặc coverage population.
Năm loại đối chứng có nhãn thuộc tính trước engine và OpenSSL oracle invocation
riêng; cùng backend, không phải triển khai mật mã độc lập. PEM public lưu,
không xuất private keys. CT signature/inclusion vẫn NOT_VERIFIED.

Lỗi purpose TLS của chain offline đã sửa; EKU/KU hiện diện phải cho máy chủ
TLS. Không thay CT/policy hoặc 14 ca Demo. Có thể xuất cùng lần chạy CLI:

```powershell
py main.py google.com --json reports/google.json --html reports/google.html
py -c "import webbrowser; from pathlib import Path; webbrowser.open(Path('reports/google.html').resolve().as_uri())"
py app.py
# Mở http://127.0.0.1:5000 hoặc http://127.0.0.1:5000/demo
```

Báo cáo PDF/HTML và slide HTML: `reports/scientific/`; số trang thực được
kiểm chứng trong `document_validation.json`. Mở HTML/slide bằng trình duyệt.
Nội dung demo: `reports/demo_script.md`. Đối chiếu từng yêu cầu và phần còn
thiếu: `reports/requirements_traceability.md`; kết quả kiểm tra hệ thống:
`reports/system_review.md`. Chưa tuyên bố hoàn thành 100%: JCR trực tiếp/cơ sở
Q1, quyền phân phối snapshot, acquisition/signature nguồn, mẫu trường, video
và điện thoại vật lý/clipboard OS còn cần xác nhận. Edge headless đã kiểm tra
13 nội dung UI (loading, score, timeline, SCT, Demo, download, viewport 390px),
evidence/screenshot ở `reports/browser_smoke/final_20261010`. Không cài thư viện
browser mới, dùng Edge sẵn có và Python standard library. Các mục dưới ghi lịch sử
phát triển; bộ bằng chứng mới ưu tiên `post_tls_20261010` và `final_validation`.

## Nghiên cứu Baseline / Extended

Đã merge research addon vào SyntheticLab hiện tại, giữ evidence và 14 ca Demo.
Baseline tắt CT qua cùng security_evaluator; Extended mặc định giữ CT matching.
VALID_CONTROL chỉ dùng cho nghiên cứu FP, không thêm vào manifest 14 ca Demo.
Không nhập sample results từ addon.

```powershell
.\.venv\Scripts\python.exe experiments/dataset_profile.py
.\.venv\Scripts\python.exe experiments/research_evaluation.py --repeats 3 --output-dir reports/research_new_run
.\.venv\Scripts\python.exe -m pytest -q --basetemp=.pytest_tmp -p no:cacheprovider
```

Artifacts: `reports/research_results/` gồm raw CSV, JSON evidence, cấu hình,
checksums, log và báo cáo đo. `reports/live_repeats/run_1` đến `run_3` lưu ba
lượt real + synthetic riêng; không trộn live ground truth với nghiên cứu offline.
`reports/ct_dataset_profile.json` mô tả dataset thật đang dùng. Các lệnh đo ghi
ra thư mục output đã chọn; runner nghiên cứu từ chối thư mục không trống.
Runtime/ca không gồm setup tạo khóa được ghi riêng. Seed cố định thứ tự profile,
không cố định cryptographic key generation. Không gọi phép đo này là tái lập
thuật toán của bài báo quản trị WebPKI.

Xem `reports/research_integration_review.md` để biết kết quả thực đo và checklist
yêu cầu còn thiếu; threat model/protocol trong `reports/research_protocol.md`.

## Vai trò chứng thư và đường dẫn tin cậy

Giao diện phân biệt root CA tự ký, intermediate và trust anchor độc lập.
Chứng thư cuối không tự động được gọi root. CA trung gian có trong trust store
có thể là điểm neo được tin cậy trực tiếp theo PARTIAL_CHAIN hiện có.
Khi terminal chưa là anchor, OpenSSL thử bổ sung đường dẫn từ store; chỉ nhận
đường dẫn đã xác minh, vẫn kiểm tra chữ ký/CA/time và fingerprint anchor độc lập.
Không tìm được đường dẫn thì trust FAIL, không ép PASS.
TLS thu cả verified chain và raw peer chain để ghi nguồn từng node. Root được
bổ sung từ store nhưng không nằm trong peer chain được ghi rõ trên timeline.
Tài liệu: `reports/chain_review.md`.

## Sửa semantics CT temporal_interval

Theo [schema Google CT Log List v3](https://www.gstatic.com/ct/log_list/v3/log_list_schema.json),
`temporal_interval` là khoảng **NotAfter** chứng thư, không phải thời điểm SCT.
Không đối chiếu timestamp SCT với khoảng này; trường tương thích
`timestamp_interval` trả NOT_APPLICABLE. Không có interval tùy chọn cũng trả
NOT_APPLICABLE; interval được cung cấp nhưng thiếu/sai hoặc NotAfter thiếu
trả UNKNOWN/cảnh báo dữ liệu, không tự kết luận SCT không hợp lệ.
SCT timestamp vẫn được kiểm tra timezone/future và retirement timestamp nếu có.
Retired thiếu timestamp trả WARNING thay vì FAIL. Log ID trùng trả WARNING
do dữ liệu mơ hồ; Log ID không tìm thấy vẫn FAIL matching, không phải bằng chứng
chữ ký SCT sai. Chữ ký SCT và inclusion proof có trạng thái riêng NOT_VERIFIED.

Case SCT_TIMESTAMP_OUTSIDE_INTERVAL hiện là hồi quy: timestamp SCT ngoài khoảng
không tạo cảnh báo, NotAfter trong khoảng thì metadata PASS. Expected tổng vẫn
WARNING do cryptography CT chưa verify, không vì timestamp. Các mô tả chẩn đoán
timestamp ở phần lịch sử bên dưới đã được thay thế bởi quy tắc này.
Chi tiết sửa và kiểm tra: `reports/ct_interval_review.md`.

## Phòng kiểm thử chứng thư số

Trang `/demo` hỗ trợ **CHẠY TOÀN BỘ 14 CA KIỂM THỬ**, lấy ID từ manifest
và tạo/chạy lại dữ liệu từng ca. Bảng tổng hợp giữ riêng verdict chứng thư và
kết luận kiểm thử; lỗi từng ca không dừng batch. Tỷ lệ khớp kỳ vọng lấy số ca
actual khớp expected chia tổng ca đã chọn (gồm lỗi/chưa chạy), không phải độ
chính xác ngoài thực tế. Thành công còn yêu cầu detected đúng điều kiện.
Nhấn tên dòng để mở certificate, reasons và evidence. **XUẤT BÁO CÁO CSV**
tải snapshot đang xem với UTF-8 BOM, không chạy lại và không dùng results.csv.
Không lưu batch vào database; tải báo cáo trước khi rời trang.

`/demo` chạy mới từng case bằng SyntheticLab và validators hiện có, hiển thị
loại đầu vào, nguồn, metadata X.509, cấu trúc CT, module đã gọi, actual/expected,
đối chiếu ĐÚNG/SAI và runtime. Mismatch hoặc chưa phát hiện điều kiện khảo sát
báo **KIỂM THỬ THẤT BẠI**; không thay đổi verdict để khớp kỳ vọng.
14 case đều dùng X.509 thật được tạo trong RAM; 3 case chính sách riêng,
11 case tổng hợp có SCT/CT Log giả lập có cấu trúc, không mock kết quả engine.
Phân loại và giới hạn từng case: [demo_validation.md](reports/demo_validation.md).
Toàn bộ pytest sau nâng cấp phòng kiểm thử: **353 pass**.

## Rà soát hoàn thiện – Phase 4

### Giai đoạn 4B – Mô phỏng kiểm thử chứng thư số

Trang `/demo` có nút **CHẠY KIỂM THỬ**, lấy các mã synthetic từ manifest
experiments và chạy lại `SyntheticLab`. Mỗi kết quả hiển thị mô tả tình huống,
phạm vi validators, actual result, reasons tiếng Việt, expectation từ manifest
và đối chiếu **KHỚP / KHÔNG KHỚP KỲ VỌNG**. Khớp kỳ vọng không có nghĩa
chứng thư đạt an toàn. Actual result và phát hiện điều kiện khảo sát được giữ
riêng, không đổi verdict theo expectation. Chỉ nhận ID synthetic đã khai báo;
không nhận đường dẫn hay lệnh hệ thống. Toàn bộ pytest sau nâng cấp: 337 pass.

Trang kết quả có **VẤN ĐỀ PHÁT HIỆN**: hạng mục, nguyên nhân cụ thể,
ảnh hưởng và khuyến nghị. Giới hạn chữ ký SCT/inclusion proof được tách khỏi
vấn đề chứng thư; không kết luận website mất an toàn chỉ vì công cụ chưa
xác minh đầy đủ CT. Điểm 90/100 không có nghĩa website thiếu 10% an toàn.
Điểm là quy ước trình bày, không thay đổi WARNING hoặc kết luận engine.
Reason gốc luôn được giữ trong **Chi tiết kỹ thuật**.

Chạy `py app.py` trong `.venv`, mở http://127.0.0.1:5000/demo để trình diễn.
Chọn một trong 14 case giả lập, bấm **CHẠY DEMO**. Mỗi lần tạo chứng thư mới
trong RAM và gọi `SyntheticLab` của experiments với clock cố định từ manifest;
không đọc CSV để giả kết quả, không kết nối website và không thay dataset CT thật.
RSA 1024/SHA1/MD5 kiểm tra riêng Algorithm Policy; các case khác tổng hợp
validators offline. Kết quả ghi rõ phạm vi, điều kiện phát hiện và lý do thực tế.
Nếu backend không tạo được fixture, trang báo chưa chạy, không giả verdict.

Nếu Flask cũ còn chạy, nhấn `Ctrl+C` trong terminal đó rồi khởi động lại để
nhận routes và templates mới. Báo cáo rà soát: `reports/phase4_review.md`.

## Mục tiêu Giai đoạn 1: Dataset + Environment

Thiết lập Python và phân tích Google Certificate Transparency Log List v3:
đọc metadata, thống kê operators, cả `logs` và `tiled_logs`, trạng thái log,
và in tối đa 5 bản ghi đầu tiên.

## Mục tiêu Giai đoạn 2A

Lấy leaf certificate qua TLS có xác minh, parse DER/PEM, kiểm tra hiệu lực
và hostname bằng SAN, thu thập thông tin khóa và chữ ký. Giữ nguyên CT analyzer.
Các mục 2A vẫn được giữ trong CLI; phần 2B bên dưới mở rộng kiểm tra.

## Mục tiêu Giai đoạn 2B

Xác minh chain và chữ ký từng certificate, áp algorithm policy từ JSON,
parse SCT nhúng trong chứng thư, đối chiếu CT log IDs và tổng hợp
`PASS` / `WARNING` / `FAIL` với reasons. Chỉ xuất terminal; không HTML,
dashboard hoặc Giai đoạn 3.

## Cấu trúc project

```text
DT007/
├── main.py
├── app.py
├── requirements.txt
├── README.md
├── pytest.ini
├── .gitignore
├── data/
│   └── log_list.json      # người dùng đặt dataset thật tại đây
├── src/
│   ├── __init__.py
│   ├── ct_log_analyzer.py
│   ├── certificate_fetcher.py
│   ├── certificate_parser.py
│   ├── validity_checker.py
│   ├── hostname_validator.py
│   ├── crypto_info.py
│   ├── chain_validator.py
│   ├── algorithm_policy.py
│   ├── sct_parser.py
│   ├── ct_validator.py
│   ├── security_evaluator.py
│   ├── certificate_security.py
│   ├── security_console.py
│   ├── certificate_service.py
│   └── web_presentation.py
├── tests/
│   ├── conftest.py
│   ├── test_ct_log_analyzer.py
│   ├── test_certificate_fetcher.py
│   ├── test_certificate_parser.py
│   ├── test_validity_checker.py
│   ├── test_hostname_validator.py
│   ├── test_crypto_info.py
│   ├── test_main.py
│   ├── test_chain_validator.py
│   ├── test_algorithm_policy.py
│   ├── test_sct_parser.py
│   ├── test_ct_validator.py
│   ├── test_security_evaluator.py
│   ├── test_experiments.py
│   └── test_web.py
├── experiments/
│   ├── __init__.py
│   ├── run_experiments.py
│   ├── synthetic_cases.py
│   ├── test_cases.json
│   ├── results.csv
│   └── summary.json
├── templates/
│   ├── base.html
│   ├── index.html
│   └── result.html
├── static/
│   ├── css/style.css
│   └── js/main.js
├── reports/
└── config/
    └── algorithm_policy.json
```

`data/log_list.json` không được tạo bằng dữ liệu giả hay file JSON rỗng.
Các fixture tổng hợp trong tests chỉ phục vụ unit test.

## Môi trường Windows PowerShell và VS Code

Môi trường dự án sử dụng Python 3.14.8, cryptography 50.0.2 và pytest 9.1.1.
Mở terminal PowerShell tại thư mục DT007. Nếu Python 3 đã cài:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Nếu `py -3` chưa nhận diện Python 3 nhưng máy có Python 3.14 ở đường dẫn này:

```powershell
& "$env:LOCALAPPDATA\Programs\Python\Python314\python.exe" -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Nếu PowerShell chặn Activate.ps1, cho phép script trong phiên terminal hiện tại:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Hoặc chạy trực tiếp `.\.venv\Scripts\python.exe` mà không cần kích hoạt.
Trong VS Code, dùng **Python: Select Interpreter** và chọn
`.venv\Scripts\python.exe`. Giai đoạn 3B dùng Flask cho giao diện local;
không cần Django hay database.

## Dataset

Tải dataset thật từ [Google CT Log List v3](https://www.gstatic.com/ct/log_list/v3/log_list.json)
và lưu nguyên nội dung UTF-8 vào `data/log_list.json` (không lưu trang HTML).
Có thể tải thủ công hoặc chạy:

```powershell
Invoke-WebRequest -Uri 'https://www.gstatic.com/ct/log_list/v3/log_list.json' -OutFile 'data/log_list.json'
```

Chương trình đọc file cục bộ, không tự tải hoặc sửa dataset. Nếu thiếu file,
JSON sai, hoặc cấu trúc danh sách sai, chương trình báo lỗi dễ hiểu và trả mã 1.
Trường tùy chọn thiếu được giữ là `None`, hiển thị `N/A`; state thiếu là `unknown`.
Các state mới được đếm theo tên thực tế. Sáu state đã biết vẫn hiển thị số 0
nếu không xuất hiện. Tổng log tính cả hai loại; operator không có log vẫn được đếm.
Operator trùng tên được cộng chung trong thống kê theo tên.

## Chạy chương trình và tests

Kích hoạt `.venv` trước khi chạy. CT analyzer (không tham số):

```powershell
.\.venv\Scripts\Activate.ps1
py main.py
```

Certificate analyzer:

```powershell
py main.py google.com
py main.py github.com
py main.py google.com --port 443 --timeout 10
```

Toàn bộ unit tests (không cần Internet):

```powershell
py -m pytest -v --basetemp=.pytest_tmp -p no:cacheprovider
```

Khi chưa kích hoạt môi trường:

```powershell
.\.venv\Scripts\python.exe main.py
.\.venv\Scripts\python.exe main.py google.com
.\.venv\Scripts\python.exe -m pytest -v --basetemp=.pytest_tmp -p no:cacheprovider
```

Máy hiện tại có `py` mặc định trỏ Python 2.7 nếu chưa kích hoạt `.venv`.
Không dùng `py` bên ngoài môi trường đã kích hoạt; dùng đường dẫn Python
trong `.venv` nếu launcher chưa nhận diện môi trường. Không cần hạ Python
hoặc thay đổi Python hệ thống.

Đường dẫn dataset được xác định từ vị trí `main.py`, không phụ thuộc thư mục
làm việc hiện tại. Tests dùng file tạm, không cần dataset thật.

## Ý nghĩa các trường

Theo [schema chính thức của Google](https://www.gstatic.com/ct/log_list/v3/log_list_schema.json):

| Trường | Ý nghĩa |
| --- | --- |
| `operator` | Tổ chức vận hành log; lấy từ `operators[].name`. |
| `description` | Mô tả giúp nhận diện log. |
| `log_id` | SHA-256 của khóa công khai log, mã hóa Base64. |
| `key` | Khóa công khai DER SubjectPublicKeyInfo, mã hóa Base64. |
| `mmd` | Maximum Merge Delay, số giây tối đa để đưa chứng thư vào log. |
| `state` | Trạng thái theo đơn vị phân phối danh sách; timestamp là thời điểm vào trạng thái đó. |
| `temporal_interval` | Khoảng ngày hết hạn chứng thư mà log chấp nhận: gồm `start_inclusive`, không gồm `end_exclusive`. |
| `logs` | Danh sách CT logs theo RFC6962, dùng `url`. |
| `tiled_logs` | Danh sách logs dùng Static CT API, có `submission_url` và `monitoring_url`. |
| `url` | URL gốc HTTP API của RFC6962 log. |
| `submission_url` | Tiền tố API gửi chứng thư của Static CT log. |
| `monitoring_url` | Tiền tố API theo dõi của Static CT log. |
| `version` | Phiên bản nội dung danh sách; khác với số phiên bản định dạng v3 trong URL. |
| `log_list_timestamp` | Thời điểm công bố phiên bản danh sách. |

Module giữ cả key, monitoring URL, state timestamp và temporal interval trong
`CTLog`; CLI chỉ in các trường yêu cầu cho năm bản ghi đầu tiên.
CT analyzer chưa xác minh chữ ký dataset.

## Chi tiết Certificate Analyzer 2A

- `certificate_fetcher`: dùng socket và `ssl.create_default_context()` với CA
  verification và hostname verification bật; không retry bằng `CERT_NONE`.
  Chỉ trả leaf certificate DER; có hàm chuyển DER sang PEM.
  Timeout áp dụng cho socket/TLS handshake; resolver DNS của hệ điều hành
  có thể vượt thời hạn này. Lỗi DNS, timeout, refused và TLS được báo riêng.
- `certificate_parser`: dùng `cryptography.x509`, đọc Subject, Issuer, serial,
  version, ngày UTC, mọi SAN và thông tin mật mã. SAN thiếu trả danh sách rỗng.
- `validity_checker`: trả `NOT_YET_VALID`, `VALID` hoặc `EXPIRED`; dùng datetime
  timezone-aware, gồm cả hai đầu mút hiệu lực. Từ chối thời gian naive.
- `hostname_validator`: so khớp SAN, không fallback Common Name khi SAN thiếu.
  Không phân biệt hoa thường, hỗ trợ IDNA và IP SAN; `*.example.com` chỉ khớp
  một cấp như `api.example.com`. IP phải khớp SAN loại IPAddress.
- `crypto_info`: nhận diện RSA, EC, DSA, Ed25519, Ed448 hoặc UNKNOWN; đọc key size
  nếu API cung cấp, signature OID/name và hash. Ed25519/Ed448 có hash trả `None`
  và không có `key_size` trong API, nên CLI hiển thị `N/A`, không đánh giá policy.

Việc xác minh tích hợp của TLS vẫn được giữ để kết nối an toàn. Vì vậy server có chứng thư hết hạn,
sai hostname hoặc không được tin cậy sẽ bị từ chối ngay tại TLS fetching;
tests tự ký kiểm tra trực tiếp các module parser/validity/hostname để bao phủ
các trường hợp đó mà không tắt verification.

Tham khảo [Python ssl](https://docs.python.org/3/library/ssl.html) và
[cryptography X.509](https://cryptography.io/en/latest/x509/reference/).

## Certificate Security Verifier 2B

### Chain validation

`fetch_peer_chain()` lấy leaf và `get_verified_chain()` trong cùng một TLS
session, cùng CA certificates từ trust store của `ssl.create_default_context()`.
API leaf-only `fetch_certificate()` của 2A vẫn hoạt động như trước.
Python 3.14.8 có API verified chain nên không cần tải intermediate qua AIA.

`chain_validator` nhận chuỗi theo thứ tự leaf → intermediate(s) → root/trust
anchor. Kiểm tra issuer/subject, chữ ký trên `tbsCertificate` bằng khóa công
khai issuer, BasicConstraints CA=True, keyCertSign nếu có, thời hạn từng cert,
certificate trùng/cycle, self-signed leaf và root thiếu/không được tin cậy.
Root/trust anchor phải khớp CA từ nguồn tin cậy độc lập; không tự thêm root từ server vào
kho tin cậy. OpenSSL `X509StoreContext` kiểm tra thêm path length và critical
extensions. Store dùng PARTIAL_CHAIN để hỗ trợ CA đã được tin cậy trực tiếp
nhưng không tự ký (như cross-signed anchor trên Windows), tương thích TLS
mặc định; terminal chưa được trust vẫn FAIL. Chữ ký được verify thật, bao gồm RSA-PKCS1, RSA-PSS, EC, DSA,
Ed25519/Ed448; không chỉ so sánh Subject/Issuer.

Verify chữ ký root SHA-1 cũ chỉ xác nhận chữ ký của anchor đã được trust store
tin cậy; không khiến SHA-1 trở thành thuật toán được policy cho chứng thư mục
tiêu chấp nhận. Không kiểm tra thu hồi OCSP/CRL trong phiên bản này.

### Algorithm policy

File `config/algorithm_policy.json` là nguồn của minimum RSA/EC/DSA key size,
allowed/blocked public-key algorithms và signature hashes. Thay file để thay
rule, không sửa code. Blocked ưu tiên allowed; unknown, field thiếu, kiểu dữ
liệu sai hoặc key quá nhỏ đều không được PASS. CLI hiển thị từng rule và tổng.
Policy áp dụng cho leaf certificate; trust anchor không được tự động đánh giá
lại bằng policy của leaf.

Ed25519/Ed448 không có hash parameter riêng trong X.509 API: danh sách
`hash.allowed_without_external_hash` cho phép rõ các signature algorithms đó.
Không coi hash `None` của thuật toán lạ là hợp lệ. File thiếu/JSON sai làm
Algorithm Policy và final result FAIL, nhưng các section khác vẫn được in.

### SCT và CT log matching

SCT (Signed Certificate Timestamp) là cam kết có chữ ký từ CT log về việc đưa
chứng thư vào log. `sct_parser` đọc extension SCT nhúng bằng cryptography,
lấy log ID (32 bytes → Base64), timestamp UTC và version. SCT thiếu hoặc
malformed trả kết quả rõ ràng, không gây crash. Phiên bản này không thu thập
SCT từ TLS extension hay OCSP.

`ct_validator` đối chiếu ID với cả `logs` và `tiled_logs` trong dataset cục bộ.
Không match theo tên operator. ID không có hoặc bị trùng/không xác định rõ
trong dataset → FAIL. Mỗi SCT được in operator, description, state, MMD,
URL/submission URL, start/end interval, timestamp và kết quả từng kiểm tra.

| State | Kết quả state rule |
| --- | --- |
| usable | PASS |
| qualified | WARNING: policy matching yêu cầu review |
| readonly | WARNING |
| retired | WARNING nếu SCT trước timestamp retirement; còn lại FAIL |
| rejected | FAIL |
| pending hoặc state khác | WARNING |

**Ý nghĩa temporal interval:** theo schema Google, interval xác định ngày hết
hạn (`NotAfter`) chứng thư mà log chấp nhận, không phải khoảng thời gian phát
hành SCT. CLI in hai kiểm tra để phân biệt:

- `SCT Timestamp Interval`: đối chiếu timestamp SCT theo yêu cầu đề tài;
  ngoài khoảng tạo WARNING chẩn đoán, không dùng để kết luận eligibility.
- `Cert Expiry Interval`: đối chiếu NotAfter với start inclusive/end exclusive;
  ngoài khoảng → FAIL. Bounds thiếu/sai → WARNING.

SCT tương lai bị FAIL; version chưa hỗ trợ bị WARNING. State được lấy theo
snapshot dataset, không tái dựng lịch sử toàn bộ CT log.

**Matching không xác minh chữ ký SCT hay inclusion proof.** Mỗi SCT có thể
match PASS nhưng `CT Overall Status` vẫn WARNING với `SCT Signatures:
NOT_VERIFIED`. Đây là giới hạn rõ của giai đoạn matching, tránh kết luận SCT
đã hợp lệ về mật mã chỉ từ ID. Thiếu SCT trả WARNING với reason `NO_SCT`.

### Kết quả tổng và xử lý lỗi

`security_evaluator` tổng hợp validity, hostname, chain, policy và CT:

- **FAIL:** expired/not yet valid, hostname mismatch, chain/signature/trust
  invalid, blocked algorithm, weak key, CT unknown/rejected hoặc lỗi module
  thiết yếu. Luôn ưu tiên FAIL khi đồng thời có warning.
- **WARNING:** không có critical fail nhưng có cảnh báo CT, NO_SCT, thiếu
  dataset CT hoặc phần kiểm tra CT chưa hoàn tất.
- **PASS:** mọi kết quả thành phần PASS và không có lỗi/cảnh báo.

Trong pipeline hiện tại CT signature/inclusion chưa được verify nên một
target có chain/policy tốt và IDs khớp vẫn nhận WARNING, không khẳng định
tuân thủ đầy đủ CT của trình duyệt hay bảo mật tuyệt đối.

`certificate_security` cô lập lỗi từng module; CLI vẫn in tất cả section,
`Module Errors`, `Security Summary`, `FINAL RESULT` và reasons. TLS fetching
thất bại làm final FAIL mà không tắt certificate verification để thử lại.
Exit code: PASS/WARNING → 0; FAIL → 1. CT analyzer không tham số giữ nguyên.

```powershell
.\.venv\Scripts\Activate.ps1
py main.py
py main.py google.com
py main.py github.com
py -m pytest -v --basetemp=.pytest_tmp -p no:cacheprovider
```

Tests tạo chain và SCT wire-format fixtures tại runtime, mô phỏng network và
module errors; không phụ thuộc Internet. Thư mục `.pytest_tmp` chỉ chứa file
tạm do pytest tạo và được pytest dọn khi chạy lại. Không lưu dữ liệu quan trọng
vào thư mục đó.

Tham khảo thêm [pyOpenSSL X509StoreContext](https://www.pyopenssl.org/en/stable/api/crypto.html)
và [Google log list schema](https://www.gstatic.com/ct/log_list/v3/log_list_schema.json).

## Giai đoạn 3A – Experiments, negative cases và metrics

Experiment runner gọi lại validators của 1/2A/2B. Có một sửa lỗi core nhỏ
được phát hiện khi chạy Microsoft: bổ sung PARTIAL_CHAIN cho OpenSSL store
để chấp nhận **trust anchor đã được tin cậy độc lập** nhưng không tự ký.
TLS mặc định đã chấp nhận loại anchor này. Có test hồi quy cho cả trường hợp
trusted và untrusted; không sửa policy hay expected results để làm khớp output.
Manifest `experiments/test_cases.json` khai báo trước case IDs, nhóm, loại case,
target, expected result, ground truth và clock synthetic UTC cố định.
Không sửa expectations theo actual results.

### Bộ case và ground truth

- **REAL_WEBSITES:** Google, GitHub, Cloudflare, Microsoft và Wikipedia. Đây
  là probes normal HTTPS có expected set `PASS|WARNING`, không phải chứng nhận
  an toàn đã audit. Certificate, dataset snapshot và mạng có thể thay đổi.
  Runner luôn ghi actual result và reasons thực tế.
- **SYNTHETIC_NEGATIVE_CASES:** 14 loại local: expired, not yet valid, hostname
  mismatch, RSA 1024, SHA-1, MD5, broken issuer link, invalid signature, non-CA
  intermediate, self-signed leaf, unknown log, retired log, SCT timestamp ngoài
  interval và NO_SCT. Root/keys local được tạo trong RAM; không mở TLS server
  hoặc dùng website lỗi làm ground truth.

`synthetic_cases.py` tạo certificate thật bằng cryptography, serialize/parse
DER lại và chạy module thật. Các case RSA/weak hashes đo riêng Algorithm
Policy để tránh kết quả chain tạo thêm lỗi không liên quan. Các case còn lại
chạy aggregate validators offline với trust root của lab. CSV ghi
`evaluation_scope` để không nhầm hai phạm vi đo này.

Cryptography X.509 builder không cho ký SHA-1/MD5: helper dùng pyOpenSSL đã có
trong requirements để ký lại certificate bằng thuật toán đó, rồi xác minh
chữ ký fixture bằng RSA public key. Policy vẫn lấy metadata từ certificate
thật; không fake `CryptoInfo`. Backend hiện tại tạo được cả hai. Nếu backend
khác không cho tạo fixture, case ghi `SKIPPED` cùng reason, không giả FAIL
hoặc âm thầm bỏ case khỏi denominator coverage.

SCT local là fixture wire format cho parser/matching, với chữ ký placeholder:
không phải fixture chứng minh SCT signature hợp lệ. Baseline CT do đó vẫn
cảnh báo NOT_VERIFIED. Riêng NO_SCT và SCT_TIMESTAMP_OUTSIDE_INTERVAL có
expected WARNING theo policy 2B đã công bố, không đổi thành FAIL để tăng
chỉ số. Coverage yêu cầu phát hiện dấu hiệu cụ thể, ví dụ `NO_SCT` trong reason
hoặc `timestamp_interval=FAIL`; final WARNING chung chưa đủ để tính phát hiện.

### Cách chạy

Kích hoạt môi trường, chạy toàn bộ tests rồi chạy hai nhóm experiment:

```powershell
.\.venv\Scripts\Activate.ps1
py -m pytest -v --basetemp=.pytest_tmp -p no:cacheprovider
py experiments/run_experiments.py
```

Chạy chỉ 14 local cases, không cần Internet:

```powershell
py experiments/run_experiments.py --offline --output-dir experiments/offline
```

Có thể điều chỉnh timeout hoặc xuất một snapshot khác:

```powershell
py experiments/run_experiments.py --timeout 15 --output-dir experiments/run_02
```

Mỗi lần chạy ghi đè `results.csv` và `summary.json` trong output directory.
Dùng output directories khác nhau để giữ các lần chạy độc lập. Defaults được
xác định từ vị trí script, không phụ thuộc thư mục làm việc. Không chạy
experiment website thật trong unit tests.

### Công thức metrics

**Positive** là case có expected duy nhất `FAIL`. **Predicted positive** là
actual security result `FAIL`; PASS/WARNING là predicted negative.
Các expectations không FAIL, kể cả `PASS|WARNING`, là negative.

| Metric | Công thức |
| --- | --- |
| TOTAL_CASES | Tất cả case đã attempt, gồm COMPLETED, ERROR và SKIPPED. |
| EVALUATED_CASES | Các case COMPLETED, có actual PASS/WARNING/FAIL. |
| CORRECT_CASES | Completed cases có actual thuộc expected set. |
| INCORRECT_CASES | Evaluated − correct. |
| ACCURACY | Correct / evaluated × 100%. |
| MISCONFIGURATION_COVERAGE | Số loại synthetic có ít nhất một case **correct và detected đúng điều kiện** / tổng loại synthetic attempted × 100%. |
| FALSE_POSITIVES | Completed expected non-FAIL nhưng actual FAIL. |
| FALSE_NEGATIVES | Completed expected FAIL nhưng actual PASS/WARNING. |
| FALSE_POSITIVE_RATE | FP / (FP + TN) × 100%. |
| FALSE_NEGATIVE_RATE | FN / (FN + TP) × 100%. |
| Runtime average/median/min/max | Tính trực tiếp từ runtime_seconds của các case attempted. |

`correct` để trống trong CSV khi ERROR/SKIPPED. Lỗi network/module không được
đánh đồng với phát hiện lỗi bảo mật: runner vẫn giữ actual result của tool
nếu đã có (ví dụ FAIL khi fetch thất bại), nhưng đánh dấu execution ERROR và
loại khỏi accuracy/FP/FN. Số errors/skips được báo riêng. Loại lỗi synthetic
không chạy được vẫn nằm trong denominator coverage. Mẫu số 0 trả JSON `null`
và terminal `N/A`, không tạo 0% giả.

Runtime đo bằng `time.perf_counter()` cho từng action: real gồm network và
pipeline; synthetic gồm tạo certificate riêng cho case và validators. Setup
khóa dùng chung được đo riêng trong `run.synthetic_setup_seconds`. Không so
sánh hai loại runtime như cùng một chi phí thực thi. Thời gian tổng trước
export được lưu ở `run.total_wall_seconds`.

### Artifacts và cách đọc kết quả

- `experiments/results.csv`: 9 cột yêu cầu (`case_id`, `category`, `case_type`,
  `target`, `expected_result`, `actual_result`, `correct`, `runtime_seconds`,
  `reasons`), thêm detected, execution_status, evaluation_scope và generation_method
  để audit. Reasons là JSON array được CSV quote đúng, hỗ trợ UTF-8.
- `experiments/summary.json`: metrics tổng, metrics riêng theo category,
  covered/uncovered types, errors/skips, Python/platform, clock, timeout và
  SHA-256 của manifest/policy/dataset và các file implementation experiment/chain.
- `[PASS]` bên cạnh case ID nghĩa là khớp expectation, **không** có nghĩa security
  result PASS. Case RSA 1024 có thể `[PASS]` vì tool báo FAIL đúng ground truth.

Accuracy tổng là mức khớp expectations trong bộ case này. Real-site expectations
là giả định normal-case; xem `by_category.synthetic` để đánh giá nhóm có ground
truth chủ động. Coverage 100% chỉ nói về các loại đã đưa vào bộ thử, không
khẳng định phát hiện mọi lỗi X.509, CT hay mức an toàn tuyệt đối. Các artifacts
là snapshot một lần chạy; chưa có confidence interval hoặc kết luận thống kê
giữa nhiều lần chạy trong Giai đoạn 3A này.

Lần chạy trước sửa partial-chain được giữ nguyên tại
`experiments/baseline_before_partial_chain_fix/`: 18/19 correct, accuracy
94.7368%, một FP ở Microsoft do OpenSSL path verification thiếu issuer.
`experiments/results.csv` và `summary.json` là lần chạy mới sau sửa lỗi;
không xóa hoặc chỉnh baseline để nâng metric.

Đã bổ sung HTML/PDF report và slide HTML trong đợt rà soát nghiên cứu;
không có dashboard hoặc file PowerPoint. Xem mục cập nhật đầu README.


## Giai đoạn 3B – Website Flask local

Website gọi trực tiếp pipeline Python hiện có qua `src/certificate_service.py`.
`app.py` là entry point riêng; `main.py`, validators, algorithm policy và logic
tổng hợp security result giữ nguyên. Web không chạy CLI qua shell.

### Khởi động trên Windows PowerShell

Tại thư mục DT007:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
py app.py
```

Chạy `py app.py` sẽ tự mở **http://127.0.0.1:5000** trong trình duyệt mặc định
ngoài VS Code. Dừng server bằng `Ctrl+C`.
Nếu chưa kích hoạt môi trường, dùng `.\.venv\Scripts\python.exe app.py`.
Server chỉ bind localhost, `debug=False`, không bật reloader.

### Sử dụng và kết quả

Trang chủ (`GET /`) nhận hostname như `google.com` hoặc `github.com`.
Không nhập URL có `http://`, `https://`, đường dẫn, port hoặc khoảng trắng.
`POST /scan` kiểm tra input ở server, gọi engine với port 443 và timeout 10 giây,
đo runtime bằng `time.perf_counter()` rồi render kết quả bằng Jinja2.

Trang kết quả gồm Certificate Information, Hostname Validation (SAN có thể
thu gọn và cuộn), Validity, Cryptography, Certificate Chain theo thứ tự,
Algorithm Policy, SCT & CT Matching và Security Summary với từng reason.
Màu trạng thái: PASS xanh, WARNING cam, FAIL đỏ, UNKNOWN/NOT_VERIFIED xám.
Trường thiếu hiển thị N/A. Có nút quét hostname khác và bố cục responsive.

CT matching giữ nguyên giới hạn của engine: **NOT_VERIFIED** cho chữ ký SCT;
không suy diễn matching thành xác minh chữ ký/inclusion proof. Target có chain
và algorithm policy PASS vẫn có thể nhận final WARNING. UI không sửa verdict.
Lỗi input, kết nối hoặc lỗi nội bộ có thông báo tiếng Việt dễ hiểu; lỗi nội bộ
không trả stacktrace ra trang. Jinja2 escape dữ liệu certificate/hostname.

### Kiểm tra và tương thích CLI

```powershell
py -m pytest -v --basetemp=.pytest_tmp -p no:cacheprovider
py main.py
py main.py google.com
py experiments/run_experiments.py
```

`tests/test_web.py` dùng Flask test client và fixtures/mock offline để kiểm tra
routes, input, từng trạng thái, đầy đủ section, SCT metadata, escaping, lỗi mạng,
lỗi nội bộ và adapter gọi đúng engine. Unit tests không truy cập Internet.
Quét website thật và experiments real-site cần kết nối mạng.

Giai đoạn 3B chỉ thêm giao diện local; không database, login, dashboard,
PDF, HTML report export hoặc các chức năng Giai đoạn 3C.
Tham khảo [Flask documentation](https://flask.palletsprojects.com/en/stable/).

## Giai đoạn 3C – Việt hóa và hoàn thiện demo

Giao diện sử dụng tiếng Việt cho tiêu đề, trường, trạng thái và thông báo.
`src/web_presentation.py` đăng ký Jinja filters qua `app.py`; mã trạng thái
và dữ liệu engine không đổi. Reason chưa có bản dịch chính xác được giữ trong
mục thu gọn **Chi tiết kỹ thuật**, có giải thích tiếng Việt phía trên.
Tên tổ chức, dữ liệu chứng thư, OID và các thuật ngữ kỹ thuật giữ nguyên.

Trang kết quả có năm thẻ tổng quan, điểm đánh giá, chuỗi dạng timeline,
bảng chính sách thuật toán, danh sách SAN thu gọn và SCT dạng accordion
(mỗi lần mở một mục). Tổng hợp an toàn nằm cuối trang. Tooltip giải thích
SAN, CA, SCT, CT Log và MMD. Bảng rộng có thanh cuộn ngang trên màn hình nhỏ.

Điểm trình bày tính từ năm hạng mục của engine: PASS = 20, WARNING = 10,
FAIL hoặc chưa xác định = 0, tổng tối đa 100. Điểm không dùng để quyết định
kết quả cuối và không phải chứng nhận an toàn tiêu chuẩn. Backend vẫn trả
PASS/WARNING/FAIL; giao diện hiển thị ĐẠT/CẢNH BÁO/KHÔNG ĐẠT.

Khi gửi form, nút bị khóa, spinner hiện và chữ đổi thành **Đang kiểm tra...**.
Trang kết quả thay thế form nên loading tự biến mất; khi quay lại bằng nút
Back, form được khôi phục. Các lệnh chạy web, CLI và experiments giữ nguyên.
Không thêm database, đăng nhập, admin hoặc PDF.

Demo:

```powershell
.\.venv\Scripts\Activate.ps1
py app.py
```

Trình duyệt mặc định tự mở http://127.0.0.1:5000. Thử lần lượt `google.com`,
`github.com`, `cloudflare.com`; xem tổng quan, điểm, chuỗi, SCT và lý do cuối
trang. Kết quả thật phụ thuộc chứng thư, dữ liệu CT và thời điểm quét.
