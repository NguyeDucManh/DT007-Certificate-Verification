# DT007 – Giao thức nghiên cứu, thực nghiệm và threat model

## Ghi chú merge trên project hiện tại

Giữ evidence X.509, Demo single/batch và quy tắc CT đã sửa. Thời điểm SCT
ngoài temporal_interval là ca hồi quy semantics, không còn chẩn đoán lỗi.
Coverage 14 mục là coverage điều kiện của bộ thử; summary có thêm coverage
misconfiguration trên 13 mục, loại hồi quy này khỏi mẫu số. Baseline gọi cùng
security_evaluator với include_ct=False; default luôn True cho web/CLI.
FN tính trên ca hoàn tất có expected duy nhất FAIL, prediction positive=FAIL.
FP trong nghiên cứu tính riêng trên valid control, không đánh đồng với live probes.
Profile order được shuffle bởi seed; case properties matched nhưng certificate
keys/serial độc lập giữa profile, không phải paired byte-identical experiment.
Runtime/ca không gồm setup RSA keys; setup_seconds được lưu từng lần.
config.json, evidence.json, execution.log, machine.json và requirements_lock.txt
bổ sung raw CSV/summary/report. Thông số CPU/RAM là cấu hình máy, chưa phải peak
memory hoặc CPU utilization của mỗi ca. Dữ liệu mẫu trong ZIP không được chép.

## 1. Phạm vi và mô hình so sánh

- **Baseline:** validity + hostname + certificate chain + algorithm policy. Không kiểm tra CT.
- **Extended:** giữ toàn bộ baseline và bổ sung CT Log List metadata matching + SCT parsing + trạng thái CT.
- Đây là **ablation study** trên cùng mã nguồn, không phải tái lập thuật toán nguyên bản của bài báo về quản trị WebPKI.
- Phạm vi so sánh offline gồm 14 ca lỗi được định nghĩa trong `experiments/test_cases.json` và một ca đối chứng X.509 hợp lệ trên mỗi lần chạy. Đầu vào được tạo mới và parse DER lại.
- Ca SHA1/MD5 được kiểm tra riêng chính sách thuật toán; các ca khác sử dụng pipeline tổng hợp. SCT trong lab là placeholder, không chứng minh chữ ký SCT hợp lệ.

## 2. Ground truth, phân chia và tránh leakage

- Ground truth xác định trước khi chạy theo thuộc tính chứng thư được tạo (NotAfter, SAN, RSA key length, issuer/signature/CA constraints, log ID/state).
- `expected_result` không được đưa vào validator. `condition_detected` được đánh giá riêng so với status.
- **Không có train/test split:** đây là rule-based verifier, không huấn luyện ML. Nguy cơ leakage chủ yếu là điều chỉnh rule sau khi xem kỳ vọng hoặc tính metric từ kết quả cache.
- Mẫu hiện tại **mất cân bằng**: 14 ca lỗi và 1 đối chứng hợp lệ mỗi lần chạy. Vì vậy 0 false positives trên 1 đối chứng không chứng minh false-positive rate ngoài thực tế.
- Các website live chỉ mang tính quan sát; không gán nhãn chuẩn độc lập bằng việc đoán rằng website lớn phải an toàn.

## 3. Threat model

- **Tài sản:** tính xác thực tên miền, chuỗi tin cậy CA, tính đúng đắn chính sách mật mã, kết luận CT, tính toàn vẹn kết quả báo cáo.
- **Đối tượng/rủi ro:** chứng thư hết hạn/chưa hiệu lực, sai SAN, khóa yếu, chữ ký yếu/sai, intermediate không phải CA, root không đáng tin, metadata SCT không khớp.
- **Ranh giới tin cậy:** website TLS công khai; OS trust store; Google CT Log List snapshot; chính sách JSON; fixtures X.509 cục bộ; ứng dụng Flask hiển thị kết quả.
- **Không nằm trong phạm vi:** an toàn nội dung website, mã độc, phishing, DNSSEC, OCSP/CRL đầy đủ, chữ ký SCT và inclusion proof thực, mức độ tuân thủ đầy đủ mọi browser CT policy.
- **Kiểm soát:** không gửi khóa riêng lab ra ngoài; chỉ dùng domain public cho live scans; lưu checksum của dữ liệu và code; tách ERROR/SKIPPED khỏi FAIL; không coi WARNING của công cụ là website mất an toàn.

## 4. Ma trận và metric

- Chạy `python experiments/research_evaluation.py --repeats 3` từ root project. Cần tối thiểu 3 lần; mặc định đúng 3.
- Mỗi lần chạy tạo mới chứng thư cho baseline và extended, dùng cùng danh sách loại ca và clock cố định; không dùng lại kết quả CSV.
- **Coverage of misconfigurations** = số loại lỗi có `expected_match=True` và `condition_detected=True` / 14.
- **Agreement** = số ca hoàn thành khớp expected / 14; đây không phải accuracy thực tế trên Internet.
- **False positives (FAIL)** = số chứng thư đối chứng hợp lệ bị kết luận FAIL / số chứng thư đối chứng hoàn thành. WARNING thống kê riêng, không tự tính là lỗi nghiêm trọng.
- **Runtime** = perf_counter trên mỗi ca; setup tạo khóa dùng chung đo riêng, không gộp với runtime/ca.
- Tính trung bình và độ lệch chuẩn mẫu giữa 3 lần chạy; với n=3 chỉ dùng mô tả, không khẳng định ý nghĩa thống kê.
- **Ablation:** so sánh baseline với extended để xác định phần tăng coverage khi bật CT. Đây là khác biệt được thiết kế trên bốn loại ca CT; không suy rộng thành mức cải thiện ngoài thực tế.

## 5. Tái lập và giới hạn

- Cố định thời điểm lab: xem `synthetic_reference_time` trong `test_cases.json`.
- `--seed` chỉ cố định Python random; **không thể làm khóa RSA OpenSSL trở nên tất định**. Đối chiếu thuộc tính và status, không đối chiếu serial/fingerprint giữa các lần.
- Môi trường, phiên bản Python, thời điểm chạy và SHA256 của dữ liệu/code lưu trong `summary.json`. Cần thêm `pip freeze` và thông số CPU/RAM máy thật khi nộp.
- Tài nguyên CPU/RAM chưa được đo trong bản chạy này; **không được bịa số**.
- Nếu chạy trên Windows, dùng venv cài `requirements.txt` và lưu lại `python --version`, `pip freeze`, CPU/RAM, phiên bản OpenSSL.

## 6. Cách đọc kết quả

- `reports/research_results/raw_results.csv`: 90 dòng nếu 3 lần × 2 profile × 15 ca.
- `reports/research_results/summary.json`: dữ liệu, checksum, các chỉ số từng lần chạy và thống kê tổng hợp.
- `reports/research_results/report.md`: bảng so sánh dễ đưa vào báo cáo.
- `reports/ct_dataset_profile.json`: provenance, SHA256, version, số operator/log, trạng thái, kiểm tra trùng log ID.

## 7. Công việc phải xác nhận trước khi bảo vệ

1. Chạy lại trên **project mới nhất** của người dùng sau khi merge, không ghi đè phiên bản `/demo` mới.
2. Bổ sung nhiều ca chứng thư hợp lệ, được gán nhãn độc lập; có thể phân tầng theo RSA/ECDSA, CA và loại SCT.
3. Đối chiếu chain validator/trust anchor trên trường hợp thực tế và hoàn thiện export JSON/HTML.
4. Đo CPU/RAM và thực hiện live validation trên danh sách website đã chọn; không đưa dữ liệu live vào cùng accuracy với synthetic.
5. Hoàn thiện báo cáo 20–30 trang, hình/bảng và minh chứng trên máy Windows của nhóm.
