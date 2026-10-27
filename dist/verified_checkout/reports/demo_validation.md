# DT007 – Phòng kiểm thử chứng thư số

## Chạy toàn bộ và xuất báo cáo

Nút CHẠY TOÀN BỘ 14 CA KIỂM THỬ POST action=all lên /demo.
run_all_demos lấy các ca synthetic từ manifest rồi gọi lại run_demo/SyntheticLab.
Mỗi lỗi được ghi riêng: actual chưa có kết quả, test thất bại; không giả FAIL
bảo mật khi chưa hoàn tất. Match rate và test success là hai chỉ số khác nhau:
match rate chỉ so status; success cần cả match và detected. Mẫu số toàn bộ ca
gồm cả lỗi/skipped. Total runtime gồm tạo dữ liệu và điều phối.

CSV sinh từ snapshot batch đã chạy, nhúng JSON escape an toàn vào HTML; nút
download dùng Blob UTF-8 BOM trong trình duyệt. Không đọc dữ liệu cũ, không có
database và không thực thi lại khi xuất. Bảng cuộn ngang trên mobile; mỗi tên
ca liên kết mở details tương ứng với metadata X.509, modules, reasons và CT.
Thống kê kiểm thử không phải độ chính xác hoặc độ an toàn website thực tế.

## Nguồn dữ liệu và cách thực thi

`experiments/test_cases.json` khai báo 14 case synthetic, expectation và clock
UTC cố định. `experiments/run_experiments.py` và `src/demo_service.py` đều gọi
`SyntheticLab.run()` trong `experiments/synthetic_cases.py`. Không đọc results.csv
để đưa ra verdict. Backend nhận ID synthetic đã khai báo; không nhận lệnh hay
đường dẫn từ form. Policy đọc từ cấu hình server, không từ dữ liệu POST.

Tất cả 14 case tạo certificate X.509 trong RAM bằng cryptography, serialize DER
và parse lại trước khi kiểm tra. SHA-1/MD5 dùng pyOpenSSL ký lại certificate và
verify chữ ký fixture riêng. Không fake CryptoInfo. Không tạo được fixture thì
báo lỗi chưa chạy, không đưa ra verdict giả.

SCT là fixture wire-format có cấu trúc, chữ ký placeholder; CT Log là dataset
có cấu trúc cục bộ. Đây không phải mock kết quả validator, nhưng cũng không phải
SCT mật mã hợp lệ hay dataset Google thật. NO_SCT không có extension SCT.
Không có case demo nào dùng mock để tính actual result. Một số unit tests web
inject/mocking service để thử lỗi và mismatch; đó là test giao diện, không phải
chứng cứ engine phát hiện lỗi. Tests riêng chạy cả 14 case bằng lab thật.

## Phạm vi và giới hạn từng case

Mọi dòng dùng X.509 thực được tạo trong RAM. Nhóm tổng hợp gọi crypto_info,
algorithm_policy, validity_checker, hostname_validator, chain_validator,
ct_log_analyzer, sct_parser, ct_validator và security_evaluator. Nhóm riêng chỉ
gọi crypto_info và algorithm_policy cho kết quả khảo sát.

| Case | Đầu vào / điều kiện | Phạm vi | Mong đợi | Giới hạn riêng |
| --- | --- | --- | --- | --- |
| case_101 EXPIRED_CERTIFICATE | NotAfter trước clock một ngày | Tổng hợp | FAIL | Clock cố định, không fetch TLS server hết hạn |
| case_102 NOT_YET_VALID_CERTIFICATE | NotBefore sau clock một ngày | Tổng hợp | FAIL | Clock cố định, không đo sai lệch đồng hồ máy thật |
| case_103 HOSTNAME_MISMATCH | SAN example.test, yêu cầu other.example.test | Tổng hợp | FAIL | DNS/SAN lab, không đo DNS hoặc TLS thực tế |
| case_104 RSA_1024 | Khóa RSA thực 1024 bit | Chính sách riêng | FAIL | Không có verdict chain/CT/TLS cho case này |
| case_105 SHA1_SIGNATURE | Chữ ký RSA/SHA-1 thực, verify fixture riêng | Chính sách riêng | FAIL | Chữ ký hợp lệ về toán học vẫn bị policy chặn; tùy backend ký |
| case_106 MD5_SIGNATURE | Chữ ký RSA/MD5 thực, verify fixture riêng | Chính sách riêng | FAIL | Tùy backend; không tạo được phải báo chưa chạy |
| case_107 BROKEN_CHAIN | Leaf issuer khác intermediate subject | Tổng hợp | FAIL | Chuỗi lab, không thử tải AIA |
| case_108 INVALID_SIGNATURE | Issuer đúng nhưng signer dùng khóa khác | Tổng hợp | FAIL | Xác minh chữ ký trong chain local, không thử TLS network |
| case_109 NON_CA_INTERMEDIATE | BasicConstraints CA=False | Tổng hợp | FAIL | Chỉ điều kiện CA giả lập này, không bao phủ mọi critical extension |
| case_110 SELF_SIGNED_LEAF | Leaf tự ký, không phải anchor tin cậy | Tổng hợp | FAIL | Root trust store riêng của lab, không thay trust store hệ thống |
| case_111 UNKNOWN_CT_LOG | SCT ID không có trong dataset lab | Tổng hợp | FAIL | CT matching; không kiểm tra chữ ký SCT/inclusion proof |
| case_112 RETIRED_CT_LOG | SCT sau timestamp retirement | Tổng hợp | FAIL | Snapshot trạng thái lab, không tái dựng lịch sử CT thực |
| case_113 SCT_TIMESTAMP_OUTSIDE_INTERVAL | SCT trước interval nhưng NotAfter nằm trong | Tổng hợp | WARNING | Chẩn đoán timestamp; Google interval áp dụng NotAfter, không eligibility FAIL |
| case_114 NO_SCT | Không có SCT extension nhúng | Tổng hợp | WARNING | Không thu SCT từ TLS extension hoặc OCSP |

Nhóm tổng hợp dùng dữ liệu SCT/CT Log có cấu trúc như trên; nhóm chính sách
không thực thi CT. Root và clock đều riêng của lab. Không kiểm tra OCSP/CRL,
không chứng nhận an toàn website và không mô phỏng tất cả lỗi X.509.

## Bằng chứng trên giao diện

Mỗi lần bấm CHẠY KIỂM THỬ tạo certificate mới, hiển thị serial, SHA256,
subject/issuer, dates, key/hash, module list và cấu trúc CT khi đã thực thi CT.
Metadata lấy trực tiếp từ leaf thật sau parse DER. SyntheticOutcome chỉ được
bổ sung evidence, không đổi các quy tắc, actual status hoặc reasons.
Kết quả mong đợi lấy từ manifest, không truyền vào lab. Đối chiếu ĐÚNG/SAI chỉ
so actual với expectation. KIỂM THỬ THÀNH CÔNG còn yêu cầu phát hiện điều kiện
khảo sát; mismatch hoặc chưa detected hiển thị KIỂM THỬ THẤT BẠI.
Runtime đo tạo lab, load policy và thực thi, không phải thời gian TLS mạng.

## Cách chạy và kiểm thử

```powershell
.\.venv\Scripts\Activate.ps1
py app.py
py -m pytest -q --basetemp=.pytest_tmp -p no:cacheprovider
```

Mở http://127.0.0.1:5000/demo. Nếu server cũ đang chạy, Ctrl+C rồi khởi động lại.
Trang `/` tiếp tục quét website thực tế. Kết quả kiểm tra tự động sau nâng cấp:
**353 tests passed**, gồm chạy cả 14 case, bằng chứng certificate mới giữa hai
lần chạy, phạm vi modules, lỗi input, mock mismatch hiển thị thất bại và hồi quy
tất cả chức năng cũ. Chưa có kiểm thử thao tác trực quan bằng browser automation.
