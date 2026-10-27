# DT007 – Báo cáo tích hợp bộ bổ sung nghiên cứu

## Bảo toàn và merge

Đọc toàn bộ RESEARCH_ADDON_README.md từ DT007_research_addon_ready.zip.
Chỉ nhập các file runner/profile/tests/tài liệu mới. Không chép synthetic_cases.py
cũ; merge keyword profile và VALID_CONTROL vào bản có evidence X.509, Demo,
quy tắc CT NOT_APPLICABLE và chain đã sửa. Không nhập sample dataset profile
hoặc raw_results/summary/report của addon. Hash ZIP được lưu addon_provenance.json.
367 tests cũ giữ nguyên; thêm tests nghiên cứu. Default profile extended;
web/CLI vẫn gọi evaluator với CT bật. VALID_CONTROL không vào danh sách Demo.

Pytest cuối: **374 passed, 0 failed** (9.03 giây). Lỗi đường dẫn checksum
Windows backslash trong test mới đã được sửa bằng đường dẫn chuẩn POSIX.

Baseline dùng validators hiện có và cùng security_evaluator (include_ct=False),
không tạo evaluator PASS/FAIL riêng. Extended giữ CT metadata matching.
Ca RSA1024/SHA1/MD5 vẫn kiểm tra policy riêng ở cả hai profile, không giả rằng
đã chạy chain/CT cho các ca này. Actual never lấy từ expectation hoặc CSV.

## Kết quả thực đo trên máy hiện tại

Nghiên cứu offline: 3 lần × 2 profile × (14 ca + 1 control) = 90 quan sát.
Thống kê từ reports/research_results/summary.json, không từ ZIP mẫu:

| Profile | Coverage 14 điều kiện | Coverage 13 điều kiện lỗi/cần lưu ý | FP trên 3 control | FN trên 36 positive observations | Runtime trung bình/ca |
| --- | ---: | ---: | ---: | ---: | ---: |
| Baseline | 71.4286% | 76.9231% | 0 | 6 | 0.00286057 giây |
| Extended | 100% | 100% | 0 | 0 | 0.00319220 giây |

FN positive = expected FAIL; prediction positive = actual FAIL. Hai FN mỗi
lần của baseline là UNKNOWN_CT_LOG và RETIRED_CT_LOG khi CT không được chạy.
NO_SCT và regression SCT interval không thuộc positive FAIL. Tỷ lệ control
warnings được ghi riêng: baseline control PASS, extended control WARNING do
NOT_VERIFIED. Mỗi profile có 3 valid control, quá ít để suy rộng FPR thực tế.
Coverage 14 gồm hồi quy semantics, không phải 14 lỗi bảo mật độc lập.
Runtime hai profile trong l?n ?o cu?i xem ? b?ng tr?n; không khẳng định
khác biệt có ý nghĩa thống kê. Xem độ lệch chuẩn, setup và
những yếu tố key generation/CPU scheduling, chỉ có n=3 và inputs không byte-identical.

Ba lượt real + synthetic riêng cũng được chạy và lưu ở reports/live_repeats:
mỗi lượt 19/19 expectation agreement, 0 errors/skips, FP/FN 0/0. Đây là probes
normal-site và bộ lab, không phải nhãn an toàn live website được audit độc lập.

Google snapshot: version 93.6, timestamp 2026-10-06T13:36:54Z, 10 operators,
26 logs + 43 tiled_logs. Checksum, size, state counts, warnings nằm trong
ct_dataset_profile.json. Ngày tạo profile không được gọi là ngày tải dữ liệu.
Giấy phép tái phân phối dataset chưa được xác minh, ghi rõ thay vì tự suy đoán.

## Artifacts và tái lập

- raw_results.csv: 90 observations mới, reasons/status/execution/runtime.
- evidence.json: serial/fingerprint/dates/key/hash, module list và CT structures
  của certificate thực tạo mới; không lưu private keys.
- config.json: manifest, policy, repeats và seed; summary có hashes toàn bộ src,
  runner, synthetic implementation, dataset, policy và manifest.
- execution.log: từng action; máy/CPU/RAM/OS trong machine.json; OpenSSL/Python
  trong summary; dependency versions trong requirements_lock.txt.
- report.md: số đo, không chứa giả định kết quả. Quá trình chạy lại ghi đè output
  được chỉ định; đổi output-dir nếu muốn giữ lần độc lập.

## Đối chiếu yêu cầu giảng viên

| Yêu cầu | Tình trạng |
| --- | --- |
| X.509, hostname, chain, algorithm policy, CT metadata | Đã triển khai và có unit/negative tests; chưa CT cryptographic verification |
| Baseline và biến thể Extended | Hoàn thành ablation bật/tắt CT, không phải thuật toán từ paper |
| Ít nhất 3 lần chạy, raw/config/log và metrics | Hoàn thành nghiên cứu offline 3 lần và real+synthetic 3 lượt riêng |
| Coverage/runtime/FP/FN | Có denominators, completed/error/skipped, phân biệt control và real probes |
| Hồ sơ dataset, checksum, version, schema/quality | Hoàn thành profile; giấy phép và ngày tải snapshot chưa xác minh |
| Threat model, leakage, class imbalance, trust boundary | Có research_protocol.md; không train/test ML vì verifier rule-based |
| Phiếu bài báo và ≥5 hạn chế | Có paper_review.md từ addon; cần đối chiếu đầy đủ primary paper trước nộp; Q1 đúng năm chưa xác nhận |
| Kiểm định/CI và mẫu đại diện | Mới mean/sample std n=3; chưa CI hoặc statistical significance, chưa control đa dạng được gán nhãn độc lập |
| Tài nguyên | Có cấu hình CPU/RAM thật; chưa peak memory/CPU utilization từng ca |
| Báo cáo 20–30 trang | Có khung và report kết quả, chưa bản báo cáo hoàn chỉnh/hình minh họa, slides/video |
| Export JSON/HTML | JSON kết quả nghiên cứu có; Demo CSV có; chưa report HTML xuất file toàn bộ pipeline |
| Đánh giá mọi browser CT / OCSP/CRL | Chưa triển khai, được ghi rõ ngoài phạm vi hiện tại |

Không tuyên bố hoàn thành các mục còn thiếu. Bài paper nghiên cứu quản trị
WebPKI, không cho thuật toán DT007 hoặc accuracy của bộ 14 ca. URL bài báo
trong paper_review.md; nội dung cần kiểm chứng độc lập trước báo cáo cuối.
