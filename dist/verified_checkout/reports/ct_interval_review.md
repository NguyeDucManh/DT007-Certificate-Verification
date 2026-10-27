# Rà soát CT temporal_interval

Nguồn: https://www.gstatic.com/ct/log_list/v3/log_list_schema.json
temporal_interval áp dụng ngày hết hạn NotAfter; start inclusive/end exclusive.
Trường temporal_interval không nằm trong required của log. State timestamp
theo schema là thời điểm log vào state, không phải temporal_interval.

Đã rà soát ct_log_analyzer: module chỉ giữ start/end và state timestamp từ
JSON, không diễn giải chúng. Không cần sửa analyzer. Sửa ct_validator để không
dùng interval NotAfter làm interval phát hành SCT. Cả hai bound vắng mặt được
coi không áp dụng; interval thiếu một bound/sai timestamp/sai thứ tự hoặc
NotAfter thiếu là dữ liệu chưa đủ. Không coi UNKNOWN là FAIL mật mã.

Retired có SCT sau retirement vẫn FAIL theo policy hiện tại; trước retirement
WARNING; retirement timestamp thiếu WARNING. Log ID không tìm thấy FAIL
matching; bản ghi trùng WARNING do dữ liệu mơ hồ. Các state khác giữ policy.
NOT_VERIFIED riêng cho signature_validation/inclusion_validation; CT vẫn WARNING
ngay cả metadata PASS. Chưa thực hiện crypto verification hay inclusion proof.

Phần findings phân biệt giới hạn công cụ/dữ liệu chưa đủ/vấn đề phát hiện.
Cảnh báo cùng nguyên nhân được gộp tại findings, còn reasons từng SCT giữ nguyên.
Đổi nhãn UI để không gợi ý temporal_interval kiểm tra timestamp SCT.

Ca SCT_TIMESTAMP_OUTSIDE_INTERVAL giữ dữ liệu cũ, đổi tiêu chí phát hiện thành
hồi quy đúng semantics: timestamp thực trước interval, timestamp_interval
NOT_APPLICABLE, certificate_interval PASS. Expected cuối vẫn WARNING, vì chưa
xác minh SCT/inclusion, không vì thời điểm SCT. Không sửa expected để khớp
output: manifest ghi rõ rationale này. RETIRED_CT_LOG và UNKNOWN_CT_LOG vẫn FAIL
vì điều kiện lab đủ dữ liệu. Không đổi chain/hostname/algorithm policy.

Kiểm tra thực tế nhaccuatui.com trong lần chạy: 3 SCT, 3 matches, 3 log usable,
NotAfter 2027-01-05T23:59:59Z nằm trong cả 3 intervals. SCT phát hành tháng 1/2026
không cần nằm trong interval hết hạn năm 2027. Ba metadata match PASS;
final WARNING duy nhất do SCT signatures/inclusion proofs NOT_VERIFIED.
Đây không phải kết luận website mất an toàn hoặc chứng nhận CT đầy đủ.

Tests sau sửa: 363 passed. Experiments: 19/19 đúng kỳ vọng, 14 synthetic
detected, ERROR/SKIPPED 0/0. Artifacts results.csv/summary.json được chạy lại.
Giới hạn còn lại: không verify mật mã CT, không tải lịch sử log, dataset snapshot
có thể thiếu log mới; trường không đủ dữ liệu không được giả PASS.
