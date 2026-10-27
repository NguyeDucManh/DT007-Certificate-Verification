# KHUNG BÁO CÁO DT007 (20–30 trang khi hoàn thiện)

**Tên đề tài:** Trình xác minh chuỗi chứng thư số và chính sách thuật toán.

## Chương 1 – Tổng quan (3–4 trang)
Bối cảnh WebPKI, vai trò CA/root store/CT, mục tiêu, câu hỏi nghiên cứu RQ1–RQ3, phạm vi và đóng góp. Dẫn bài báo nền tại `paper_review.md`.

## Chương 2 – Cơ sở lý thuyết và nghiên cứu liên quan (4–5 trang)
X.509, ASN.1/DER, SAN, BasicConstraints, RSA/ECDSA, hash, PKIX chain validation, CT/SCT và giới hạn. Phân tích bài báo Grindal et al. (2025), phương pháp, dữ liệu, metric, ít nhất 5 khoảng trống liên hệ DT007.

## Chương 3 – Dữ liệu và thiết kế hệ thống (4–5 trang)
Nguồn Google CT Log List v3; checksum/version, EDA, schema, thời điểm snapshot. Kiến trúc pipeline Python, Flask, validator modules, threat model, giới hạn trust anchor, kiểm soát input. Đưa sơ đồ luồng từ chứng thư đến báo cáo.

## Chương 4 – Thiết kế thực nghiệm (3–4 trang)
Baseline/extended, 14 lỗi và đối chứng hợp lệ, ground truth, môi trường, 3 lần chạy, kiểm soát seed/clock, cách tính coverage/runtime/false positives, giới hạn class imbalance.

## Chương 5 – Kết quả và thảo luận (4–5 trang)
Chèn bảng số liệu **từ máy nhóm** sau khi chạy `research_evaluation.py`, không dùng số dự kiến. Phân tích so sánh, runtime, lỗi chưa phát hiện, cảnh báo CT, các tình huống thực tế, ablation, độ ổn định. Thêm hình chụp giao diện thật và ví dụ RSA_1024, NO_SCT.

## Chương 6 – Kết luận (2–3 trang)
Những gì thực sự triển khai, giới hạn, hướng phát triển xác minh SCT/inclusion proof và thêm tập dữ liệu gán nhãn độc lập.

## Phụ lục và tài liệu tham khảo
README chạy từ đầu; version/dependency lock, checksum, mã nguồn, raw results CSV, summary JSON, hướng dẫn demo và trích dẫn DOI. Rà soát bí mật/tài khoản trước khi nộp.

> Đây là **khung có hướng dẫn nội dung**, chưa phải báo cáo 20–30 trang đã hoàn chỉnh. Các số liệu trong báo cáo cuối phải lấy từ lần chạy thực tế trên máy nhóm.
