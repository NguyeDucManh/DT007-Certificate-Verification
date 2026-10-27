# Kịch bản bảo vệ DT007 (8–10 phút)

1. Mở `reports/scientific/defense_slides.html` bằng trình duyệt; dùng phím mũi tên để chuyển 14 slide. Giới thiệu câu hỏi nghiên cứu và phạm vi kiểm tra chứng thư. Nói rõ chưa xác minh nội dung website, thu hồi hoặc CT mật mã đầy đủ.
2. Activate .venv, chạy `py app.py`, mở http://127.0.0.1:5000. Quét google.com. Trình bày kết quả thực hiện tại, không hứa luôn giống kết quả lưu. Nếu mạng lỗi, trình bày lỗi thực tế rồi chuyển phòng kiểm thử offline.
3. Giải thích WARNING CT: chữ ký SCT/inclusion proof NOT_VERIFIED, không phải chứng cứ website mất an toàn. Điểm 90/100 là quy đổi giao diện, không phải xác suất an toàn. Mở “Vấn đề phát hiện” và “Chi tiết kỹ thuật”.
4. Mở chuỗi: phân biệt leaf/intermediate/root/anchor; chỉ ra nguồn máy chủ gửi hoặc bổ sung store. Không gọi phần tử cuối là root nếu không tự ký. Nêu lỗi EKU/KU offline đã tái hiện và sửa bằng regression tests.
5. Mở http://127.0.0.1:5000/demo. Nhãn dữ liệu giả lập luôn có. Chạy ca hết hạn hoặc chữ ký sai: chứng thư KHÔNG ĐẠT nhưng kiểm thử THÀNH CÔNG vì engine phát hiện đúng lỗi. Xem module, bằng chứng và actual/expected; không đọc CSV làm actual.
6. Chạy toàn bộ 14 ca; mở chi tiết một ca và xuất CSV. Nói rõ tỷ lệ khớp 14 ca không phải accuracy Internet. Ca temporal_interval là hồi quy chống báo lỗi sai: thời điểm SCT không phải NotAfter.
7. Chiếu bảng và biểu đồ Baseline/Extended. Baseline tắt CT có 2 FN/lượt; tổng 6/36. Coverage 10/14, còn 13 mục lỗi/cần lưu ý báo riêng. FP=0/15 controls không đủ suy rộng FPR.
8. Cho xem raw CSV/config/evidence/log của `post_tls_20261010`, SHA256 và kết quả pytest XML. Trình bày runtime/CPU time/RSS cùng giới hạn n=3, không nói Extended “nhanh hơn có ý nghĩa” hoặc RSS boundary là peak mỗi ca.
9. Minh họa CLI xuất cùng engine: `py main.py github.com --json reports/demo_live.json --html reports/demo_live.html`. Mở HTML bằng browser. Kết quả là lần đo mới, không giả kết quả cũ.
10. Kết thúc bằng giới hạn và việc còn cần xác nhận: JCR trực tiếp/cơ sở Q1, giấy phép snapshot, mẫu báo cáo trường, video và dữ liệu có nhãn ngoài lab. Không tuyên bố hoàn thành/độ chính xác 100% ngoài thực tế.

## Checklist browser trước buổi bảo vệ

- Kiểm tra spinner/nút disabled khi scan, không submit nhiều lần.
- Mở timeline chuỗi và SCT accordion; kiểm tra tooltip và copy tóm tắt.
- Thu nhỏ màn hình khoảng 360–390 px; bảng cuộn ngang, Log ID/serial không tràn.
- Kiểm tra màu ĐẠT xanh, CẢNH BÁO vàng/cam, KHÔNG ĐẠT đỏ, CHƯA XÁC MINH xám.
- Kiểm tra download CSV, mở HTML và chuyển slide bằng bàn phím.

Edge headless đã kiểm tra loading, timeline, score, SCT accordion, single/batch, detail link, CSV và viewport 390px; evidence tại browser_smoke/final_20261010. Checklist vẫn cần rà trên browser sử dụng khi bảo vệ; clipboard OS và điện thoại vật lý chưa kiểm tra. Video thuyết trình cần người thực hiện quay, không giả tạo video.
# Trình diễn chức năng bổ sung

Chạy `python app.py`, chọn ô kiểm tra bổ sung trên trang chủ; scan google.com,
xem Trạng thái thu hồi, AIA, SCT và inclusion. GOOD chỉ nói trạng thái thu hồi;
CT còn NOT_VERIFIED thì final WARNING không được đổi thành PASS.
CLI: `python main.py google.com --advanced --json reports/demo_new.json --html reports/demo_new.html`.
Offline: `python -m pytest tests/test_security_extensions.py tests/test_revocation_checker.py tests/test_revocation_network.py -v`.
/demo giữ 14 ca cũ; không có fixture website giả hoặc Demo UI mới cho AIA/SCT.
Xem bảng giới hạn và evidence tại security_extensions_completion.md.

