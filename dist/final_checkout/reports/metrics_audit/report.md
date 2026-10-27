# Giai đoạn 1 — Kiểm chứng metrics từ dữ liệu thô

Nguồn: `reports/research_results/raw_results.csv`, kế hoạch đóng băng `config.json`, kết quả cần đối chiếu `summary.json`. Chương trình kiểm chứng độc lập: `experiments/audit_research_metrics.py`; đầu ra máy đọc: `audit.json`. Không sửa dữ liệu nguồn. SHA-256 dữ liệu thô được lưu trong audit.

## Mẫu số và kết quả

90 quan sát = 3 lần × 2 cấu hình × (14 ca hiện có + 1 đối chứng hợp lệ). Mỗi cấu hình có 45 quan sát. Không có ERROR/SKIPPED trong dữ liệu này.

| Chỉ số | Baseline | Extended |
|---|---:|---:|
| Coverage điều kiện, từng lần | 10/14 = 71,428571% | 14/14 = 100% |
| Coverage lỗi/cần lưu ý, từng lần | 10/13 = 76,923077% | 13/13 = 100% |
| Khớp kỳ vọng 14 ca, từng lần | 10/14 | 14/14 |
| FP trên đối chứng hoàn thành | 0/3 | 0/3 |
| FN trên ca có kỳ vọng FAIL | 6/36 = 16,666667% | 0/36 |
| Runtime trung bình/ca | 0,002860571 giây | 0,003192204 giây |

Coverage đòi hỏi đồng thời khớp trạng thái mong đợi **và** `condition_detected=True`; khớp WARNING đơn thuần không đủ. 14 mục không phải 14 lỗi bảo mật: ca `SCT_TIMESTAMP_OUTSIDE_INTERVAL` là hồi quy xác nhận không áp dụng temporal_interval cho thời điểm SCT. 13 mục còn lại gồm cả điều kiện thiếu SCT cần lưu ý, không đồng nghĩa 13 lỗ hổng nghiêm trọng.

FP ở đây là đối chứng hợp lệ bị gán FAIL; WARNING giới hạn CT được đếm riêng, không tính là FP. FN là ca đã hoàn thành có kỳ vọng chính xác FAIL nhưng engine không trả FAIL. Mỗi lần có 12 ca dương theo định nghĩa này; NO_SCT và hồi quy SCT có kỳ vọng WARNING nên không thuộc mẫu số FN. ERROR/SKIPPED không được coi là kết luận âm: báo riêng, vẫn nằm trong mẫu số coverage/khớp kế hoạch.

Baseline bỏ CT: UNKNOWN_CT_LOG và RETIRED_CT_LOG đều trả PASS ở cả 3 lần, tạo 2 × 3 = 6 FN. Baseline cũng không bao phủ NO_SCT và hồi quy SCT, nên coverage là 10/14, không phải 12/14. Extended phát hiện đủ điều kiện được định nghĩa trong fixtures; chưa xác minh mật mã SCT/inclusion proof.

## Tổng hợp và giới hạn

Coverage và runtime báo trung bình theo 3 lần, độ lệch chuẩn mẫu n−1, min/max; FP/FN là tổng số quan sát qua các lần. Trong bộ này các mẫu số mỗi lần bằng nhau nên trung bình FNR bằng FNR gộp. Không được áp dụng giả định này khi số ca hoàn thành khác nhau. Runtime gồm tạo chứng thư từng ca và xác minh, chưa gồm tạo khóa/khởi tạo lab; setup được lưu riêng trong summary.

Không phát hiện sai lệch số học khi đối chiếu tất cả trường từng lần và thống kê tổng hợp. Vấn đề là cách gọi “14 loại lỗi” trong báo cáo cũ dễ gây hiểu nhầm; tài liệu này sửa nghĩa, không thay số đo lịch sử. `condition_detected` vẫn là bằng chứng do bộ kiểm thử ghi, không phải oracle độc lập. Ba lần lặp cùng kịch bản không tạo 36 loại lỗi độc lập. FP=0 trên 3 đối chứng không chứng minh FPR ngoài thực tế bằng 0. Coverage này không phải coverage dòng mã và không phải độ chính xác trên Internet.

Chạy lại: `.venv\Scripts\python.exe experiments/audit_research_metrics.py`. Sai lệch sẽ trả mã thoát 1 và được lưu trong audit.json.
