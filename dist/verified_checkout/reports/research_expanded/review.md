# Giai đoạn 2 — Nghiên cứu mở rộng và giới hạn

Kết quả mới được thực thi trên máy này, lưu riêng `run_20261010/`: **114 quan sát = 3 × 2 × (14 ca cũ + 5 đối chứng mới)**. Không thay raw/evidence của nghiên cứu 90 quan sát hoặc 14 ca Demo. Mỗi ca gọi engine lại, không đọc CSV để xác định trạng thái. Lỗi/SKIPPED lưu nguyên và tách khỏi mẫu số confusion, vẫn làm giảm coverage theo kế hoạch.

## Đối chứng và nhãn

Năm đối chứng: RSA2048/SHA256, RSA3072/SHA384, EC256/SHA256, EC384/SHA384, Ed25519 public key với chứng thư ký bởi RSA/SHA256. Không gọi ca cuối là chữ ký Ed25519. Chứng thư không có SCT, được CA lab tin cậy ký, thời hạn bao phủ clock, SAN control.example.test. Thuộc tính/nhãn được khai báo trước. OpenSSL store verification riêng và kiểm tra trực tiếp thuộc tính xác nhận nhãn trước khi gọi engine. Oracle không dùng actual/expected của DT007; nhưng chia sẻ backend OpenSSL, chưa là triển khai mật mã độc lập. Nhãn “chứng thư hợp lệ trong trust store lab” không phải “website an toàn hoàn toàn”.

Baseline kỳ vọng PASS, Extended kỳ vọng WARNING vì thiếu SCT. WARNING không bị tự chuyển PASS. PEM công khai leaf/anchor trong evidence cho phép kiểm tra lại; không xuất private key. Các ca cũ tiếp tục X.509 thật; SCT/CT metadata có cấu trúc và placeholder, không phải SCT mật mã hợp lệ. RSA1024/SHA1/MD5 vẫn là policy isolation, không giả rằng chạy full chain/CT.

## Kết quả thật

| Chỉ số | Baseline | Extended |
|---|---:|---:|
| Coverage 14 điều kiện | 71,428571% | 100% |
| Coverage 13 lỗi/cần lưu ý | 76,923077% | 100% |
| FP | 0/15 đối chứng | 0/15 đối chứng |
| FN | 6/36 ca kỳ vọng FAIL | 0/36 |
| Runtime trung bình của 14 ca (giây) | 0,002995576 | 0,002718931 |
| SD runtime giữa 3 lượt | 0,000202928 | 0,000073031 |
| CV runtime | 6,7743% | 2,6860% |
| CPU time trung bình/lượt, gồm 19 ca, chưa setup | 0,270833 s | 0,104167 s |
| RSS tối đa tại ranh giới ca | 39.034.880 byte | 39.084.032 byte |

Không có ERROR/SKIPPED. Runtime của 5 control đo riêng trong summary: gồm sinh khóa mới, oracle và engine, nên không trộn với runtime 14 ca khi so sánh chi phí CT. CPU time là thời gian CPU của tiến trình, **không phải CPU utilization**. Timer Windows có thể lượng tử hóa ca rất ngắn thành 0. RSS đo trước/sau ca; process_peak_rss là đỉnh toàn đời tiến trình, không phải peak riêng mỗi ca. Setup có phép đo CPU/wall/RSS riêng. Máy và dependency lock lưu kèm kết quả.

## Ổn định, khoảng và ablation

Coverage/status ổn định qua 3 lần. Runtime Extended lần này thấp hơn Baseline; dữ liệu 90 quan sát cũ cho thứ tự ngược. Không suy ra CT giúp tăng tốc: keys, thứ tự, scheduler và chi phí fixtures khác nhau. `summary.json` có mean/SD/min/max/CV và khoảng t95 cho trung bình 3 lượt, t(df=2)=4,302653. Khoảng này giả định trung bình lượt độc lập/gần chuẩn, không đủ kiểm chứng với n=3; chỉ trình bày mô tả. Khoảng coverage [100,100] trên fixtures không là khoảng tin cậy population. Không dùng 15 control lặp như 15 loại độc lập để suy rộng FPR. Không khẳng định có khác biệt thống kê giữa profile.

Ablation duy nhất có mục tiêu rõ: bật/tắt CT trong cùng evaluator; Baseline vẫn chạy toàn bộ kiểm tra không CT. Hai FN mỗi lượt do UNKNOWN_CT_LOG/RETIRED_CT_LOG không được khảo sát khi CT tắt. Điều này xác nhận phạm vi module trên các ca thiết kế, không chứng minh mức giảm FN ngoài Internet.

## Dữ liệu và bài báo

Schema v3 chính thức: 0 lỗi; 69 public keys parse được và Log ID khớp SHA256 DER SPKI; 0 lỗi key. Version 93.6, timestamp 2026-10-06T13:36:54Z, 10 operators, 26 logs + 43 tiled_logs. Chi tiết/hash/schema: `reports/ct_snapshot_validation.json`. Không có chữ ký detached đúng snapshot: nguồn gốc mật mã NOT_VERIFIED. Không có thời điểm acquisition gốc. Điều khoản sử dụng Chrome CT Log Lists được lưu; quyền tái phân phối cụ thể chưa xác nhận.

DOI/ngày/tạp chí đã kiểm chứng Crossref. Oxford ghi thứ hạng JIF 2025 14/275 trong Social Sciences, Interdisciplinary, thuộc 25% đầu; suy ra Q1 theo cơ sở này, chưa có bản JCR trực tiếp hoặc SCImago xác nhận. Phương pháp/dữ liệu/≥5 hạn chế có trong `paper_review.md`; nguồn/khó truy cập trong `research_sources/verification.md`. Không tái lập kết quả quản trị WebPKI của bài báo bằng benchmark DT007.
