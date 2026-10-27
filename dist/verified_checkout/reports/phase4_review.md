# DT007 – Báo cáo rà soát hoàn thiện Phase 4

## Các lỗi đã sửa

- Reason hết hạn/chưa có hiệu lực, CT Log retired, SCT timestamp interval,
  missing trusted root, invalid signature, CA invalid và lỗi OpenSSL trong
  CSV được giải thích cụ thể bằng tiếng Việt. Mọi reason gốc giữ trong
  Chi tiết kỹ thuật. Không sửa CSV reasons hoặc kết quả engine để làm test pass.
- VẤN ĐỀ PHÁT HIỆN nằm ngay dưới kết quả cuối: hạng mục, nguyên nhân,
  mức ảnh hưởng và khuyến nghị. Giới hạn chữ ký SCT/inclusion proof được
  ghi rõ là giới hạn công cụ; chẩn đoán timestamp CT không bị đồng nhất với
  eligibility theo ngày hết hạn. Lỗi thực thi được phân biệt với lỗi chứng thư.
- Security Score giữ công thức cũ và giải thích 90/100 không có nghĩa thiếu
  10% an toàn; không dùng score để đổi WARNING thành PASS.
- GET/POST /demo tái sử dụng 14 case trong manifest và SyntheticLab.
  Tạo chứng thư thật trong RAM, gọi validators thật, không dùng kết quả CSV.
  Dữ liệu giả lập và website thực tế có nhãn và điều hướng riêng.
  Case không hợp lệ trả 400; backend không tạo được fixture/lỗi demo trả 503
  với thông báo an toàn, không stacktrace hoặc kết luận giả.

## Kết quả kiểm thử

- Toàn bộ pytest: **329 passed**, 11.44 giây, gồm 14 case demo thật offline,
  translations của reasons CSV, CT limitation, routes, errors và hồi quy web.
- Experiments chạy lại: 19/19 correct, accuracy 100%, coverage các loại
  synthetic trong manifest 100%, FP/FN = 0/0, ERROR/SKIPPED = 0/0.
  Runtime trung bình lần chạy 0.0442 giây; results.csv/summary.json ghi lại thật.
- HTTP bản mới: cả 14 POST demo trả 200; input demo/hostname sai trả 400.
  Google/GitHub/Cloudflare trả 200, final WARNING khớp engine độc lập.
  Score và khu vực giải thích xuất hiện trong HTML.
- Hash main.py, certificate_security.py, chain_validator.py và experiment
  runner giữ nguyên so với trước đợt chỉnh sửa. Không thay logic backend/CLI.
- Cổng 5000 đang có phiên Flask cũ: kiểm thử HTTP bản mới trên 5001,
  sau đó dừng server kiểm thử. Người dùng cần restart phiên 5000 để dùng /demo.

## Giới hạn còn tồn tại / chưa hoàn thành

- Chưa xác minh chữ ký SCT hoặc inclusion proof; matching chỉ đối chiếu
  metadata với snapshot CT. Chưa có OCSP/CRL. Không đánh giá an toàn toàn
  diện website. Không suy diễn normal-site expectations thành audit bảo mật.
- Demo SCT dùng chữ ký placeholder để thử parser/matching; không phải bằng
  chứng SCT hợp lệ mật mã. SHA1/MD5 tùy khả năng backend; trường hợp không
  tạo được phải báo chưa chạy. Clock synthetic khác thời điểm website thật.
- Chưa có công cụ điều khiển trình duyệt để kiểm thử trực quan responsive,
  loading và thao tác accordion; đã kiểm tra HTTP, HTML và Flask test client.
- Reason mới ngoài các mẫu nhận diện vẫn có giải thích chung và bản gốc
  thu gọn để đối chiếu. Không tự diễn giải dữ liệu chưa đủ bằng chứng.
- Không thêm database, đăng nhập, admin hoặc PDF theo phạm vi yêu cầu.

## File thay đổi

app.py; src/web_presentation.py; src/web_findings.py (mới);
src/demo_service.py (mới); templates/base.html; templates/result.html;
templates/demo.html (mới); static/css/style.css; static/js/main.js;
tests/test_web.py; tests/test_phase4.py (mới); README.md;
experiments/results.csv; experiments/summary.json; báo cáo này.
