# Rà soát trước khi bổ sung chức năng bảo mật

Ngày rà soát: 2026-10-10. Đây là kết quả Giai đoạn 1 của yêu cầu nâng cấp mới; không phải báo cáo hoàn thành Giai đoạn 2–6.

## Căn cứ và phạm vi

Đối chiếu yêu cầu đề tài gốc đã cung cấp, README.md, reports/requirements_traceability.md, reports/system_review.md và PDF khoa học 27 trang. Đọc trực tiếp các module điều phối, thu thập TLS, chain, CT, tổng hợp trạng thái và các điểm tích hợp đầu ra. Chưa thực hiện kiểm toán toàn bộ từng dòng mã hoặc kiểm tra website mới trong giai đoạn này.

PDF trang 6, 10 và 26 ghi rõ chưa có OCSP/CRL/AIA; trang 14 ghi chữ ký SCT và inclusion proof chưa xác minh. Các giới hạn này phù hợp với mã nguồn, không phải bằng chứng rằng chức năng đã được triển khai.

## Phân loại chức năng

| Nhóm | Chức năng | Bằng chứng / kết luận |
|---|---|---|
| Bắt buộc theo đề tài gốc, đã có | Đọc X.509, SAN, hostname, thời hạn | certificate_parser.py, hostname_validator.py, validity_checker.py và tests tương ứng |
| Bắt buộc theo đề tài gốc, đã có | Chữ ký, liên kết issuer/subject, CA, đường dẫn đến trust anchor | chain_validator.py: verify_signature, validate_chain; kiểm tra BasicConstraints, KeyUsage, EKU, thời hạn và OpenSSL store độc lập |
| Bắt buộc theo đề tài gốc, đã có | Chính sách khóa, độ dài khóa, thuật toán băm | algorithm_policy.py và config/algorithm_policy.json |
| Bắt buộc theo đề tài gốc, đã có | Google CT Log List v3, logs/tiled_logs và đối chiếu SCT | ct_log_analyzer.py, sct_parser.py, ct_validator.py; đây là đối chiếu metadata, không phải xác minh mật mã |
| Bắt buộc theo đề tài gốc, đã có | CLI, Web, JSON/HTML, phòng kiểm thử, thực nghiệm | main.py, app.py, certificate_service.py, report_export.py, experiments; 14 ca định nghĩa trong test_cases.json |
| Bắt buộc theo yêu cầu nâng cấp mới, còn thiếu | Thu hồi OCSP và CRL | Chưa có module hoặc kết quả thu hồi trong CertificateAnalysis; chain PASS không chứng minh chứng thư chưa bị thu hồi |
| Bắt buộc theo yêu cầu nâng cấp mới, còn thiếu | Tải intermediate qua AIA có kiểm soát | Chưa có trình tải AIA; get_verified_chain chỉ trả đường dẫn TLS/OpenSSL xây được, không đảm bảo tự tải intermediate qua AIA |
| Bắt buộc theo yêu cầu nâng cấp mới, còn thiếu | Chữ ký SCT | SCTRecord chỉ giữ log_id, timestamp, version; CTResult mặc định NOT_VERIFIED. Chưa giữ đầy đủ đầu vào chữ ký và chưa có bộ xác minh |
| Bắt buộc có điều kiện theo yêu cầu nâng cấp mới, còn thiếu | Inclusion proof | Chưa có kiểm tra Merkle path, chữ ký Signed Tree Head hoặc truy vấn endpoint; phải giữ NOT_VERIFIED khi thiếu đầu vào |
| Mở rộng hữu ích | Kênh tải mạng dùng chung chống SSRF; fixture mật mã offline; nguồn tin cậy khóa CT được xác định rõ | Cần cho các chức năng mới; chưa được xem là đã hoàn thành |
| Ngoài phạm vi | Database, đăng nhập, quản trị, quét mã độc/phishing, bảo đảm an toàn nội dung website | Không triển khai |

Không suy diễn rằng đề tài gốc bắt buộc OCSP/CRL/AIA khi mô tả gốc không nêu rõ; yêu cầu mới hiện làm các chức năng này trở thành công việc cần thực hiện.

## Những điểm phải bảo toàn

1. certificate_fetcher.py dùng ssl.create_default_context(), kiểm tra TLS và hostname; không dùng CERT_NONE. TLS có thể thất bại trước khi trả chứng thư nếu thiếu intermediate. AIA không thể khắc phục trường hợp đó chỉ bằng cách thêm lời gọi sau fetch_peer_chain; phải thiết kế luồng thu thập chưa tin cậy riêng và xác minh đầy đủ trước khi công nhận đường dẫn.
2. chain_validator.py chỉ chấp nhận anchor từ tập độc lập, so fingerprint và xác minh đường dẫn bằng X509StoreContext. PARTIAL_CHAIN cho phép anchor là intermediate được tin cậy độc lập; chứng thư cuối không mặc nhiên là root. Dữ liệu AIA tuyệt đối không được đưa vào tập anchor.
3. security_evaluator.py có include_ct=False cho Baseline và mặc định True cho Extended. Không thay đổi mặc định này hoặc thêm kết quả thu hồi vào số liệu đã công bố mà chưa đánh giá tác động.
4. temporal_interval hiện áp dụng NotAfter, không áp dụng thời điểm SCT. Log ID khớp không chứng minh chữ ký. Không đổi NOT_VERIFIED thành VALID/PASS dựa vào metadata.
5. Giữ synthetic_cases.py, manifest 14 ca, chính sách thuật toán và dữ liệu thô 90 + 114 quan sát. Bằng chứng nâng cấp phải lưu riêng; báo cáo khoa học hiện có là ảnh chụp kết quả trước nâng cấp, chưa viết lại.

## Thứ tự triển khai và tiêu chí chấp nhận

| Giai đoạn | Công việc tiếp theo | Điều kiện trước khi chuyển giai đoạn |
|---|---|---|
| 2 | OCSP/CRL, xác minh chữ ký/issuer/freshness; GOOD/REVOKED/UNKNOWN/NOT_CHECKED/ERROR; tải mạng giới hạn và offline | Test hợp lệ, thu hồi, sai chữ ký/issuer, stale, thiếu dữ liệu, lỗi mạng, SSRF; không coi lỗi tải là GOOD |
| 3 | AIA completion trên dữ liệu chưa tin cậy, giới hạn tải, dùng trust store độc lập | Test thiếu intermediate, sai CA/chữ ký, AIA lỗi, anchor không bị tạo từ AIA |
| 4 | Giữ đủ SCT wire data; xác định loại signed entry và nguồn tin cậy khóa log; xác minh SCT/proof khi đủ dữ liệu | Test mật mã hợp lệ/sai và thiếu dữ liệu; phân biệt VALID/INVALID/NOT_VERIFIED/UNSUPPORTED/ERROR; không tuyên bố live verified từ fixture |
| 5 | Tích hợp Web/CLI/JSON/HTML đồng nhất, bằng chứng và giới hạn tiếng Việt | Không làm mất giao diện hiện có hoặc đổi WARNING thành PASS; kiểm tra lỗi và màn hình nhỏ |
| 6 | Regression, tài liệu và evidence riêng | Full pytest, đủ 14 Demo; đánh giá ảnh hưởng profile trước quyết định chạy lại nghiên cứu |

Trạng thái hiện tại: chỉ hoàn thành rà soát Giai đoạn 1. Chưa triển khai hoặc tuyên bố kiểm chứng các chức năng mới.

## Kiểm chứng trạng thái trước sửa

Bằng chứng thực thi cuối được lưu riêng trong reports/security_extensions/phase1_verified/: validation.json ghi 37 module import thành công, không lỗi import; pytest.xml và pytest.log ghi **426 PASS, 0 FAIL, 0 ERROR, 0 SKIP**. Lần sandbox trước tại phase1_suite/ có 369 PASS và 57 lỗi fixture do WinError 5 truy cập .pytest_tmp; giữ nguyên log, chạy lại với quyền phù hợp và không sửa mã kiểm tra để né lỗi.

phase1_validation/preservation.json ghi SHA-256 các file bảo toàn trước/sau chạy test: synthetic_cases.py, test_cases.json, algorithm_policy.json, dataset, CSV lịch sử 90 quan sát, CSV mở rộng 114 quan sát và PDF khoa học đều không đổi. Manifest vẫn đủ 14 ca Demo. Đây là kiểm chứng bảo toàn và suite hồi quy; chưa chạy lại website, browser hoặc thực nghiệm trong giai đoạn rà soát.
