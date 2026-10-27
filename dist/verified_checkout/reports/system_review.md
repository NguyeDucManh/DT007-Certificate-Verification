# Giai đoạn 3 — Rà soát hệ thống

## Lỗi xác minh mục đích TLS

`X509StoreContext` mặc định xác minh đường dẫn cho mục đích any. Không thể suy từ đường dẫn PKIX hợp lệ rằng EKU/KU cho phép máy chủ TLS. [Đặc tả OpenSSL](https://docs.openssl.org/3.5/man1/openssl-verification-options/) phân biệt kiểm tra purpose và các extension EKU/KU. Kết nối TLS thật vẫn được SSL context kiểm tra; lỗi được phát hiện trong validator offline.

Trước sửa: 4 test tái hiện FAILED, 3 ca hợp lệ PASS (`tests/test_tls_chain_purpose.py`). Sau sửa: 7/7 PASS; nhóm chain/provenance 33/33 PASS. Validator kiểm tra EKU hiện diện trên leaf/intermediate/anchor, cho phép serverAuth/anyExtendedKeyUsage hoặc SGC tương thích; KU leaf hiện diện phải cho digitalSignature/keyEncipherment/keyAgreement. Extension không có không bị coi là lỗi. Sử dụng API cryptography công khai, không phụ thuộc API private pyOpenSSL. Không tuyên bố đây là hiện thực đầy đủ mọi purpose/extension lịch sử OpenSSL. CA constraints, chữ ký, thời hạn, path building và anchor độc lập giữ nguyên. Nếu quyền TLS không đạt, trust FAIL, không xuất trust_anchor đã xác minh. Lý do cụ thể Việt hóa và lưu nguyên bản.

## JSON/HTML còn thiếu đã bổ sung

`main.py --json PATH --html PATH` xuất cùng kết quả engine của một lần fetch, giữ console và exit code. JSON giữ mã trạng thái/reasons/checks; HTML độc lập, UTF-8, autoescape hostname/subject/reason, mở trực tiếp bằng trình duyệt. Không thêm endpoint tải file tùy ý vào Demo. Cổng đích đúng tham số CLI, không cố định 443 trong báo cáo khi dùng cổng khác. Test bảo toàn PASS/WARNING/FAIL, XSS escaping, chỉ gọi engine một lần và lỗi thiếu hostname.

## Bằng chứng tương thích

`reports/system_smoke/20261010/summary.json`: HTTP thật qua server Flask riêng trên cổng ngẫu nhiên, không dừng web người dùng. GET / và /demo: 200; input sai: 400; body quá lớn: 413; POST chạy toàn bộ Demo: 200; POST scan google.com/github.com/cloudflare.com: 200. CLI dataset exit 0, cả ba website WARNING exit 0; JSON/HTML và console log được lưu. Không có traceback trong HTTP responses. CT signature/inclusion vẫn NOT_VERIFIED; không biến WARNING thành PASS.

Sau thay đổi chain đã thực thi lại nghiên cứu trong `reports/research_expanded/post_tls_20261010` (114 quan sát, 3 lần mỗi profile). Thực nghiệm live+synthetic chạy lại 3 lần trong `reports/final_experiments/run_1..3`: mỗi lượt 19/19 khớp kỳ vọng, 14 ca lab còn đủ, ERROR/SKIPPED=0. Nhãn 5 website là quan sát thông thường, không ground truth an toàn độc lập. Số đo lịch sử không bị ghi đè.

Giai đoạn 4 bổ sung Edge headless thật: `reports/browser_smoke/final_20261010/summary.json` có 13 checks đạt, screenshots desktop/390px và CSV tải từ browser. Đã kiểm tra spinner/disabled, score, chain timeline, SCT accordion, single/batch 14 ca, detail link và download. Dùng profile tạm riêng, không đụng browser profile cá nhân. Screenshot mobile và desktop đã xem trực quan; không tràn ngang ở viewport khảo sát. Hai lần harness trước được giữ: handshake reason phrase và selector score sai, không phải lỗi engine/UI; sửa harness rồi chạy lại, không ép kết quả.

Chưa kiểm tra trên điện thoại vật lý hoặc ghi clipboard hệ điều hành; headless viewport không chứng minh tất cả thiết bị. Video/bảo vệ trực tiếp chưa thực hiện.
