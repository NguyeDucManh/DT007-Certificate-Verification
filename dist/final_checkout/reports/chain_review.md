# Rà soát chuỗi chứng thư DT007

## Kết luận và sửa lỗi

Lỗi cũ nằm ở UI: certificate cuối luôn được gán Root / Trust Anchor, dù là
intermediate. Backend cũ yêu cầu DER/fingerprint terminal khớp trust store,
nhưng pipeline chỉ truyền anchor khớp terminal nên không bổ sung root thiếu.
Không có việc tự tin cậy CA server gửi chỉ vì nó là terminal.

Đã thêm trust_anchor vào ChainResult sau OpenSSL verification; root được phân
loại theo subject=issuer và chữ ký tự ký hợp lệ. Trust anchor là thuộc tính
tin cậy độc lập, không đồng nghĩa root tự ký. Terminal không trusted vẫn
intermediate/root không tin cậy, không tự được gán anchor.

Đường dẫn thiếu root được OpenSSL thử xây dựng bằng trust store độc lập;
không tải AIA. Chỉ bổ sung đường dẫn giữ nguyên prefix chain đầu vào, tránh
che lỗi sai thứ tự/signature. Không hoàn tất hoặc path verification lỗi thì
trust FAIL. Giữ chính sách PARTIAL_CHAIN: intermediate trusted trực tiếp có
thể là anchor hợp lệ, không yêu cầu nó phải là root tự ký.

TLSCertificates bổ sung peer_chain_der từ get_unverified_chain trong cùng
TLS session đã xác minh. Chuỗi verify không bị đánh đồng với raw peer chain.
UI ghi nguồn server gửi hoặc store/path bổ sung, metadata chưa có báo chưa thu
thập, không suy đoán root đã được server gửi. CLI đổi Root / Trust Anchor
thành Terminal CA và Verified Trust Anchor riêng.

## shoppe.com trong lần kiểm tra

Leaf CN=shoppe.com, issuer RapidSSL TLS RSA CA G1. Node thứ hai RapidSSL TLS
RSA CA G1, issuer DigiCert Global Root G2, không tự ký. Trust store máy hiện
tại chứa chính CA RapidSSL; path verification kết thúc ở intermediate này.
Giao diện mới: Chứng thư trung gian / Điểm neo tin cậy trực tiếp.
Không hiển thị DigiCert root như một chứng thư đã xác minh nếu path không dùng
nó. Chain/trust PASS, final WARNING do CT giữ nguyên. Trust store khác có thể
cho đường dẫn khác; đây không phải kết luận universal cho mọi máy.

## Kiểm thử và giới hạn

Toàn bộ pytest sau sửa: **367 passed**, 0 failed (53.53 giây lần chạy cuối).

Tests bao phủ intermediate không trusted FAIL; root thiếu nhưng độc lập trong
store hoàn tất PASS; intermediate anchor trực tiếp PASS nhưng không gọi root;
leaf thiếu intermediate FAIL; nguồn root không thuộc peer chain; hồi quy các
signature/constraints/time tests. Test missing_root trước đây kỳ vọng FAIL dù
có issuer root trong store được cập nhật vì backend nay xây dựng và verify
đường dẫn, không sửa rule để ép verdict.

Không thay CT, hostname hoặc algorithm policy. Không thêm AIA/OCSP/CRL.
Nguồn API: https://docs.python.org/3/library/ssl.html và
https://www.pyopenssl.org/en/stable/api/crypto.html#get_verified_chain.
