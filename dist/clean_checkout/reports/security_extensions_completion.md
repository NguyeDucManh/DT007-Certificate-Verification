# Kết quả nâng cấp sau OCSP/CRL

Ngày 2026-10-10. Không tuyên bố mọi chức năng đã hoàn thiện: các giới hạn dưới đây vẫn còn. Báo cáo khoa học 27 trang và dữ liệu nghiên cứu giữ nguyên.

## Bảng triển khai và bằng chứng

| Chức năng | Đã triển khai | Offline | Live | Chưa hỗ trợ / giới hạn |
|---|---|---|---|---|
| OCSP/CRL | Có, module Giai đoạn 2 và tích hợp opt-in | 71 tests OCSP/CRL/transport | CRL GOOD google/cloudflare; OCSP github bị từ chối freshness | Delegate thiếu noCheck, delta/indirect/reason-partition, nonce, stapling: xem revocation_phase2.md |
| AIA completion | Có, DER/PEM single cert, tải có giới hạn, tái sử dụng chain validator | Intermediate thật, thiếu anchor, sai issuer, dữ liệu lỗi, vòng lặp, timeout | Chưa chứng minh ca website thiếu intermediate được cứu qua AIA | PKCS#7 chưa hỗ trợ; TLS xác minh thất bại trước fetch vẫn FAIL, không tự thu thập bằng TLS bỏ xác minh |
| SCT wire data | Có metadata, entry_type, extensions, thuật toán, chữ ký trong SCTRecord | Parser và hồi quy | Parser chạy trong scan thật | Chưa lấy SCT qua TLS/OCSP; không lưu nguyên byte SCT envelope, giữ các trường được ký cần thiết |
| SCT signature v1 | Có RSA/ECDSA SHA256, khóa tin cậy caller cung cấp, Log ID=SHA256 SPKI | Fixture ký thật trên chứng thư X.509 thật; signed bytes precert được cấp rõ ràng | NOT_VERIFIED, chưa có registry khóa được xác thực độc lập | Chưa tự dựng precert TBS/đổi issuer cho preissuer; v2/thuật toán khác UNSUPPORTED |
| STH signature | Có primitive RFC6962 | Chữ ký đúng/sai | Chưa | Chưa xác minh freshness/consistency/gossip, không coi signature hợp lệ là cây mới nhất |
| Merkle inclusion | Có primitive audit path, tree không cân bằng | Tree 1/3 lá, path sai | NOT_VERIFIED | Chưa tải endpoint RFC6962 hoặc static/tiled CT; chưa nối leaf vào STH/transport trong pipeline |
| Web/CLI/JSON/HTML | Có kết quả extensions và opt-in OCSP/AIA | Tests Web/CLI/export + tích hợp boundary | CLI google và Flask cloudflare 200; Edge UI hiện có | Không có UI upload fixtures; CT key registry không tự tin cậy snapshot |

AIA tải tối đa 4 lần, sâu tối đa 6 chứng thư (cấu hình không quá 8), mặc định 256 KiB/download và 8 giây/download; dùng transport Giai đoạn 2 chống SSRF/redirect/DNS rebinding. Chỉ chứng thư có CA, keyCertSign nếu có KU, thời hạn và chữ ký/issuer khớp được thêm vào chuỗi chưa tin cậy. validate_chain vẫn kiểm tra toàn bộ đường dẫn, EKU, CA/pathLen, thời hạn và independent anchors. AIA không thêm bất kỳ downloaded cert nào vào anchors.

## Phương án chuỗi khi TLS handshake mặc định thất bại

Hiện giữ ssl.create_default_context() và xác minh TLS/hostname mặc định. Không có fallback CERT_NONE trong engine. Thiết kế luồng thu thập riêng cần một kết quả chỉ chứa leaf/peer-chain chưa tin cậy; phải qua AIA rồi validate_chain, hostname, thời hạn, thuật toán trước khi báo thành công. Trust store lấy độc lập từ hệ điều hành, không từ AIA. Luồng này chưa triển khai/kiểm chứng nên missing-intermediate trước handshake vẫn báo lỗi rõ, không giả báo đã hoàn thiện khả năng cứu mọi TLS chain.

## CT: chuẩn và giới hạn

Tham khảo [RFC 6962 v1](https://www.rfc-editor.org/rfc/rfc6962) cho CertificateTimestamp, Signed Tree Head, audit path. RFC này đã được thay thế bởi RFC9162 nhưng v1 log không tự trở thành v2; chỉ hỗ trợ loại cấu trúc khai báo rõ trong module. Google CT List v3 là schema danh sách, không phải phiên bản giao thức CT. logs/tiled_logs vẫn được parser cũ xử lý; chưa tự truy vấn tiled/static API hoặc tuyên bố proof đã được xác minh.

verify_sct yêu cầu khóa SPKI trong trusted_keys do caller xác định nguồn tin cậy; không lấy keys từ snapshot rồi tự tuyên bố tin cậy. Precertificate dùng issuer_key_hash và TBS chính xác do caller cung cấp; chưa có tái dựng ASN.1 từ chứng thư cuối, nên embedded SCT trong scan thật vẫn NOT_VERIFIED. Fixture precert kiểm tra cấu trúc signed entry với TBS cung cấp rõ; không chứng minh tái dựng precert của CA thực tế. Merkle primitive không tự xác thực STH, module tách verify_sth và verify_inclusion; ứng dụng chưa kết nối đủ chứng cứ để trả inclusion VALID. Không đổi temporal_interval hoặc CT metadata policy.

## Tích hợp và hồi quy

CertificateAnalysis thêm extensions với default factory để giữ các lời gọi cũ. Mặc định giữ final result cũ; ghi rõ thu hồi NOT_CHECKED và inclusion NOT_VERIFIED. --advanced hoặc checkbox Web bật mạng: REVOKED thêm FAIL; GOOD thêm PASS của riêng thu hồi, không xóa CT WARNING; lỗi/UNKNOWN/NOT_CHECKED thêm WARNING. Cùng analysis đi vào Web view model, CLI và JSON/HTML. Bằng chứng chi tiết có JSON escape trong Web và bản JSON đầy đủ trong HTML export. Không có engine thứ hai hoặc profile nghiên cứu mới.

Tests tích hợp inject trạng thái extension chỉ để kiểm tra propagation và crash boundary; các bài xác minh mật mã riêng dùng chữ ký/cert thật. Không sử dụng expected_status làm actual. Không sửa synthetic_cases.py hoặc test_cases.json.

## Kết quả thực chạy

- 508 pytest PASS, 0 FAIL, 0 ERROR, 0 SKIP; 42 modules import thành công. Evidence final_verified_20261010/{pytest.xml,pytest.log,validation.json}; lần kiểm chứng cuối sau sửa timestamp dùng số nguyên lưu tại final_precise_20261010/.
- 14 Demo chạy lại trong integration_live_20261010/demo_batch.json; Edge kiểm tra single/batch 14 ca, chi tiết và CSV, không thay danh sách cũ.
- CLI google.com --advanced: final WARNING, CRL GOOD, JSON/HTML cùng analysis. Flask cloudflare.com có advanced section, HTTP200; hostname sai HTTP400. Files integration_live_20261010/{google.json,google.html,cli.log,web.html,web_status.json}.
- Edge headless: 13/13 checks đạt, gồm loading, timeline, SCT accordion, score 90, desktop/mobile390px không tràn ngang và Demo. Evidence browser_20261010/summary.json, screenshots. Harness kiểm tra luồng scan mặc định; chưa thao tác checkbox nâng cao bằng browser, Flask integration đã thực thi lựa chọn này.
- Chế độ không mạng: tests fixtures và transport timeout. Chưa kiểm chứng mất kết nối toàn máy hoặc điện thoại vật lý. Không lấy kết quả offline để tuyên bố live SCT VALID.
- preservation.json trong final_verified_20261010 xác nhận byte hashes không đổi cho 14-case manifest, synthetic_cases.py, CT snapshot, policy, raw90/raw114 và scientific PDF.

Thư mục evidence đều nằm dưới reports/security_extensions/. Hai lần final_validation/final_verified giữ riêng vì có bổ sung test sau checkpoint đầu. Không chạy lại research lớn: engine của synthetic Baseline/Extended không đổi; các bộ mới opt-in và tách riêng. Nếu sau này bật extension vào research profile phải thực nghiệm mới với config riêng, không sửa số liệu cũ.

## File thay đổi trong lượt này

Mới: src/aia_completion.py, src/ct_crypto.py, tests/test_security_extensions.py, báo cáo này và evidence.

Sửa: src/sct_parser.py, src/certificate_security.py, src/certificate_service.py, src/web_presentation.py, main.py, app.py, templates/index.html, templates/result.html, README.md, .gitignore, requirements_traceability.md, demo_script.md. Không thêm dependency runtime.

## Chạy và trình diễn

Trong .venv: `python app.py`, mở http://127.0.0.1:5000, chọn checkbox kiểm tra bổ sung, scan tên miền. /demo tiếp tục chạy 14 ca cũ. CLI: `python main.py google.com --advanced --json reports/demo_new.json --html reports/demo_new.html`. Offline: `python -m pytest tests/test_security_extensions.py tests/test_revocation_checker.py tests/test_revocation_network.py -v`. Không có nút Demo mới cho AIA/SCT; các chức năng chưa đủ dữ liệu phải trình bày là chưa xác minh, không dùng fixture để giả kết quả website.

Nội dung cần cập nhật vào PDF ở lượt sau: module/bằng chứng thu hồi, AIA offline và giới hạn handshake, wire data/CT primitives, opt-in UI/CLI, số tests mới, bảng giới hạn. Chưa viết lại PDF theo yêu cầu.
