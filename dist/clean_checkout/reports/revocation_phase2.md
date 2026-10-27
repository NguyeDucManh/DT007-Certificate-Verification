# Giai đoạn 2 — OCSP/CRL

Hoàn thành ngày 2026-10-10. Không triển khai AIA, SCT verification, inclusion proof hoặc sửa báo cáo 27 trang.

## Chức năng

- Đọc AIA OCSP và CRL Distribution Points; không tin cậy URL chỉ vì xuất hiện trong chứng thư.
- OCSP: đối chiếu serial/issuerNameHash/issuerKeyHash, responder ID theo tên hoặc hash khóa, chữ ký thực RSA PKCS#1 v1.5/SHA256–512, EC/SHA256–512, DSA/SHA256 và Ed25519/Ed448; kiểm tra thời gian, extension critical và quyền responder. RSA-PSS OCSP chưa hỗ trợ do API hiện không cung cấp tham số chữ ký, trả ERROR thay vì đoán.
- Issuer phải được caller lấy từ đường dẫn tin cậy độc lập; mặc định không được tin cậy. Module kiểm tra thêm chữ ký chứng thư mục tiêu, CA, KeyUsage và hiệu lực issuer. Phản hồi không tự cấp trust anchor.
- Responder được ủy quyền phải được issuer trực tiếp cấp, còn hiệu lực, có EKU OCSP_SIGNING và quyền ký phù hợp. Thiếu OCSPNoCheck trả UNKNOWN sau khi xác minh chữ ký vì chưa kiểm tra thu hồi của responder; không chấp nhận GOOD dựa vào delegate chưa kiểm tra đầy đủ.
- CRL DER/PEM: issuer, chữ ký, quyền cRLSign, AuthorityKeyIdentifier nếu có, thisUpdate/nextUpdate, số sê-ri, thời điểm thu hồi, extension critical và số sê-ri trùng lặp. Hỗ trợ CRL đầy đủ/direct và IssuingDistributionPoint khớp URI của chứng thư, giới hạn CA/user certificate. Delta, indirect, reason-limited, relative-name hoặc attribute-certificate scope chưa hỗ trợ đầy đủ, không suy ra GOOD.
- Tổng hợp: REVOKED có bằng chứng hợp lệ ưu tiên cao nhất; nếu chưa có REVOKED thì ERROR/UNKNOWN ngăn aggregate GOOD. Không có dữ liệu/issuer tin cậy trả NOT_CHECKED, kèm giải thích không suy ra chứng thư an toàn.
- Mạng: HTTP/HTTPS cổng 80/443, không credentials/fragments/proxy môi trường; từ chối toàn bộ câu trả lời DNS nếu có địa chỉ không công khai, reserved, multicast hoặc IPv6 transition. Pin numeric sockaddr, HTTPS vẫn dùng context mặc định xác minh TLS và SNI tên gốc. Mỗi redirect kiểm tra lại, không downgrade HTTPS.
- Mặc định: deadline mỗi nguồn 8 giây gồm DNS/TLS/streaming, tối đa 2 redirects, 2 MiB/phản hồi, tối đa 4 nguồn/fixture. Tổng thời gian tải tối đa xấp xỉ 32 giây cho bốn nguồn, ngoài thời gian xử lý mật mã. DNS worker tối đa 4; worker bị timeout có thể tiếp tục ở nền nhưng không giữ request và không tăng số worker không giới hạn. Không nhận phản hồi nén, kiểm tra kích thước thực đọc và Content-Length.
- Offline mặc định; result.to_dict() chứa trạng thái/nguồn/hash/chữ ký/issuer/thời gian, sẵn cho tích hợp Giai đoạn 5. Không thay đổi CertificateAnalysis hoặc security_evaluator hiện tại.

## Chính sách và giới hạn

Chuẩn tham khảo: [RFC 6960, đặc biệt 3.2 và 4.2.2.2](https://www.rfc-editor.org/rfc/rfc6960), [RFC 5280, CRL profile và processing](https://www.rfc-editor.org/rfc/rfc5280), [API OCSP cryptography](https://cryptography.io/en/latest/x509/ocsp/). Máy này dùng cryptography 50.0.2.

Clock skew 5 phút. OCSP thisUpdate không quá 24 giờ dù nextUpdate chưa hết hạn; đây là chính sách freshness cục bộ chặt hơn chỉ kiểm tra nextUpdate, không có nghĩa nguồn trả trạng thái REVOKED. OCSP thiếu nextUpdate chỉ có thể được chấp nhận trong cửa sổ tuổi 24 giờ. CRL phải có nextUpdate. Chữ ký phản hồi MD5/SHA1 không được chấp nhận; SHA1 trong OCSP CertID chỉ là định danh issuer, không phải thuật toán chữ ký.

Chưa có nonce request/response: sử dụng freshness và giới hạn tuổi cho phản hồi cache, không tuyên bố chống replay tuyệt đối trong cửa sổ đó. OCSP nhiều SingleResponse trả ERROR vì chưa kiểm tra được đầy đủ extension từng entry bằng API hiện có. Không tải CRL phân mảnh để hợp nhất reason coverage hoặc delta; không kiểm tra OCSP stapling và TLS Feature/must-staple trong giai đoạn này. Chỉ kiểm tra chứng thư mục tiêu được truyền vào, không tự chạy trên mọi intermediate.

GOOD không chứng minh chứng thư đã được phát hành hợp lệ, mọi thành phần chuỗi chưa bị thu hồi hoặc website an toàn. Đây là module độc lập: Web/CLI/JSON/HTML hiện có chưa gọi nó; không được diễn giải các kết quả hiện tại là đã kiểm tra thu hồi. API mặc định trả NOT_CHECKED rõ ràng. Không đổi mặc định Baseline/Extended.

## Bằng chứng thực tế

Chạy mới tại reports/security_extensions/phase2_live_final_20261010/results.json, dùng TLS được xác minh và validate_chain PASS cho cả ba hostname; lưu PEM leaf/issuer, bytes phản hồi nguyên bản, SHA-256, nguồn và thời gian. Không lưu private key.

| Website | Nguồn | Kết quả | Bằng chứng |
|---|---|---|---|
| google.com | CRL | GOOD | Chữ ký/issuer/phạm vi hợp lệ; thisUpdate 2026-10-10 04:49:30 UTC; nextUpdate 2026-10-20 03:49:29 UTC; serial không nằm trong CRL |
| cloudflare.com | CRL | GOOD | Chữ ký/issuer/phạm vi hợp lệ; thisUpdate 2026-10-10 03:17:26 UTC; nextUpdate 2026-10-20 02:17:25 UTC; serial không nằm trong CRL |
| github.com | OCSP | ERROR | Chữ ký đã xác minh; thisUpdate 2026-10-07 13:14:45 UTC, nextUpdate 2026-10-14 13:14:44 UTC; quá tuổi 24 giờ tại lần đo, không chấp nhận GOOD |

Lần trước phase2_live_20261010 được giữ: CRL có IDP trả UNKNOWN trước khi bổ sung kiểm tra scope, không sửa số liệu cũ. Chưa xác nhận GOOD OCSP thực tế hoặc REVOKED thực tế trên Internet. Các trạng thái này đã được kiểm tra với fixtures ký mật mã thực trong môi trường offline, không giả danh chứng thư website. Có cảnh báo deprecation của cryptography khi đọc một anchor serial không dương từ trust store máy; không tắt TLS hay bỏ qua validation để tránh cảnh báo.

## Kiểm thử và bảo toàn

71 kiểm thử mới: OCSP GOOD/REVOKED/UNKNOWN, CRL GOOD/REVOKED, issuer/chữ ký sai, stale, dữ liệu lỗi, protocol lỗi, thiếu nguồn, delegate, phạm vi CRL, giới hạn fixture, SSRF/private/mixed DNS, redirects, downgrade, pinned IP, HTTPS verification, DNS/deadline, size/compression/truncation và tích hợp orchestration với validator thật. Fixtures X.509/OCSP/CRL được tạo và ký ở runtime; mock chỉ dùng cho lỗi transport, không mock kết quả bảo mật.

Toàn bộ **497 PASS, 0 FAIL, 0 ERROR, 0 SKIP**, 40 imports thành công. Evidence: reports/security_extensions/phase2_verified/pytest.xml, pytest.log, validation.json. preservation.json xác nhận synthetic_cases.py, 14-case manifest, policy, Google dataset, CSV 90 + 114 quan sát và PDF 27 trang không đổi. Không chạy lại nghiên cứu vì không thay đổi profile hoặc engine đang sử dụng trong nghiên cứu.

File mới: src/revocation_checker.py, src/revocation_network.py, experiments/revocation_probe.py, tests/test_revocation_checker.py, tests/test_revocation_network.py, báo cáo này và thư mục evidence. File sửa: README.md, .gitignore. Không sửa engine cũ, CT, chain, hostname hoặc policy.

Hướng dẫn chạy offline và probe thực tế nằm trong README, mục Bổ sung OCSP/CRL. Dừng ở Giai đoạn 2 để người dùng kiểm tra.
