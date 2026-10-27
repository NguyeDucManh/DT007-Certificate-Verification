# DT007 – Phiếu đọc bài báo nền và phạm vi tái lập

**Bài báo được giao:** Karl Grindal, Milton Mueller, Vagisha Srivastava (2025), *Non-governmental governance of trust on the internet: WebPKI as public good*, Journal of Cybersecurity 11(1), tyaf018. DOI: https://doi.org/10.1093/cybsec/tyaf018. Bài công bố ngày 07/08/2025. **Chưa xác nhận phân hạng Q1 theo đúng năm/cơ sở xếp hạng giảng viên yêu cầu.**

## 1. Câu hỏi và phương pháp bài báo

**Cập nhật kiểm chứng 10/10/2026:** Crossref xác nhận DOI, tạp chí, ngày online;
Oxford About ghi JIF 2025 rank 14/275 ở Social Sciences, Interdisciplinary.
Thứ hạng thuộc 25% đầu; đây là suy luận Q1 từ nguồn nhà xuất bản, chưa là
bản xuất JCR trực tiếp/SCImago. Chi tiết và giới hạn phiên bản bài đọc tại
`research_sources/verification.md`; không dùng dòng “chưa xác nhận” ở đầu
phiếu như thể chưa tra cứu gì.

Bài báo nghiên cứu vì sao và bằng cách nào các tác nhân phi chính phủ hợp tác để duy trì cơ chế xác thực website WebPKI như một lợi ích công. Phương pháp chính là **phân tích thể chế**, gồm (1) xác định lợi ích chung cần hành động tập thể; (2) xác định tác nhân và xung đột lợi ích; (3) xác định các quy tắc/thực hành được chấp nhận tạo nên cân bằng thể chế. Đây **không phải** bài báo đề xuất thuật toán kiểm tra chứng thư mới.

Bằng chứng được tác giả sử dụng gồm: biên bản họp CA/B Forum; 10 phỏng vấn bán cấu trúc với người tham gia có mức độ hoạt động cao; các ballot/voting; mẫu URL từ Common Crawl để ước lượng thị phần CA; so sánh browser root stores và mức độ áp dụng CT. Nghiên cứu dùng cả định tính và định lượng.

## 2. Dữ liệu và metric trong bài báo

- Biên bản họp, thành viên và mức tham gia CA/B Forum; kết quả bỏ phiếu.
- Chứng thư thu thập từ mẫu URL; phân bố CA; thành phần root store.
- Chỉ số đánh giá hiệu lực thể chế: kết quả bỏ phiếu, mức độ áp dụng HTTPS/CT, sự hội tụ root stores, số lượng CA và phát hiện/cải thiện xử lý chứng thư cấp sai.

**Không được** viết rằng bài báo gốc báo cáo accuracy/coverage của 14 ca kiểm thử DT007: đó là phép đo mới do nhóm xây dựng.

## 3. Ít nhất 5 hạn chế/điểm cần kiểm chứng khi liên hệ DT007

Đây là **các hạn chế và khoảng trống cần xử lý khi chuyển từ nghiên cứu WebPKI thể chế sang nguyên mẫu kỹ thuật DT007**, không phải tất cả đều là tuyên bố nguyên văn của tác giả.

1. **Khác biệt mục tiêu nghiên cứu:** bài báo đánh giá quản trị WebPKI, DT007 kiểm tra chứng thư. Không thể gọi thí nghiệm DT007 là tái lập toàn bộ kết quả bài báo.
2. **Thiên lệch mẫu quan sát:** mẫu URL trong nghiên cứu có những website không truy xuất được chứng thư trong thời gian giới hạn; việc lấy mẫu live website cho DT007 cũng gặp timeout và thiên lệch truy cập.
3. **Khác biệt trust store:** các browser/OS có tập root khác nhau; một trust store cục bộ không đại diện cho tất cả trình duyệt.
4. **Giới hạn dữ liệu CT:** Google CT Log List là metadata về log, không phải chứng cứ chữ ký SCT/inclusion proof hợp lệ; chỉ đối chiếu log ID không thể xác nhận toàn bộ CT.
5. **Khác biệt giữa chứng thư và website:** chứng thư hợp lệ không xác minh danh tính thương mại hay tính an toàn của nội dung website.
6. **Độ biến động theo thời gian:** chứng thư và trạng thái CT Log thay đổi; phải chốt snapshot và ghi thời điểm quan sát.
7. **Giới hạn thực nghiệm offline:** chứng thư tổng hợp có ground truth rõ nhưng không đại diện cho phân bố lỗi WebPKI ngoài Internet.

## 4. Câu hỏi nghiên cứu DT007 và giả thuyết có thể kiểm chứng

- **RQ1:** Khi thêm CT metadata matching vào pipeline validity/hostname/chain/algorithm, coverage trên 14 ca cấu hình sai thay đổi thế nào?
- **RQ2:** Việc thêm CT metadata matching làm thay đổi runtime trên cùng điều kiện lab thế nào?
- **RQ3:** Pipeline có báo FAIL nhầm cho chứng thư hợp lệ đối chứng hay không, và WARNING xuất hiện do giới hạn xác minh nào?

**H1:** Phiên bản extended đạt coverage cao hơn baseline trên bộ 14 ca đã định nghĩa. **H2:** Runtime extended có thể cao hơn baseline; cần đo, không áp đặt kết quả. **H3:** Không đủ mẫu đối chứng để suy rộng false-positive rate thực tế.

## 5. Mối liên hệ và đóng góp DT007

Bài báo giải thích bối cảnh tin cậy WebPKI và tầm quan trọng của CA, browser, root stores, CT. DT007 hiện thực một phần kỹ thuật cụ thể: phân tích X.509, kiểm tra thời hạn/hostname/chuỗi/chính sách thuật toán và CT metadata; sau đó thực nghiệm so sánh baseline với biến thể bổ sung CT. Đây là **tái lập nguyên mẫu kỹ thuật liên quan**, không phải tái lập phép phân tích thể chế hay số liệu thị phần trong bài báo.

**Nguồn để đối chiếu trước khi nộp:** https://academic.oup.com/cybersecurity/article/11/1/tyaf018/8225340
