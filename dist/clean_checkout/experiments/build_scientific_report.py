"""Build research documents and plots from measured artifacts, never sample data."""
from __future__ import annotations
import argparse
import csv
from dataclasses import dataclass, field
from html import escape
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("MPLCONFIGDIR", str(ROOT / ".cache/matplotlib"))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@dataclass
class Section:
    """Report content shared by PDF, standalone HTML and defense slides."""
    title: str
    paragraphs: list[str]
    table: list[list[str]] = field(default_factory=list)
    figure: str | None = None


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def source_part(name: str, heading: str, maximum: int = 2800) -> str:
    """Reuse a bounded, relevant section of existing project documentation."""
    text = (ROOT / "reports" / name).read_text(encoding="utf-8")
    if heading not in text:
        raise ValueError(f"Không tìm thấy mục {heading} trong {name}")
    part = text.split(heading, 1)[1].split("\n## ", 1)[0].strip()
    # Preserve complete paragraphs; never turn a partial excerpt into a citation.
    paragraphs, selected, size = re.split(r"\n\s*\n", part), [], 0
    for paragraph in paragraphs:
        if size + len(paragraph) > maximum:
            break
        selected.append(paragraph)
        size += len(paragraph)
    return "\n\n".join(selected).replace("**", "").replace("`", "")


def figures(study: dict, output: Path) -> None:
    """Create exportable scientific figures using actual summary values."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    output.mkdir(parents=True, exist_ok=True)
    names = ["baseline", "extended"]
    labels, colors = ["Baseline", "Extended"], ["#385970", "#16826b"]
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.8), layout="constrained")
    for ax, metric, title in zip(axes, ["coverage_percent", "misconfiguration_coverage_percent"], ["14 điều kiện kiểm thử", "13 lỗi/điều kiện cần lưu ý"]):
        values = [study["profiles"][p]["descriptive"][metric]["mean"] for p in names]
        ax.bar(labels, values, color=colors)
        ax.set(ylim=(0, 115), ylabel="Coverage trên bộ thử (%)", title=title)
        for i, value in enumerate(values):
            ax.text(i, value + 2, f"{value:.2f}%", ha="center")
    fig.savefig(output / "coverage.png", dpi=180)
    fig.savefig(output / "coverage.svg")
    plt.close(fig)
    fig, ax = plt.subplots(figsize=(8, 4), layout="constrained")
    for name, label, color in zip(names, labels, colors):
        runs = study["profiles"][name]["runs"]
        ax.plot([r["repeat"] for r in runs], [r["synthetic_wall_mean_seconds"] * 1000 for r in runs], marker="o", color=color, label=label)
    ax.set(xlabel="Lần chạy", ylabel="Runtime trung bình 14 ca (ms)", title="Thời gian thực đo; không gồm setup")
    ax.set_xticks([r["repeat"] for r in study["profiles"]["baseline"]["runs"]])
    ax.legend()
    fig.savefig(output / "runtime.png", dpi=180)
    fig.savefig(output / "runtime.svg")
    plt.close(fig)


def sections(study: dict, audit: dict, dataset: dict, tests: dict) -> list[Section]:
    """Assemble findings with precise denominators and explicit remaining limits."""
    profiles = study["profiles"]
    cases = read_json(ROOT / "experiments/test_cases.json")["SYNTHETIC_NEGATIVE_CASES"]
    quality = dataset["dataset_profile"]
    controls = read_json(ROOT / "reports/research_expanded/post_tls_20261010/config.json")["controls"]
    metric_rows = [["Cấu hình", "Coverage 14", "Coverage 13", "FP / đối chứng", "FN / dương"]]
    runtime_rows = [["Cấu hình", "Mean ms", "SD ms", "CV %", "Khoảng t95 ms"]]
    resource_rows = [["Cấu hình", "CPU/lượt (s)", "RSS boundary max (MiB)"]]
    for name, p in profiles.items():
        d = p["descriptive"]
        metric_rows.append([name, f"{d['coverage_percent']['mean']:.4f}%", f"{d['misconfiguration_coverage_percent']['mean']:.4f}%", f"{p['FP']}/{p['controls_completed']}", f"{p['FN']}/{p['positive_completed']}"])
        r = d["synthetic_wall_mean_seconds"]
        interval = r["t95_mean_interval"]
        runtime_rows.append([name, f"{r['mean']*1000:.4f}", f"{r['sample_std']*1000:.4f}", f"{r['cv_percent']:.2f}", "N/A" if interval is None else f"[{interval[0]*1000:.4f}, {interval[1]*1000:.4f}]"])
        resource_rows.append([name, f"{d['cpu_total_seconds']['mean']:.6f}", f"{max(r['rss_boundary_max_bytes'] for r in p['runs'])/1048576:.3f}"])
    case_rows = [["Mã / loại", "Kỳ vọng", "Điều kiện khảo sát"]]
    for c in cases:
        case_rows.append([c["case_id"] + " / " + c["case_type"], str(c["expected_result"]), c["ground_truth"]])
    return [
        Section("DT007 — Trình xác minh chuỗi chứng thư số và chính sách thuật toán", [
            "BÁO CÁO NGHIÊN CỨU VÀ THỰC NGHIỆM. Sinh viên: [điền họ tên, mã số và lớp]. Giảng viên: [điền tên]. Bản dự thảo kỹ thuật phục vụ rà soát; cần áp dụng mẫu trình bày chính thức của trường trước khi nộp.",
            f"Tóm tắt: DT007 kết hợp phân tích X.509, hostname, thời hạn, chuỗi chứng thư, thuật toán và đối chiếu metadata CT. Nghiên cứu mới có {study['observations']} quan sát qua {study['repeats']} lần mỗi cấu hình, giữ nguyên 14 ca phòng kiểm thử và bổ sung 5 đối chứng hợp lệ. Baseline bỏ CT để khảo sát đóng góp module; Extended giữ CT. Mọi kết quả trong báo cáo lấy từ raw CSV/summary/evidence thực chạy, không từ số liệu mẫu.",
            "Các kết quả xác nhận khả năng phát hiện điều kiện của bộ thử có kiểm soát, không đo xác suất website an toàn trên Internet. Chữ ký SCT/inclusion proof vẫn chưa xác minh; điều này không tự chứng minh SCT sai. Các giới hạn dữ liệu, đối chứng và khả năng suy rộng được trình bày cùng kết quả, thay vì che giấu bằng điểm số giao diện.",
            f"Kết quả kiểm thử tự động được ghi nhận: {tests.get('tests', 'chưa có XML')} tests, failures={tests.get('failures', 'chưa xác nhận')}, errors={tests.get('errors', 'chưa xác nhận')}. Ngày đo mới: {study['created_utc']}. Tài liệu được dựng lại từ artifacts bằng experiments/build_scientific_report.py."]),
        Section("1. Vấn đề, phạm vi và câu hỏi nghiên cứu", [
            "Chứng thư số giúp liên kết khóa công khai với danh tính được CA chứng nhận. Việc giải mã được X.509 chưa đủ để kết luận tin cậy: tên miền, thời hạn, chữ ký, ràng buộc CA và nguồn điểm neo đều phải được kiểm tra. Chứng thư cuối chuỗi máy chủ gửi có thể chỉ là intermediate; root có thể được tìm trong trust store. DT007 tách những dữ kiện này trong engine và lớp trình bày.",
            "RQ1: bổ sung đối chiếu CT metadata thay đổi coverage điều kiện thế nào? RQ2: runtime và tài nguyên tiến trình biến động qua các lần chạy thế nào? RQ3: đối chứng hợp lệ có bị báo FAIL và WARNING có nguyên nhân gì? Ba câu hỏi được trả lời trong phạm vi lab. Không có dữ liệu có nhãn độc lập trên toàn Internet để ước lượng accuracy thực tế.",
            "Đóng góp gồm lab chứng thư có chữ ký thật, bằng chứng công khai cho đối chứng, CT ablation dùng cùng engine, phép đo tái lập và giao diện giải thích tiếng Việt. Không xây evaluator PASS/FAIL riêng cho Demo. Không có database, đăng nhập, mô hình học máy hoặc dashboard quản trị; những thành phần này không giải quyết câu hỏi nghiên cứu đã xác định."]),
        Section("2. Bài báo nền và xác minh thư mục", [
            "Karl Grindal, Milton Mueller, Vagisha Srivastava: Non-governmental governance of trust on the internet: WebPKI as public good. Journal of Cybersecurity 11(1), tyaf018, DOI 10.1093/cybsec/tyaf018; Crossref xác nhận ngày trực tuyến 07/08/2025. Metadata gốc và checksum lưu trong research_sources/20261010.",
            "Oxford About ghi JIF 2025 và thứ hạng 14/275 ở Social Sciences, Interdisciplinary. Thứ hạng thuộc 25% đầu, là cơ sở suy ra Q1 ở category/năm này; chưa có bản xuất trực tiếp JCR hoặc bằng chứng SCImago tương ứng. Không nhầm tạp chí với Cybersecurity của nhà xuất bản khác.",
            "Bài báo giải thích cơ chế quản trị tin cậy, không cung cấp bộ quy tắc verifier để sao chép. DT007 tái lập một nguyên mẫu kỹ thuật liên quan và xây nghiên cứu CT ablation riêng. Không gọi coverage lab là kết quả tái lập thống kê thị phần hay quản trị trong bài báo."]),
        Section("3. Phương pháp, dữ liệu và metric của nghiên cứu nền", [source_part("paper_review.md", "## 1. Câu hỏi và phương pháp bài báo"), source_part("paper_review.md", "## 2. Dữ liệu và metric trong bài báo"),
            "Bản tác giả đọc được tại UTD; PDF xuất bản chính thức không lấy được qua công cụ hiện tại. Việc đối chiếu chi tiết phiên bản xuất bản còn cần hoàn tất trước nộp. Không chèn số liệu gốc chưa kiểm chứng vào bảng thực nghiệm DT007; hai nghiên cứu có đơn vị quan sát và mục đích khác nhau."]),
        Section("4. Hạn chế và khoảng trống chuyển sang nguyên mẫu", [source_part("paper_review.md", "## 3. Ít nhất 5 hạn chế/điểm cần kiểm chứng khi liên hệ DT007", 3900),
            "Các hạn chế này là phân tích áp dụng cho DT007, không tất cả là kết luận nguyên văn của tác giả. Đặc biệt, tập URL live và tập chứng thư tổng hợp không thay thế dữ liệu biên bản/phỏng vấn của nghiên cứu nền. Mọi suy luận từ hiệu lực quản trị sang trạng thái an toàn kỹ thuật cần bằng chứng riêng."]),
        Section("5. Threat model và ranh giới tin cậy", [source_part("research_protocol.md", "## 3. Threat model"),
            "Đầu vào không được tin cậy: tên miền, chứng thư do máy chủ gửi, metadata CT và form Demo. Trust anchors phải đến từ store độc lập, không tự nâng chứng thư máy chủ gửi thành điểm tin cậy. Form Demo chỉ nhận ID trong allowlist; không nhận đường dẫn hay lệnh hệ thống. Flask bind localhost, debug tắt; không triển khai nguyên mẫu như dịch vụ quét công khai.",
            "Engine fail closed khi thiếu kiểm tra thiết yếu; dữ liệu CT không đủ được phân biệt với lỗi mật mã. HTML escape tên miền, chủ thể và chi tiết gốc để không biến dữ liệu chứng thư thành mã script. Không xuất private keys lab. Chỉ quét thông tin TLS công khai, không đăng nhập, không khai thác, không lấy nội dung riêng tư."]),
        Section("6. Hồ sơ dữ liệu Google CT Log List", [
            f"Snapshot version {quality['version']}; timestamp {quality['dataset_timestamp']}; {quality['operators']} đơn vị vận hành; tổng {sum(quality['logs_by_type'].values())} logs gồm {quality['logs_by_type']}. Đây là metadata CT Log, không phải corpus chứng thư TLS được gán nhãn lỗi. Không được dùng tổng số log để làm mẫu số FP/FN của verifier.",
            "Nguồn định danh: https://www.gstatic.com/ct/log_list/v3/log_list.json. File được giữ nguyên, profiler và validator không cập nhật snapshot. Thời điểm tải gốc không được ghi; thời điểm tạo profile không phải ngày acquisition. Các thực nghiệm lab dùng metadata giả lập có cấu trúc đã ghi rõ, không giả rằng đang ký SCT bằng khóa của Google CT Log.",
            f"SHA-256 snapshot: {quality['sha256']}. Hash phục vụ tái lập và phát hiện sửa file, không tự chứng minh chữ ký nhà phát hành. Phân bố trạng thái:",
            "Các URL/key/log_id được giữ để phân tích. Với tiled_logs, submission_url và monitoring_url có vai trò khác url của logs RFC6962; analyzer hỗ trợ cả hai loại, không ép cấu trúc tiled thành RFC6962."], [["Trạng thái", "Số log"]] + [[s, str(n)] for s,n in quality["states"].items()]),
        Section("7. Schema, chất lượng và điều khoản dữ liệu", [
            f"Schema chính thức v3 được lưu độc lập. Kết quả: {len(dataset['schema_errors'])} lỗi schema, {len(dataset['key_errors'])} lỗi key; {dataset['public_keys_and_ids_verified']} public keys parse DER và Log ID khớp SHA256 SPKI. Kiểm tra datatype/format và định danh được thực hiện lại bằng jsonschema và cryptography, không lấy count hard-code để kết luận hợp lệ.",
            "Không có detached signature đúng snapshot, nên publisher signature vẫn NOT_VERIFIED. Schema hợp lệ không chứng minh dữ liệu đúng ở thời điểm scan. Danh sách có thể đổi mỗi ngày; nghiên cứu cần chốt snapshot, còn kết luận operational cần hiểu độ mới và chính sách trạng thái. Dataset không cung cấp mọi lịch sử trạng thái.",
            "Chrome CT Log Lists có Acceptable Use Policy riêng: nghiên cứu hệ sinh thái và CT enforcement trong TLS clients không có cùng điều kiện sử dụng. Quyền tái phân phối snapshot chưa xác nhận; không áp dụng giấy phép Apache của repository khác cho JSON gstatic. Khi đóng gói nộp cần kèm nguồn/điều khoản và xác nhận hình thức phân phối phù hợp."]),
        Section("8. Kiến trúc và bảo toàn chức năng", [
            "CLI và Flask dùng cùng certificate_security pipeline. Service tạo view model, presentation dịch trạng thái và giải thích, không đánh giá lại engine để đổi verdict. Phòng kiểm thử gọi SyntheticLab theo manifest, có kết quả actual mới mỗi lần; CSV download xuất snapshot đã chạy, không làm nguồn actual.",
            "Phân chia module giúp kiểm thử độc lập: fetcher kiểm tra TLS và lấy chuỗi; parser/crypto_info đọc X.509; validators trả dữ liệu có cấu trúc; evaluator tổng hợp; export serialize cùng kết quả. Baseline chỉ đổi cờ include_ct=False trong nghiên cứu, mặc định Web/CLI vẫn bật CT. Không thay policy để làm ca thử khớp.",
            "14 ca, file synthetic_cases.py và dữ liệu cũ được bảo toàn. Bổ sung nghiên cứu ở module riêng; artifacts mới nằm trong thư mục mới. Theo dõi checksum mã nguồn/config tại thời điểm đo, không so fingerprint RSA giữa lần vì khóa/serial thực được sinh ngẫu nhiên."], [["Lớp", "File / trách nhiệm"], ["Đầu vào", "certificate_fetcher, certificate_parser"], ["Kiểm tra", "hostname_validator, validity_checker, chain_validator, algorithm_policy, ct_validator"], ["Tổng hợp", "security_evaluator, certificate_security"], ["Trình bày", "certificate_service, web_presentation, web_findings"], ["Đầu ra", "main.py, app.py, report_export, demo_service"]]),
        Section("9. Chuỗi chứng thư và điểm neo tin cậy", [
            "Leaf là chứng thư đích; intermediate phát hành chứng thư khác; root tự ký không tự động đáng tin; trust anchor là điểm tin cậy được store độc lập cấp. Một intermediate có thể là anchor được tin cậy trực tiếp. Không gán nhãn root chỉ vì là phần tử cuối chuỗi TLS.",
            "Validator xác minh issuer/subject, chữ ký thật, CA BasicConstraints, keyCertSign nếu có, thời hạn, chu kỳ, path constraints bằng OpenSSL, và fingerprint anchor. Chuỗi thiếu root có thể được hoàn tất từ store; nếu không hoàn tất đường dẫn độc lập thì trust FAIL. Chứng thư thêm từ store được UI ghi nguồn, tách chuỗi máy chủ đã gửi.",
            "PARTIAL_CHAIN chỉ có ý nghĩa với anchor từ store độc lập; không biến CA không được tin cậy thành anchor. Một root được máy chủ gửi vẫn là dữ liệu untrusted cho tới khi store xác nhận. Không tải AIA hay kiểm tra OCSP/CRL hiện tại; các giới hạn này được ghi, không được diễn giải chain PASS như kiểm tra toàn bộ trạng thái thu hồi."]),
        Section("10. Sửa lỗi EKU/KU cho mục đích TLS", [
            "Trong rà soát, bốn negative tests cho thấy X509StoreContext ở purpose mặc định chấp nhận đường dẫn có EKU chỉ clientAuth hoặc KU leaf không cho sử dụng TLS. Kết nối SSL thật có kiểm tra purpose; validator offline chưa có, nên hai đường vào có thể khác nhau trên thuộc tính này.",
            "Đã bổ sung kiểm tra extension hiện diện trên chuỗi bằng cryptography public API. EKU phải cho serverAuth, anyExtendedKeyUsage hoặc SGC tương thích. KU leaf phải cho ít nhất digitalSignature/keyEncipherment/keyAgreement. Extension thiếu không bị tự coi là lỗi. TLS usage FAIL kéo trust FAIL và không xuất trust_anchor đã xác minh.",
            "Bốn test ban đầu FAILED và ba positive controls PASS; sau sửa 7/7 PASS. Nhóm chain/provenance có 33 tests PASS ở lần kiểm tra liên quan. Lý do dịch tiếng Việt, nguyên bản giữ trong chi tiết kỹ thuật. Không tuyên bố đã hiện thực mọi extension lịch sử/purpose của OpenSSL; không thay CT hoặc policy. Thực nghiệm được chạy lại sau sửa."]),
        Section("11. Tên miền, thời hạn và xử lý lỗi", [
            "Hostname được chuẩn hóa/kiểm tra trước network, SAN là nguồn tên miền bảo vệ. Form chỉ nhập DNS/IP, không URL hoặc path; server validate lại dù browser có kiểm tra. Thời hạn dùng datetime có timezone, phân biệt VALID, EXPIRED và NOT_YET_VALID; đồng hồ cố định dành cho lab, đồng hồ thật dành cho scan.",
            "Timeout/DNS/TLS/certificate parsing không thành kết luận chứng thư an toàn. UI trả thông báo tiếng Việt, không lộ traceback. Thiếu policy/chain/validity là lỗi thiết yếu và fail closed; CT dataset không đủ là WARNING với giới hạn cụ thể. Không chuyển WARNING thành PASS để đạt kết quả demo đẹp.",
            "HTTP thật đã kiểm tra input sai 400, body quá lớn 413, homepage/demo/scan hợp lệ 200. Edge headless thêm 13 checks đạt về loading, score, timeline, accordion, Demo/CSV và viewport 390px. Screenshots/summary được lưu; chưa kiểm tra clipboard OS hoặc điện thoại vật lý. Không dùng HTTP/viewport emulation để tuyên bố mọi thiết bị đều đạt."]),
        Section("12. Chính sách thuật toán và kiểm tra mật mã", [
            "Policy lấy từ config/algorithm_policy.json, không cố định số liệu hay đổi rule theo hostname. RSA tối thiểu 2048, EC tối thiểu 256; các thuật toán/hash cho phép hoặc chặn được khai báo ngoài engine. Danh sách blocked ưu tiên allowed; policy thiếu/sai không ngầm PASS.",
            "Chữ ký chứng thư và chính sách thuật toán là hai câu hỏi khác nhau: signature có thể verify bằng SHA-1 nhưng hash vẫn bị chặn. Ba ca RSA1024/SHA1/MD5 kiểm tra policy isolation; không coi kết quả riêng này là full chain/CT. SHA1/MD5 được tạo thật và verify fixture bằng backend trước đánh giá policy, không giả CryptoInfo.",
            "Đối chứng Ed25519 là public key của leaf; certificate vẫn được issuer RSA ký SHA256. Không nhập nhằng thuật toán khóa và thuật toán chữ ký. Thuật toán signature, OID, hash, key type/key size hiển thị riêng. Chưa tuyên bố policy cục bộ tương đương mọi yêu cầu WebPKI của browser."], [["Thuộc tính", "Quy tắc snapshot"], ["RSA", "minimum_key_size=2048"], ["EC", "minimum_key_size=256"], ["Hash allowed", "SHA256, SHA384, SHA512"], ["Hash blocked", "MD5, SHA1"], ["Public key", "RSA, EC, Ed25519, Ed448; DSA blocked"]]),
        Section("13. Certificate Transparency và diễn giải thời gian", [
            "Google temporal_interval áp dụng cho NotAfter chứng thư thuộc shard, không phải khoảng thời điểm phát hành SCT. Ca hồi quy cố ý đặt SCT trước start nhưng NotAfter trong khoảng; matcher phải không kết luận lỗi SCT vì phép so sánh sai trường thời gian. Thiếu trường optional không tự là SCT invalid.",
            "Tách Log ID không khớp, state cần xem xét/bị từ chối, thiếu dữ liệu, signature NOT_VERIFIED và inclusion NOT_VERIFIED. Retired cần xem SCT có trước thời điểm retirement; snapshot thiếu lịch sử không đủ suy luận chính sách Chrome hoàn chỉnh. Chỉ khớp Log ID không chứng minh chữ ký SCT hợp lệ.",
            "Giới hạn mật mã được gom cùng nguyên nhân ở phần vấn đề phát hiện nhưng giữ chi tiết mỗi SCT. CT matched usable với NotAfter phù hợp vẫn WARNING do chưa verify signature/inclusion. Điểm UI không phải xác suất an toàn; 90/100 không có nghĩa website thiếu 10% an toàn. Kết quả Web/CLI của google.com/github.com/cloudflare.com mới đều WARNING, không bị thay đổi để trình bày đẹp."]),
        Section("14. Thiết kế Baseline/Extended và tái lập", [
            f"Nghiên cứu hiện tại: {study['repeats']} lần × hai cấu hình × (14 ca + 5 loại đối chứng) = {study['observations']} quan sát. Config và nhãn đóng băng trước thực thi. Thứ tự profile và ca được random theo seed, nhưng RSA keys/serial không tất định. Profiles dùng chứng thư khác bytes có cùng thuộc tính, không phải paired input byte-identical.",
            "Baseline giữ hostname/validity/chain/algorithm, bỏ CT bằng cờ evaluator. Extended giữ các thành phần và thêm SCT parsing/CT metadata. Đây là ablation do nhóm thiết kế, không thay engine hoặc tạo quy tắc actual riêng. Setup tạo khóa/lab đo riêng; wall mỗi ca gồm sinh fixture và validators, controls còn gồm oracle.",
            "Không có train/test ML vì công cụ dùng quy tắc. Leakage có thể xảy ra nếu sửa policy/expected sau khi xem actual, nên giữ manifest/hash và ghi mismatch. Tập thử mất cân bằng, số kiểu control ít; không gọi nhiều lần sinh khóa là nhiều mẫu tình huống hoàn toàn mới. Live sites là quan sát công khai, không nhãn an toàn đã được audit."]),
        Section("15. Bảy ca đầu: phạm vi và bằng chứng", [
            "Các ca chứng thư được tạo X.509 thật, serialize/parse DER rồi chạy validators. Thời hạn trước/sau clock, SAN không khớp hoặc key/hash yếu là thuộc tính đầu vào đã định trước. Ba ca policy isolation dùng đường kiểm tra riêng có ghi rõ module; các ca khác dùng pipeline tổng hợp.",
            "Kết quả FAIL của chứng thư lỗi và kết quả kiểm thử thành công là hai khái niệm: test thành công khi actual đúng kỳ vọng và phát hiện điều kiện khảo sát. Signature placeholder của SCT không được dùng để tuyên bố CT mật mã hợp lệ. Khi backend không tạo được thuật toán legacy, ghi SKIPPED thay vì fake kết quả."], case_rows[:8]),
        Section("16. Bảy ca sau và hồi quy CT", [
            "Chữ ký sai được tạo bằng signer khác nhưng issuer text vẫn đúng, nên không thể phát hiện chỉ bằng so sánh chuỗi ký tự. Intermediate CA=False, leaf tự ký và CT log/state không phù hợp khảo sát module khác nhau. Hồi quy temporal_interval là điều kiện không được báo lỗi sai, không phải lỗi bảo mật thứ 14.",
            "Demo dùng ID allowlist trong manifest, gọi lại SyntheticLab. Batch giữ kết quả riêng từng ca và hiển thị mismatches; không dùng results.csv hay expected_status làm actual. ERROR không được tự tính là FAIL đúng kỳ vọng. Dữ liệu giả lập được gắn nhãn rõ, không gán cho website thật."], [case_rows[0], *case_rows[8:]]),
        Section("17. Đối chứng hợp lệ và nguồn nhãn", [
            "Năm đối chứng bổ sung có thuộc tính khai báo trước, root CA lab tin cậy độc lập với dữ liệu engine. Trước engine, một lần OpenSSL store verification và đọc trực tiếp dates/SAN/constraints/hash/key size xác nhận nhãn. Oracle không lấy actual/expected engine, nhưng chia sẻ backend OpenSSL; giới hạn này khác kiểm chứng bằng một triển khai mật mã độc lập.",
            "PEM leaf/anchor công khai lưu trong evidence, không có private keys. Baseline kỳ vọng PASS; Extended kỳ vọng WARNING do không có SCT, không phải chứng thư sai. Ba lần mỗi loại tạo 15 đối chứng trên mỗi profile nhưng chỉ 5 tình huống kiểm soát; không dùng 0/15 để khẳng định FPR Internet bằng 0.",
            "Controls được đặt ở module nghiên cứu riêng; danh sách phòng kiểm thử vẫn 14 ca. Không chèn chứng thư đối chứng vào Google CT dataset. Runtime controls gồm sinh khóa mới, nên được tổng hợp riêng với 14 ca sử dụng key material lab."], [["Mã", "Khóa công khai", "Digest issuer"]] + [[c["case_id"], f"{c['key_type']} {c['bits']}", c["digest"]] for c in controls]),
        Section("18. Định nghĩa và mẫu số metrics", [
            "Coverage điều kiện = số loại khớp kỳ vọng VÀ detected / 14 loại theo kế hoạch. Coverage lỗi/cần lưu ý loại hồi quy temporal_interval khỏi mẫu số, còn 13. Errors/skips không bao phủ được điều kiện, vẫn nằm trong mẫu số coverage. Agreement là khớp trạng thái, không đồng nghĩa detected và không phải accuracy Internet.",
            "Positive theo phép đo FN là ca hoàn thành có expected duy nhất FAIL; có 12 mỗi lượt. FN là actual khác FAIL trong tập này. NO_SCT và hồi quy SCT kỳ vọng WARNING không nằm trong mẫu số FN. FP là đối chứng hợp lệ hoàn thành bị gán FAIL; warnings báo riêng. Không tính lỗi thực thi như kết luận âm hợp lệ.",
            "FP/FN gộp là tổng số quan sát; rate gộp cần chia tổng mẫu số completed. Trung bình rate từng lượt chỉ bằng rate gộp khi mẫu số bằng nhau. Ba lượt cùng loại fixture có tương quan, nên tổng 36 ca dương không đại diện 36 loại lỗi độc lập. CPU/RAM/runtime đều có đơn vị và ranh giới đo được ghi cùng bảng."]),
        Section("19. Kiểm chứng số đo lịch sử", [
            f"Audit độc lập kiểm chứng {audit['observations']} quan sát cũ, {audit['repeats']} lần: verified={audit['verified']}, {len(audit['issues'])} sai lệch. Đối chiếu expected với config đóng băng, uniqueness ID/profile/repeat, boolean strict, từng lượt, aggregates và FP/FN. Không sửa raw CSV để khớp summary.",
            "Baseline 10/14 = 71,428571%; coverage trên 13 mục = 76,923077%. FN=6 do UNKNOWN_CT_LOG và RETIRED_CT_LOG bị bỏ qua mỗi lượt: 2 × 3. Extended 14/14, FN=0. FP=0/3 controls mỗi profile trong nghiên cứu cũ, ít hơn controls nghiên cứu mới. Hai artifact không được nhập nhằng mẫu số.",
            "Báo cáo cũ gọi 14 loại lỗi là không chính xác về thuật ngữ; audit sửa nghĩa trong tài liệu riêng, không thay đo lịch sử. Audit xác nhận phép tính từ recorded detected, không oracle độc lập cho mọi ca. raw_sha256 nằm trong metrics_audit/audit.json, có test bảo toàn bytes trước/sau audit."]),
        Section("20. Kết quả mới và ablation CT", [
            "Bảng dưới lấy trực tiếp từ summary sau sửa TLS usage. Coverage Extended cao hơn theo điều kiện được thiết kế cho module CT; không chứng minh tỷ lệ cải thiện trên phân bố lỗi ngoài thực tế. Hai FN/lượt Baseline là CT log unknown/retired. Các lỗi không CT giữ khả năng phát hiện ở cả hai profile.",
            "FP=0 trên controls được khảo sát; chưa có FP trong bộ này không có nghĩa không tồn tại false positive khác. NO_SCT và SCT regression tạo WARNING được diễn giải riêng. Thực nghiệm live+synthetic bổ sung ba lần, mỗi lần 19/19 khớp, nhưng website thực chỉ có nhãn quan sát normal case.",
            "Tất cả actual đến từ engine mới thực thi. Không dùng biểu đồ kết quả mẫu trong addon. Nhãn/thời điểm/chính sách/code hashes, raw CSV, JSON evidence và execution.log cho phép đối chiếu từng hàng với phép đo tổng hợp."], metric_rows, "coverage.png"),
        Section("21. Runtime và biến động", [
            "Runtime 14 ca báo mean theo lượt; biểu đồ trình bày cả ba lượt thay vì chỉ số trung bình. Khoảng t95 dùng df=2, không mặc nhiên hợp lệ trên n nhỏ. Run mới sinh khóa/fixtures mới, có scheduler và order effect. Không khẳng định độ chênh mean là khác biệt có ý nghĩa thống kê.",
            "Lượt mở rộng trước sửa TLS cho Extended thấp hơn; lượt sau sửa cho thứ tự khác. Điều này minh họa nhiễu timing và chi phí fixture, không bằng chứng thêm CT làm nhanh hơn. Runtime controls tách riêng vì sinh RSA3072/EC/Ed key trong từng ca và chạy oracle. Setup root/intermediate/shared keys cũng tách khỏi wall mỗi ca.",
            "Đối chiếu runtime từng dòng CSV nếu phát hiện outlier; không loại hoặc sửa số đo để đẹp. Đối với deployment, cần benchmark lặp nhiều hơn, paired serialized inputs, warm-up và đo riêng validation; nghiên cứu này chỉ chứng minh pipeline vận hành và ghi chi phí lab trên máy hiện tại."], runtime_rows, "runtime.png"),
        Section("22. CPU, RAM và giới hạn phép đo", [
            "CPU time đo bằng process_time tại ranh giới ca, là tổng thời gian xử lý của tiến trình; không phải phần trăm CPU máy. Các ca ngắn có thể bị lượng tử hóa bởi timer Windows. Tổng CPU có thể khác wall vì I/O, scheduling và độ phân giải. Không suy hiệu quả CPU của module CT từ tổng gồm sinh khóa của controls.",
            "RAM đo working set trước/sau qua Windows GetProcessMemoryInfo. process_peak_rss là high-water mark của tiến trình, không đỉnh của mỗi ca. RSS boundary max chỉ là giá trị lớn nhất tại điểm lấy mẫu; không đảm bảo bắt transient peak. Bộ nhớ allocator/cache tích lũy có thể làm lượt sau tăng RSS dù workload tương tự.",
            "Cấu hình CPU/core/RAM thật và dependency lock được lưu riêng. Không lấy dung lượng RAM máy làm RAM tiêu thụ của engine. Để đo peak theo module cần tiến trình riêng hoặc sampling đủ tần suất và đánh giá observer overhead; chưa triển khai trong nghiên cứu hiện tại."], resource_rows),
        Section("23. Độ ổn định, CI và khả năng suy rộng", [
            "Mean, SD mẫu n−1, min/max và CV mô tả ba repeat. Khoảng t95(mean) = mean ± 4,302653 × SD/√3 chỉ khi có đúng ba lượt, giả định independent repeat means và gần chuẩn. Chưa kiểm định được giả định với n=3; báo khoảng để minh bạch độ biến thiên, không dùng như kiểm định thắng/thua.",
            "Coverage các fixture giống nhau nên SD có thể 0, khoảng [100,100]. Đó là kết quả ổn định trên điều kiện chốt, không phải confidence interval cho population. Tương tự 0 FP trên controls lặp không đủ suy ra độ đặc hiệu ngoài lab. Không báo tỷ lệ khớp như độ chính xác hệ thống khi thiếu độc lập ground truth.",
            "Ablation CT là hợp lý để kiểm chứng thành phần tăng khả năng khảo sát log ID/state/no SCT. Chưa làm ablation làm yếu hostname/chain/policy vì không cần cho câu hỏi nghiên cứu và dễ bị hiểu nhầm như cấu hình an toàn. Nếu khảo sát thêm phải ghi rõ cấu hình nghiên cứu, không thay mặc định sản phẩm."]),
        Section("24. Kiểm thử, đầu ra và hướng dẫn tái lập", [
            f"Suite cuối lấy từ JUnit XML: {tests.get('tests', 'chưa ghi')} tests; failures {tests.get('failures', 'chưa ghi')}; errors {tests.get('errors', 'chưa ghi')}; skipped {tests.get('skipped', 'chưa ghi')}. Tests bao phủ parsing, hostname/time, chain/signature/anchor/TLS purpose, CT thiếu dữ liệu/time semantics, policy, Flask invalid/service exception, demo single/batch/errors/export, audit và research controls.",
            "Windows PowerShell: tạo/activate .venv; cài requirements-lock.txt cho môi trường đã đo, hoặc requirements-research.txt để giải dependencies lại. Dùng python/py trong venv. Chạy pytest với basetemp riêng và no:cacheprovider. Nghiên cứu mới phải chọn output directory trống để bảo toàn evidence; seed cố định order, không cố định keys.",
            "CLI không tham số phân tích Google dataset; CLI hostname kiểm tra TLS. --json/--html xuất cùng engine, không fetch lại hoặc đổi trạng thái. Web localhost:5000 giữ real scan và phòng kiểm thử; HTML report độc lập mở được trong browser. Edge headless xác minh spinner và viewport, chưa ghi clipboard OS hay kiểm tra điện thoại vật lý; người dùng cần rà môi trường bảo vệ thực."]),
        Section("25. Đối chiếu yêu cầu, giới hạn còn lại và kết luận", [
            "Bảng đối chiếu chi tiết nằm trong requirements_traceability.md, dẫn mỗi yêu cầu tới mã và evidence. Các thành phần kỹ thuật, lab, metrics và tài liệu có thể rà soát. Chưa tuyên bố hoàn thành 100%: cần xác nhận cơ sở Q1 giảng viên chấp nhận, quyền phân phối snapshot, acquisition/chữ ký nguồn nếu yêu cầu, định dạng báo cáo trường, thông tin tác giả và video bảo vệ.",
            "Giới hạn chính: không OCSP/CRL/AIA; không full SCT signature/inclusion; không audited Internet ground truth; fixtures chưa đại diện mọi certificate path/purpose; chỉ ba lượt và năm control types; oracle chia sẻ OpenSSL; memory boundary sampling. Các giới hạn không bị che bằng WARNING→PASS hoặc điểm số UI.",
            "Kết luận trong phạm vi đo: pipeline phát hiện các điều kiện được khảo sát, CT ablation giải thích khác biệt coverage và FN, exports giữ security result. Lỗi EKU/KU offline được tái hiện và sửa bằng regression tests. Hướng mở rộng hợp lý là oracle đa triển khai, bộ chứng thư public có nhãn, đo validation trên inputs byte-identical và xác minh CT mật mã thực, với điều kiện nguồn/giấy phép rõ."]),
        Section("26. Tài liệu tham khảo và chỉ mục bằng chứng", [
            "[1] Grindal, Mueller, Srivastava (2025). DOI https://doi.org/10.1093/cybsec/tyaf018. Metadata: https://api.crossref.org/works/10.1093/cybsec/tyaf018. Bản tác giả UTD liên kết trong research_sources/verification.md.",
            "[2] Oxford, Journal of Cybersecurity About: https://academic.oup.com/cybersecurity/pages/About. Thứ hạng theo năm/category, không đồng nhất JCR/SJR/CiteScore.",
            "[3] GoogleChrome CertificateTransparency log_lists.md: https://github.com/GoogleChrome/CertificateTransparency/blob/main/log_lists.md. Schema: https://www.gstatic.com/ct/log_list/v3/log_list_schema.json.",
            "[4] OpenSSL verification options: https://docs.openssl.org/3.5/man1/openssl-verification-options/. RFC5280: https://www.rfc-editor.org/rfc/rfc5280. RFC6962: https://www.rfc-editor.org/rfc/rfc6962.",
            "Bằng chứng nội bộ: metrics_audit/audit.json; ct_snapshot_validation.json; research_expanded/post_tls_20261010/{raw_results.csv,config.json,evidence.json,summary.json,execution.log}; final_experiments/run_1..3; system_smoke/20261010; final_validation/pytest.xml. Khóa public nằm trong evidence; private key không xuất. document_validation.json lưu số trang PDF, hashes artifact và kết quả JUnit dùng lúc dựng tài liệu."]),
    ]


def junit_counts(path: Path) -> dict:
    """Read actual test-run evidence; absence is explicit, never invented."""
    if not path.exists():
        return {}
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    return {key: sum(int(s.get(key, "0")) for s in suites) for key in ("tests", "failures", "errors", "skipped")}


def build(output: Path, study_path: Path, junit: Path) -> dict:
    """Build and validate a real 20–30 page document from measured inputs."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle, Image
    from matplotlib import font_manager
    from pypdf import PdfReader
    output.mkdir(parents=True, exist_ok=True)
    study, audit, dataset = read_json(study_path), read_json(ROOT / "reports/metrics_audit/audit.json"), read_json(ROOT / "reports/ct_snapshot_validation.json")
    counts = junit_counts(junit)
    content = sections(study, audit, dataset, counts)
    # Preserve research measurements; describe operational additions separately.
    for section in content:
        section.paragraphs = [p.replace("OCSP/CRL", "thu hồi (ngoài profile nghiên cứu)") if "Không nằm trong phạm vi:" in p else p for p in section.paragraphs]
        section.paragraphs = [p.replace("Không tải AIA hay kiểm tra OCSP/CRL hiện tại; các giới hạn này được ghi, không được diễn giải chain PASS như kiểm tra toàn bộ trạng thái thu hồi.",
            "Nâng cấp opt-in: OCSP/CRL xác minh chữ ký/issuer/freshness; AIA tải intermediate chưa tin cậy. Sau lỗi TLS thiếu issuer (20/21), luồng thu thập riêng phải xác minh lại chain/hostname/thời hạn/policy với trust store độc lập. Luồng TLS chính không đổi.")
            .replace("Giới hạn chính: không OCSP/CRL/AIA; không full SCT signature/inclusion;", "Giới hạn chính: OCSP/CRL/AIA chỉ bật opt-in; SCT/inclusion live chưa xác minh đầy đủ;") for p in section.paragraphs]
        if section.title.startswith("12."):
            section.paragraphs.append("Nâng cấp có SCT wire fields và primitive chữ ký v1, STH, Merkle path đã thử offline. Scan Web/CLI chưa có khóa CT được tin cậy độc lập hoặc precertificate TBS chính xác; vẫn NOT_VERIFIED. STH/proof chưa được truy vấn hoặc nối vào pipeline. Không đánh đồng fixture có chữ ký thật với live VERIFIED.")
        if section.title.startswith("13."):
            section.paragraphs.append("Web checkbox/CLI --advanced bật thu hồi/AIA; JSON/HTML dùng cùng analysis. REVOKED kéo FAIL, ERROR/UNKNOWN kéo WARNING. GOOD không chứng nhận website an toàn. Điểm giữ 5 thành phần lịch sử, không bao gồm thu hồi; điểm cao không phủ định FAIL do thu hồi.")
        if section.title.startswith("25."):
            section.paragraphs.append("Bằng chứng live riêng: CRL google/cloudflare GOOD; OCSP github ERROR vì tuổi quá 24 giờ. Offline có GOOD/REVOKED/UNKNOWN, signature/issuer/stale lỗi, SSRF và recovery không tin cậy. Thực nghiệm 90 + 114 giữ nguyên; extensions không bật trong Baseline/Extended. Evidence và giới hạn xem FINAL_ACCEPTANCE.md.")
    figures(study, output / "figures")
    pdfmetrics.registerFont(TTFont("DTFont", font_manager.findfont("DejaVu Sans")))
    body = ParagraphStyle("body", fontName="DTFont", fontSize=10, leading=15, spaceAfter=12)
    heading = ParagraphStyle("heading", parent=body, fontSize=16, leading=22, spaceAfter=20, textColor=colors.HexColor("#173e50"))
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=12, spaceAfter=3)
    story, html_sections = [], []
    for index, section in enumerate(content):
        if index:
            story.append(PageBreak())
        story.append(Paragraph(escape(section.title), heading))
        html = "<h2>" + escape(section.title) + "</h2>"
        for text in section.paragraphs:
            story.append(Paragraph(escape(text).replace("\n", "<br/>"), body))
            html += "<p>" + escape(text).replace("\n", "<br>") + "</p>"
        if section.table:
            cells = [[Paragraph(escape(str(cell)), small) for cell in row] for row in section.table]
            table = Table(cells, colWidths=[480 / len(cells[0])] * len(cells[0]), repeatRows=1, hAlign="LEFT")
            table.setStyle(TableStyle([("BACKGROUND", (0,0),(-1,0), colors.HexColor("#e0eef2")),("GRID",(0,0),(-1,-1),.35,colors.HexColor("#bdcbd0")),("VALIGN",(0,0),(-1,-1),"TOP"),("BOTTOMPADDING",(0,0),(-1,-1),7)]))
            story.append(table)
            html += "<div class='scroll'><table>" + "".join("<tr>" + "".join("<td>" + escape(str(cell)) + "</td>" for cell in row) + "</tr>" for row in section.table) + "</table></div>"
        if section.figure:
            story.extend([Spacer(1, 12), Image(str(output / "figures" / section.figure), width=470, height=210)])
            html += f"<img alt='{escape(section.title)}' src='figures/{section.figure}'>"
        html_sections.append("<section>" + html + "</section>")
    def footer(canvas, doc):
        canvas.setFont("DTFont", 8)
        canvas.drawString(50, 30, "DT007 — Bản dự thảo nghiên cứu, kết quả từ artifacts thực đo")
        canvas.drawRightString(A4[0] - 50, 30, str(doc.page))
    pdf = output / "scientific_report.pdf"
    SimpleDocTemplate(str(pdf), pagesize=A4, rightMargin=50, leftMargin=50, topMargin=48, bottomMargin=48, title="DT007 — Báo cáo khoa học").build(story, onFirstPage=footer, onLaterPages=footer)
    pages = len(PdfReader(pdf).pages)
    css = "body{font:16px system-ui;max-width:1000px;margin:auto;padding:24px;color:#163448}section{margin:24px 0;padding:24px;border:1px solid #ddd}p{line-height:1.65}table{border-collapse:collapse;width:100%;font-size:14px}td{border:1px solid #ccd;padding:8px;vertical-align:top}.scroll{overflow-x:auto}img{max-width:100%}h2{color:#126052}@media print{section{break-before:page;border:0}}"
    prefix = f"<!doctype html><html lang='vi'><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>DT007 — Báo cáo khoa học</title><style>{css}</style>"
    (output / "scientific_report.html").write_text(prefix + "".join(html_sections) + "</html>", encoding="utf-8")
    slides = [html_sections[i] for i in (0,1,5,7,8,9,12,13,16,17,19,20,21,24)]
    navigation = "<nav><button onclick='move(-1)'>← Trước</button> <span id='count'></span> <button onclick='move(1)'>Tiếp →</button></nav><script>const slides=[...document.querySelectorAll('section')];let current=0;function move(n){current=Math.max(0,Math.min(slides.length-1,current+n));slides.forEach((s,i)=>s.hidden=i!==current);document.getElementById('count').textContent=(current+1)+' / '+slides.length;}document.addEventListener('keydown',e=>{if(e.key==='ArrowRight')move(1);if(e.key==='ArrowLeft')move(-1)});move(0);</script>"
    (output / "defense_slides.html").write_text(prefix + "".join(slides) + navigation + "</html>", encoding="utf-8")
    validation = {"pdf_pages": pages, "within_20_30_pages": 20 <= pages <= 30, "sections": len(content), "slides": len(slides), "pytest": counts,
                  "study_source": str(study_path), "study_sha256": hashlib.sha256(study_path.read_bytes()).hexdigest(),
                  "artifacts_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (pdf, output / "scientific_report.html", output / "defense_slides.html")},
                  "limits": "Draft technical report; student details, institutional formatting and oral/video defense remain to complete. Browser interaction not verified by PDF page count."}
    (output / "document_validation.json").write_text(json.dumps(validation, ensure_ascii=False, indent=2), encoding="utf-8")
    if not validation["within_20_30_pages"]:
        raise ValueError(f"Báo cáo có {pages} trang, cần điều chỉnh bố cục 20–30 trang")
    return validation


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "reports/scientific")
    parser.add_argument("--study", type=Path, default=ROOT / "reports/research_expanded/post_tls_20261010/summary.json")
    parser.add_argument("--junit", type=Path, default=ROOT / "reports/final_validation/final_browser_20261010/pytest.xml")
    args = parser.parse_args()
    result = build(args.output_dir, args.study, args.junit)
    print("PDF pages:", result["pdf_pages"], "slides:", result["slides"], "tests:", result["pytest"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
