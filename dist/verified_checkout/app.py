"""DT007 Flask local UI; chạy riêng với py app.py, CLI giữ nguyên."""

from pathlib import Path
from threading import Timer
from typing import Any, Mapping
import webbrowser

from flask import Flask, render_template, request
from flask.typing import ResponseReturnValue

from src import certificate_service
from src import demo_service
from src.web_findings import explain_findings
from experiments.synthetic_cases import UnsupportedSyntheticCase
from src.web_presentation import presentation_score, translate_label, translate_reason, translate_status

PROJECT_ROOT = Path(__file__).resolve().parent


def create_app(config: Mapping[str, Any] | None = None) -> Flask:
    """Tạo Flask app độc lập cho demo hoặc test client, không có database."""
    application = Flask(__name__, template_folder=str(PROJECT_ROOT / "templates"),
                        static_folder=str(PROJECT_ROOT / "static"))
    application.config.update(
        DEBUG=False, MAX_CONTENT_LENGTH=4096,
        SCAN_TIMEOUT=10.0, CT_DATASET_PATH=certificate_service.DEFAULT_DATASET,
        ALGORITHM_POLICY_PATH=certificate_service.DEFAULT_POLICY,
    )
    if config is not None:
        application.config.update(config)
    application.jinja_env.filters.update(
        translate_status=translate_status, translate_label=translate_label,
        translate_reason=translate_reason, presentation_score=presentation_score,
    )

    @application.get("/")
    def index() -> ResponseReturnValue:
        """Trang nhập tên miền."""
        return render_template("index.html", hostname="", error=None)

    @application.post("/scan")
    def scan() -> ResponseReturnValue:
        """Validate form ở server, gọi service và giữ nguyên kết luận của engine."""
        raw_hostname = request.form.get("hostname", "")
        try:
            hostname = certificate_service.validate_web_hostname(raw_hostname)
        except ValueError as exc:
            return render_template("index.html", hostname=raw_hostname, error=str(exc)), 400
        try:
            result = certificate_service.scan_certificate(
                hostname, timeout=application.config["SCAN_TIMEOUT"],
                dataset_path=Path(application.config["CT_DATASET_PATH"]),
                policy_path=Path(application.config["ALGORITHM_POLICY_PATH"]),
                **({"advanced": True} if request.form.get("advanced") == "on" else {}),
            )
        except Exception:
            # Chi tiết exception chỉ vào log của server, không vào HTML response.
            application.logger.exception("Certificate service failed for %s", hostname)
            return render_template(
                "index.html", hostname=raw_hostname,
                error="Không thể kiểm tra chứng thư của tên miền này. Dịch vụ kiểm tra gặp lỗi nội bộ; vui lòng thử lại.",
            ), 502
        return render_template("result.html", result=result, findings=explain_findings(result)), 502 if result.get("scan_error") else 200

    @application.route("/demo", methods=["GET", "POST"])
    def demo() -> ResponseReturnValue:
        """Trang trình diễn chỉ chạy case local trong manifest."""
        try:
            cases = demo_service.demo_cases()
            outcome = None
            batch = None
            if request.method == "POST":
                if request.form.get("action") == "all":
                    batch = demo_service.run_all_demos(Path(application.config["ALGORITHM_POLICY_PATH"]))
                    return render_template("demo.html", cases=cases, outcome=None, batch=batch,
                                           csv_report=demo_service.batch_csv(batch), error=None)
                selected = request.form.get("case_id", "")
                if selected not in {case["id"] for case in cases}:
                    return render_template("demo.html", cases=cases, outcome=None, error="Trường hợp demo không hợp lệ."), 400
                outcome = demo_service.run_demo(selected, Path(application.config["ALGORITHM_POLICY_PATH"]))
            return render_template("demo.html", cases=cases, outcome=outcome, error=None)
        except UnsupportedSyntheticCase:
            return render_template("demo.html", cases=[], outcome=None, error="Backend hiện tại không tạo được chứng thư của case này. Case chưa được chạy; không có kết luận bảo mật."), 503
        except Exception:
            application.logger.exception("Demo execution failed")
            return render_template("demo.html", cases=[], outcome=None, error="Không thể chạy demo lúc này. Kiểm tra manifest và chính sách thuật toán; không có kết luận bảo mật."), 503

    @application.errorhandler(413)
    def request_too_large(error: Exception) -> ResponseReturnValue:
        """Body quá lớn có thông báo tiếng Việt, không lộ thông tin nội bộ."""
        return render_template("index.html", hostname="", error="Dữ liệu nhập quá dài. Vui lòng chỉ nhập tên miền dạng google.com."), 413

    @application.errorhandler(500)
    def internal_error(error: Exception) -> ResponseReturnValue:
        """Trang lỗi an toàn khi xảy ra lỗi ngoài service boundary."""
        return render_template("index.html", hostname="", error="Không thể kiểm tra chứng thư lúc này. Vui lòng thử lại."), 500

    return application


app = create_app()

if __name__ == "__main__":
    browser_timer = Timer(1.0, webbrowser.open, args=("http://127.0.0.1:5000",))
    browser_timer.daemon = True
    browser_timer.start()
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
