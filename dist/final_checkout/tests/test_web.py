"""Flask test client và service adapter, không cần Internet."""

from collections.abc import Callable
from copy import deepcopy
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

from cryptography.hazmat.primitives.serialization import Encoding
from flask import Flask
from flask.testing import FlaskClient
import pytest

from app import create_app
from src import certificate_service
from src.certificate_fetcher import TLSCertificates
from src.certificate_security import CertificateAnalysis, analyze_certificate
from src.ct_log_analyzer import analyze_dataset
from src.ct_validator import validate_ct
from src.sct_parser import parse_scts
from src.web_presentation import presentation_score, translate_reason, translate_status


@pytest.fixture
def web_app() -> Flask:
    """App riêng cho mỗi test, debugger tắt."""
    return create_app({"TESTING": True})


@pytest.fixture
def client(web_app: Flask) -> FlaskClient:
    """Flask client không mở socket."""
    return web_app.test_client()


@pytest.fixture
def analysis(chain_factory: Callable, reference_time: datetime) -> CertificateAnalysis:
    """Gọi engine thật với TLS fixture local, không gọi network."""
    chain = chain_factory()
    fetched = TLSCertificates(chain[0].public_bytes(Encoding.DER),
                              tuple(cert.public_bytes(Encoding.DER) for cert in chain),
                              (chain[-1].public_bytes(Encoding.DER),))
    return analyze_certificate("example.com", 443, 10, certificate_service.DEFAULT_DATASET,
                               certificate_service.DEFAULT_POLICY, reference_time, lambda *args: fetched)


@pytest.fixture
def view_model(analysis: CertificateAnalysis) -> dict:
    """Dữ liệu render có cấu trúc giống response của service."""
    return certificate_service.build_view_model("example.com", analysis, 0.125)


def test_home(client: FlaskClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    text = response.get_data(as_text=True)
    assert "TRÌNH XÁC MINH AN TOÀN" in text and "DT007" in text
    assert 'action="/scan"' in text and 'name="hostname"' in text
    assert "KIỂM TRA CHỨNG THƯ" in text


@pytest.mark.parametrize("hostname", [
    "", " ", "https://google.com", "http://google.com", "HTTPS://google.com",
    "bad host", "google.com ", "google.com:443", "a..example.com", "-bad.example",
    "bad_.example", "*.example.com", "google.com/path", "a" * 254,
])
def test_invalid_input(client: FlaskClient, monkeypatch: pytest.MonkeyPatch, hostname: str) -> None:
    service = MagicMock()
    monkeypatch.setattr(certificate_service, "scan_certificate", service)
    response = client.post("/scan", data={"hostname": hostname})
    assert response.status_code == 400
    assert "Tên miền không hợp lệ" in response.get_data(as_text=True)
    service.assert_not_called()


def test_missing_input(client: FlaskClient) -> None:
    assert client.post("/scan", data={}).status_code == 400


@pytest.mark.parametrize("status", ["PASS", "WARNING", "FAIL"])
def test_mock_security_status(client: FlaskClient, monkeypatch: pytest.MonkeyPatch, view_model: dict, status: str) -> None:
    model = deepcopy(view_model)
    model["security"]["status"] = status
    monkeypatch.setattr(certificate_service, "scan_certificate", lambda *args, **kwargs: model)
    response = client.post("/scan", data={"hostname": "example.com"})
    assert response.status_code == 200
    assert f'class="badge status-{status.lower()}" data-status="{status}">{translate_status(status)}</span>' in response.get_data(as_text=True)
    assert "KẾT QUẢ CUỐI CÙNG" in response.get_data(as_text=True)
    assert model["security"]["status"] == status


def test_service_exception_safe(client: FlaskClient, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> dict:
        raise RuntimeError("private-internal-details <script>alert(1)</script>")
    monkeypatch.setattr(certificate_service, "scan_certificate", fail)
    response = client.post("/scan", data={"hostname": "example.com"})
    assert response.status_code == 502
    text = response.get_data(as_text=True)
    assert "Không thể kiểm tra chứng thư" in text
    assert "private-internal-details" not in text and "Traceback" not in text
    assert "<script>alert(1)</script>" not in text


def test_network_error_result_page(client: FlaskClient, monkeypatch: pytest.MonkeyPatch) -> None:
    analysis = analyze_certificate("example.com", 443, 10, certificate_service.DEFAULT_DATASET,
                                   certificate_service.DEFAULT_POLICY,
                                   fetcher=MagicMock(side_effect=TimeoutError("TLS timeout")))
    model = certificate_service.build_view_model("example.com", analysis, 0.15)
    assert model["security"]["status"] == "FAIL"
    monkeypatch.setattr(certificate_service, "scan_certificate", lambda *args, **kwargs: model)
    response = client.post("/scan", data={"hostname": "example.com"})
    text = response.get_data(as_text=True)
    assert response.status_code == 502
    assert "Không thể kiểm tra chứng thư của tên miền này." in text
    assert "TLS timeout" in text and "KẾT QUẢ CUỐI CÙNG" in text and "Traceback" not in text
    assert "Kết nối vượt quá thời gian chờ" in text and "Chi tiết kỹ thuật" in text


def test_all_sections(client: FlaskClient, monkeypatch: pytest.MonkeyPatch, view_model: dict) -> None:
    monkeypatch.setattr(certificate_service, "scan_certificate", lambda *args, **kwargs: view_model)
    text = client.post("/scan", data={"hostname": "example.com"}).get_data(as_text=True)
    for section in ("certificate", "hostname", "validity", "cryptography", "chain", "policy", "ct", "security-summary"):
        assert f'id="{section}"' in text
    for field in ("Chủ thể", "Đơn vị cấp", "Số sê-ri", "Có hiệu lực từ", "Có hiệu lực đến", "Số lượng SAN", "Thời điểm kiểm tra",
                  "Thuật toán khóa công khai", "OID chữ ký", "Độ dài đường dẫn xác minh", "Xác minh chữ ký", "Ràng buộc CA",
                  "Đường dẫn tới điểm neo tin cậy", "Trạng thái chính sách", "Số lượng SCT", "SCT khớp dữ liệu", "Thời gian xử lý", "0.1250 giây"):
        assert field in text


def test_sct_warning_is_preserved(client: FlaskClient, monkeypatch: pytest.MonkeyPatch, view_model: dict) -> None:
    monkeypatch.setattr(certificate_service, "scan_certificate", lambda *args, **kwargs: view_model)
    response = client.post("/scan", data={"hostname": "example.com"})
    text = response.get_data(as_text=True)
    assert "NOT_VERIFIED" in text and "Chữ ký SCT chưa được xác minh" in text
    assert 'status-neutral" data-status="NOT_VERIFIED">CHƯA XÁC MINH' in text
    assert view_model["security"]["status"] == "WARNING"


def test_sct_metadata_rendered(client: FlaskClient, monkeypatch: pytest.MonkeyPatch,
                              analysis: CertificateAnalysis, sct_certificate_factory: Callable, reference_time: datetime) -> None:
    parsed = parse_scts(sct_certificate_factory())
    dataset = analyze_dataset({"operators": [{"name": "Fixture Operator", "logs": [{
        "log_id": parsed.scts[0].log_id, "description": "Fixture CT Log", "mmd": 86400,
        "url": "https://ct.example.test/", "state": {"usable": {}},
        "temporal_interval": {"start_inclusive": "2026-01-01T00:00:00Z", "end_exclusive": "2027-01-01T00:00:00Z"},
    }]}]})
    ct = validate_ct(parsed, dataset, reference_time, reference_time)
    model = certificate_service.build_view_model("example.com", replace(analysis, ct=ct), 0.5)
    monkeypatch.setattr(certificate_service, "scan_certificate", lambda *args, **kwargs: model)
    text = client.post("/scan", data={"hostname": "example.com"}).get_data(as_text=True)
    assert "SCT #1" in text and "Fixture Operator" in text and "Fixture CT Log" in text
    assert parsed.scts[0].log_id in text
    for field in ("Bắt đầu khoảng thời gian", "Kết thúc khoảng thời gian", "Đối chiếu SCT với temporal_interval", "Khoảng hết hạn chứng thư", "Đối chiếu Log ID", "Chính sách trạng thái"):
        assert field in text


def test_intermediates_keep_order(client: FlaskClient, monkeypatch: pytest.MonkeyPatch, view_model: dict) -> None:
    model = deepcopy(view_model)
    model["chain"]["certificates"].insert(2, {"role": "Intermediate #2", "subject": "CN=Extra Intermediate",
                                            "issuer": "CN=DT007 Test Root", "not_before": "start", "not_after": "end"})
    model["chain"]["length"] = 4
    monkeypatch.setattr(certificate_service, "scan_certificate", lambda *args, **kwargs: model)
    text = client.post("/scan", data={"hostname": "example.com"}).get_data(as_text=True)
    assert text.index("Chứng thư trung gian #1") < text.index("Chứng thư trung gian #2") < text.index("Chứng thư gốc / Điểm neo tin cậy")


@pytest.mark.parametrize("status, expected", [
    ("PASS", "ĐẠT"), ("WARNING", "CẢNH BÁO"), ("FAIL", "KHÔNG ĐẠT"),
    ("VALID", "CÒN HIỆU LỰC"), ("EXPIRED", "HẾT HẠN"),
    ("NOT_YET_VALID", "CHƯA CÓ HIỆU LỰC"), ("NOT_VERIFIED", "CHƯA XÁC MINH"),
    ("NO_SCT", "KHÔNG CÓ SCT"), (None, "CHƯA XÁC ĐỊNH"), ("NEW_STATE", "CHƯA XÁC ĐỊNH"),
])
def test_translate_status(status: str | None, expected: str) -> None:
    assert translate_status(status) == expected


def test_score_does_not_change_verdict(client: FlaskClient, monkeypatch: pytest.MonkeyPatch, view_model: dict) -> None:
    model = deepcopy(view_model)
    model["security"]["checks"] = dict(zip(
        ["Validity", "Hostname", "Certificate Chain", "Algorithm Policy", "Certificate Transparency"],
        ["PASS", "PASS", "PASS", "PASS", "WARNING"]))
    model["security"]["status"] = "FAIL"
    original = deepcopy(model)
    monkeypatch.setattr(certificate_service, "scan_certificate", lambda *args, **kwargs: model)
    text = client.post("/scan", data={"hostname": "example.com"}).get_data(as_text=True)
    assert 'id="security-score">90</strong>' in text
    assert 'data-status="FAIL">KHÔNG ĐẠT' in text
    assert model == original
    assert "không phải chứng nhận an toàn tiêu chuẩn" in text


def test_unknown_score_is_conservative() -> None:
    assert presentation_score({"Validity": "UNKNOWN", "Extra": "PASS"}) == 0


def test_unknown_reason_is_technical(client: FlaskClient, monkeypatch: pytest.MonkeyPatch, view_model: dict) -> None:
    model = deepcopy(view_model)
    model["security"]["reasons"] = ["Unmapped diagnostic <script>unsafe</script>"]
    monkeypatch.setattr(certificate_service, "scan_certificate", lambda *args, **kwargs: model)
    text = client.post("/scan", data={"hostname": "example.com"}).get_data(as_text=True)
    assert "Thông tin kiểm tra cần được đối chiếu thêm" in text
    assert 'class="technical-details"' in text
    assert "&lt;script&gt;unsafe" in text and "<script>unsafe" not in text


def test_ct_reason_translation() -> None:
    translated = translate_reason("SCT signatures/inclusion proofs are NOT_VERIFIED; CT result covers dataset matching only")
    assert "Chữ ký SCT" in translated["text"]
    assert translated["technical"].startswith("SCT signatures/inclusion proofs")


@pytest.mark.parametrize("reason, expected", [
    ("Allowed public key algorithm: EC", "Thuật toán khóa công khai được phép: EC"),
    ("Blocked signature hash: sha1", "Thuật toán băm chữ ký bị chặn: SHA1"),
    ("Key size meets policy minimum (256 bits)", "Độ dài khóa đạt mức tối thiểu của chính sách (256 bit)."),
    ("RSA key size below policy minimum (2048 bits)", "Độ dài khóa RSA thấp hơn mức tối thiểu của chính sách (2048 bit)."),
])
def test_policy_reason_translation(reason: str, expected: str) -> None:
    assert translate_reason(reason) == {"text": expected, "technical": reason}


def test_demo_elements(client: FlaskClient, monkeypatch: pytest.MonkeyPatch, view_model: dict) -> None:
    home = client.get("/").get_data(as_text=True)
    assert 'id="scan-spinner"' in home
    monkeypatch.setattr(certificate_service, "scan_certificate", lambda *args, **kwargs: view_model)
    text = client.post("/scan", data={"hostname": "example.com"}).get_data(as_text=True)
    assert 'class="chain-list chain-timeline"' in text
    assert "Xem tất cả SAN" in text and 'class="table-scroll"' in text
    assert text.index('id="security-summary"') > text.index('id="ct"')


def test_certificate_fields_are_escaped(client: FlaskClient, monkeypatch: pytest.MonkeyPatch, view_model: dict) -> None:
    model = deepcopy(view_model)
    model["certificate"]["subject"] = "<script>alert('unsafe')</script>"
    monkeypatch.setattr(certificate_service, "scan_certificate", lambda *args, **kwargs: model)
    text = client.post("/scan", data={"hostname": "example.com"}).get_data(as_text=True)
    assert "<script>alert(" not in text and "&lt;script&gt;" in text


def test_invalid_input_is_escaped(client: FlaskClient) -> None:
    response = client.post("/scan", data={"hostname": '<script>alert("bad")</script>'})
    text = response.get_data(as_text=True)
    assert response.status_code == 400
    assert '<script>alert("bad")</script>' not in text and "&lt;script&gt;" in text


def test_form_passes_normalized_domain(client: FlaskClient, monkeypatch: pytest.MonkeyPatch, view_model: dict) -> None:
    service = MagicMock(return_value=view_model)
    monkeypatch.setattr(certificate_service, "scan_certificate", service)
    assert client.post("/scan", data={"hostname": "WWW.GOOGLE.COM"}).status_code == 200
    assert service.call_args.args == ("www.google.com",)
    assert service.call_args.kwargs["timeout"] == 10.0


def test_service_calls_existing_engine(monkeypatch: pytest.MonkeyPatch, analysis: CertificateAnalysis,
                                       tmp_path: Path) -> None:
    engine = MagicMock(return_value=analysis)
    monkeypatch.setattr(certificate_service, "analyze_certificate", engine)
    model = certificate_service.scan_certificate("EXAMPLE.COM", timeout=3,
                                                dataset_path=tmp_path / "logs.json", policy_path=tmp_path / "policy.json")
    engine.assert_called_once_with("example.com", 443, 3, tmp_path / "logs.json", tmp_path / "policy.json")
    assert model["runtime_seconds"] >= 0
    assert model["security"]["status"] == analysis.security.status
    assert model["security"]["reasons"] == list(analysis.security.reasons)


def test_default_debug_off(web_app: Flask) -> None:
    assert web_app.debug is False


def test_payload_too_large(client: FlaskClient) -> None:
    response = client.post("/scan", data={"hostname": "a" * 5000})
    assert response.status_code == 413 and "Dữ liệu nhập quá dài" in response.get_data(as_text=True)


def test_scan_get_not_allowed(client: FlaskClient) -> None:
    assert client.get("/scan").status_code == 405


@pytest.mark.parametrize("asset", ["css/style.css", "js/main.js"])
def test_static_assets(client: FlaskClient, asset: str) -> None:
    assert client.get(f"/static/{asset}").status_code == 200
