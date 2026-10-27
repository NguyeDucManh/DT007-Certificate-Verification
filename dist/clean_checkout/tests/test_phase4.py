"""Hồi quy lý do, giới hạn CT và demo chạy validators thật offline."""
import csv
import json
from copy import deepcopy
from pathlib import Path
from unittest.mock import MagicMock
import pytest
from app import create_app
from src.demo_service import demo_cases, run_demo
from src.certificate_service import DEFAULT_POLICY
from src.web_findings import explain_findings
from src.web_presentation import translate_reason
from experiments.synthetic_cases import UnsupportedSyntheticCase


def test_csv_reasons_are_specific() -> None:
    with Path('experiments/results.csv').open(encoding='utf-8', newline='') as stream:
        reasons = [reason for row in csv.DictReader(stream) for reason in json.loads(row['reasons'])]
    for reason in reasons:
        translated = translate_reason(reason)
        assert translated['technical'] == reason
        assert not translated['text'].startswith('Thông tin kiểm tra cần'), reason


@pytest.mark.parametrize('reason, fragment', [
    ('Certificate validity: EXPIRED; Certificate đã hết hạn.', 'đã hết hạn'),
    ('CT log is retired; SCT is not proven to predate retirement', 'ngừng hoạt động'),
    ('SCT #1: SCT timestamp interval: FAIL (diagnostic; Google interval applies to certificate NotAfter)', 'chẩn đoán'),
    ('Missing issuer/trusted root: terminal certificate is not an independent trust anchor', 'điểm tin cậy độc lập'),
    ('Invalid signature/issuer at certificate #1', 'không hợp lệ'),
])
def test_specific_translations(reason: str, fragment: str) -> None:
    assert fragment in translate_reason(reason)['text']


def test_ct_limit_is_not_certificate_failure() -> None:
    result = {'ct': {'status':'WARNING', 'reasons':['SCT signatures/inclusion proofs are NOT_VERIFIED; CT result covers dataset matching only']}, 'security': {'status':'WARNING'}}
    original = deepcopy(result)
    findings = explain_findings(result)
    assert findings[0]['category'] == 'Giới hạn xác minh của công cụ'
    assert 'không kết luận website mất an toàn' in findings[0]['impact']
    assert result == original


def test_same_ct_cause_grouped_without_losing_sct_details() -> None:
    reasons = ['SCT #1: Certificate expiry interval: UNKNOWN', 'SCT #2: Certificate expiry interval: UNKNOWN']
    result = {'ct': {'status':'WARNING', 'reasons':reasons}}
    findings = explain_findings(result)
    assert len(findings) == 1
    assert 'SCT #1' in findings[0]['cause'] and 'SCT #2' in findings[0]['cause']
    assert result['ct']['reasons'] == reasons
    assert 'dữ liệu chưa đủ' in findings[0]['category']


@pytest.mark.parametrize('case', demo_cases(), ids=lambda case: case['id'])
def test_all_demo_cases_run_real_lab(case: dict) -> None:
    result = run_demo(case['id'], DEFAULT_POLICY)
    assert result['detected'] is True
    assert result['status'] == ('WARNING' if case['type'] in ('NO_SCT','SCT_TIMESTAMP_OUTSIDE_INTERVAL') else 'FAIL')
    assert result['reasons'] and result['runtime'] > 0


def test_demo_routes_and_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    app = create_app({'TESTING':True})
    client = app.test_client()
    assert client.get('/demo').status_code == 200
    assert 'DỮ LIỆU GIẢ LẬP' in client.get('/demo').get_data(as_text=True)
    assert client.post('/demo', data={'case_id':'invalid'}).status_code == 400
    response = client.post('/demo', data={'case_id':'case_104'})
    assert response.status_code == 200
    assert 'KHÔNG ĐẠT' in response.get_data(as_text=True)
    from src import demo_service
    monkeypatch.setattr(demo_service, 'run_demo', MagicMock(side_effect=RuntimeError('private-stack')))
    response = client.post('/demo', data={'case_id':'case_104'})
    assert response.status_code == 503
    assert 'private-stack' not in response.get_data(as_text=True)
    monkeypatch.setattr(demo_service, 'run_demo', MagicMock(side_effect=UnsupportedSyntheticCase('private-backend')))
    response = client.post('/demo', data={'case_id':'case_104'})
    assert response.status_code == 503
    assert 'không có kết luận bảo mật' in response.get_data(as_text=True)
