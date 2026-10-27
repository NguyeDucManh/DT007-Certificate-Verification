"""Chứng minh lab chạy mới và metadata lấy từ certificate thực tế."""
from app import create_app
from src.demo_service import demo_cases, run_demo
from src.certificate_service import DEFAULT_POLICY
import pytest


@pytest.mark.parametrize('case', demo_cases(), ids=lambda c:c['id'])
def test_evidence_matches_scope(case: dict) -> None:
    result = run_demo(case['id'], DEFAULT_POLICY)
    evidence = result['evidence']
    assert evidence['mock_used'] is False
    assert len(evidence['certificate']['sha256']) == 64
    assert int(evidence['certificate']['serial']) > 0
    assert result['test_success'] is True
    if case['type'] in ('RSA_1024','SHA1_SIGNATURE','MD5_SIGNATURE'):
        assert evidence['structured_ct'] is None
        assert evidence['modules'] == ['crypto_info.get_crypto_info','algorithm_policy.evaluate_algorithm']
    else:
        assert 'security_evaluator.evaluate_security' in evidence['modules']
        assert evidence['structured_ct']['signature_verified'] is False


def test_repeated_execution_generates_new_certificate() -> None:
    first = run_demo('case_104', DEFAULT_POLICY)
    second = run_demo('case_104', DEFAULT_POLICY)
    assert first['evidence']['certificate']['sha256'] != second['evidence']['certificate']['sha256']
    assert first['evidence']['certificate']['key_size'] == 1024


def test_flask_lab_displays_input_and_modules() -> None:
    response = create_app({'TESTING':True}).test_client().post('/demo',data={'case_id':'case_112'})
    assert response.status_code == 200
    text = response.get_data(as_text=True)
    for label in ('Bằng chứng thực thi','Nguồn dữ liệu thử nghiệm','Loại dữ liệu đầu vào','Module được thực thi','Vân tay SHA256','KIỂM THỬ THÀNH CÔNG','ĐÚNG'):
        assert label in text
