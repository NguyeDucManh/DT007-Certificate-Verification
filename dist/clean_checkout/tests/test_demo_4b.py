"""Đối chiếu demo lấy expectation từ manifest, không sửa actual của lab."""
from unittest.mock import MagicMock
import pytest
from app import create_app
from src import demo_service
from src.certificate_service import DEFAULT_POLICY
from experiments.synthetic_cases import SyntheticOutcome


def test_demo_title_and_choices() -> None:
    response = create_app({'TESTING': True}).test_client().get('/demo')
    text = response.get_data(as_text=True)
    assert 'PHÒNG KIỂM THỬ CHỨNG THƯ SỐ' in text
    assert 'DỮ LIỆU GIẢ LẬP – PHỤC VỤ KIỂM THỬ' in text
    assert 'CHẠY KIỂM THỬ' in text
    assert text.count('<option ') == len(demo_service.demo_cases())


def test_mismatch_is_reported_not_overwritten(monkeypatch: pytest.MonkeyPatch) -> None:
    lab = MagicMock()
    lab.run.return_value = SyntheticOutcome('PASS', ('Actual diagnostic',), False, 'Algorithm Policy (isolated)', 'fixture')
    monkeypatch.setattr(demo_service, 'SyntheticLab', MagicMock(return_value=lab))
    result = demo_service.run_demo('case_104', DEFAULT_POLICY)
    assert result['expected'] == ('FAIL',)
    assert result['status'] == 'PASS' and result['matches_expected'] is False
    response = create_app({'TESTING': True}).test_client().post('/demo', data={'case_id':'case_104'})
    text = response.get_data(as_text=True)
    assert 'KHÔNG KHỚP KỲ VỌNG' in text and 'Mô tả tình huống' in text
    assert 'KIỂM THỬ THẤT BẠI' in text and 'SAI' in text


@pytest.mark.parametrize('case_id', ['../../file.json', 'case_001', 'cmd /c whoami', '', '<script>'])
def test_only_defined_synthetic_ids(monkeypatch: pytest.MonkeyPatch, case_id: str) -> None:
    run = MagicMock()
    monkeypatch.setattr(demo_service, 'run_demo', run)
    response = create_app({'TESTING': True}).test_client().post('/demo', data={'case_id':case_id})
    assert response.status_code == 400
    run.assert_not_called()


def test_expected_warning_comes_from_manifest() -> None:
    result = demo_service.run_demo('case_114', DEFAULT_POLICY)
    assert result['status'] == 'WARNING' and result['expected'] == ('WARNING',)
    assert result['matches_expected'] is True
