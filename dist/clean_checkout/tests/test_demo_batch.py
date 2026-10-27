"""Batch lab thật, lỗi từng ca, đối chiếu và CSV đúng snapshot."""
import csv
import io
import json
import re
from unittest.mock import MagicMock
import pytest
from app import create_app
from src import demo_service
from src.certificate_service import DEFAULT_POLICY
from experiments.synthetic_cases import UnsupportedSyntheticCase


@pytest.fixture(scope='module')
def batch() -> dict:
    return demo_service.run_all_demos(DEFAULT_POLICY)


def test_real_batch(batch: dict) -> None:
    assert batch['total'] == len(demo_service.demo_cases()) == 14
    assert batch['success'] == 14 and batch['failed'] == 0
    assert batch['matched'] == 14 and batch['match_rate'] == 100
    assert batch['runtime'] > 0
    assert all(row['evidence']['mock_used'] is False for row in batch['rows'])


@pytest.mark.parametrize('error', [RuntimeError('private'),UnsupportedSyntheticCase('private')])
def test_error_does_not_stop_batch(monkeypatch: pytest.MonkeyPatch, batch: dict, error: Exception) -> None:
    rows = {row['case_id']:row for row in batch['rows']}
    def run(case_id, policy):
        if case_id == 'case_101': raise error
        return dict(rows[case_id])
    mock = MagicMock(side_effect=run)
    monkeypatch.setattr(demo_service,'run_demo',mock)
    actual=demo_service.run_all_demos(DEFAULT_POLICY)
    assert mock.call_count==14
    assert actual['success']==13 and actual['failed']==1 and actual['errors']==1
    assert actual['rows'][0]['status'] is None
    assert 'private' not in actual['rows'][0]['error']


def test_matched_but_not_detected_is_failure(monkeypatch: pytest.MonkeyPatch,batch: dict) -> None:
    rows={row['case_id']:dict(row) for row in batch['rows']}
    rows['case_101'].update(detected=False,test_success=False)
    monkeypatch.setattr(demo_service,'run_demo',lambda case_id,path:dict(rows[case_id]))
    result=demo_service.run_all_demos(DEFAULT_POLICY)
    assert result['matched']==14 and result['success']==13 and result['failed']==1


def test_csv_snapshot(batch: dict) -> None:
    rows=list(csv.reader(io.StringIO(demo_service.batch_csv(batch))))
    assert len(rows)==15
    assert rows[0][0]=='STT'
    assert 'KHÔNG ĐẠT' in rows[1] and 'KIỂM THỬ THÀNH CÔNG' in rows[1]


def test_flask_batch_and_export(monkeypatch: pytest.MonkeyPatch,batch: dict) -> None:
    monkeypatch.setattr(demo_service,'run_all_demos',MagicMock(return_value=batch))
    response=create_app({'TESTING':True}).test_client().post('/demo',data={'action':'all'})
    assert response.status_code==200
    text=response.get_data(as_text=True)
    assert 'id="batch-results"' in text and 'XUẤT BÁO CÁO CSV' in text
    payload=re.search(r'id="batch-csv">(.*?)</script>',text,re.S)[1]
    assert json.loads(payload)==demo_service.batch_csv(batch)
    assert text.count('class="batch-detail-link"')==14


def test_flask_batch_manifest_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(demo_service,'run_all_demos',MagicMock(side_effect=ValueError('private')))
    response=create_app({'TESTING':True}).test_client().post('/demo',data={'action':'all'})
    assert response.status_code==503 and 'private' not in response.get_data(as_text=True)
