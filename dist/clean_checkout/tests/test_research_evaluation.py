from datetime import datetime, timezone
from experiments.synthetic_cases import SyntheticLab
from src.algorithm_policy import load_policy
from experiments.run_experiments import POLICY_PATH
import pytest
from experiments.research_evaluation import evaluate
from experiments.dataset_profile import profile
import json

def test_ct_ablation_is_real_and_changes_outcome():
    lab = SyntheticLab(datetime(2026, 10, 7, tzinfo=timezone.utc), load_policy(POLICY_PATH))
    baseline = lab.run('UNKNOWN_CT_LOG', profile='baseline')
    extended = lab.run('UNKNOWN_CT_LOG', profile='extended')
    assert baseline.status == 'PASS' and baseline.detected is False
    assert extended.status == 'FAIL' and extended.detected is True

def test_non_ct_failure_detected_in_both_profiles():
    lab = SyntheticLab(datetime(2026, 10, 7, tzinfo=timezone.utc), load_policy(POLICY_PATH))
    assert lab.run('RSA_1024', profile='baseline').status == 'FAIL'
    assert lab.run('RSA_1024', profile='extended').status == 'FAIL'

def test_valid_control_does_not_fail():
    lab = SyntheticLab(datetime(2026, 10, 7, tzinfo=timezone.utc), load_policy(POLICY_PATH))
    assert lab.run('VALID_CONTROL', profile='baseline').status == 'PASS'
    assert lab.run('VALID_CONTROL', profile='extended').status in ('PASS','WARNING')


def test_reject_less_than_three(tmp_path):
    with pytest.raises(ValueError):
        evaluate(2,tmp_path,1)


def test_profiles_preserve_demo_evidence_and_real_reasons():
    lab = SyntheticLab(datetime(2026,10,7,tzinfo=timezone.utc),load_policy(POLICY_PATH))
    result=lab.run('EXPIRED_CERTIFICATE',profile='baseline')
    assert result.status=='FAIL' and result.evidence['mock_used'] is False
    assert any('EXPIRED' in reason for reason in result.reasons)
    assert 'ct_validator.validate_ct' not in result.evidence['modules']
    assert lab.run('SCT_TIMESTAMP_OUTSIDE_INTERVAL').detected is True


def test_dataset_quality_warns_bad_fields(tmp_path):
    file=tmp_path/'data.json'
    file.write_text(json.dumps({'operators':[{'name':'Fixture','tiled_logs':[{'log_id':[], 'submission_url':[]}]}]}),encoding='utf-8')
    result=profile(file)
    assert len(result['quality_warnings'])==2


def test_research_exports_real_metrics(tmp_path):
    result=evaluate(3,tmp_path,42)
    assert result['case_count_per_profile_repeat']==15
    assert result['profiles']['baseline']['false_negative_count']==6
    assert result['profiles']['extended']['false_negative_count']==0
    assert result['profiles']['extended']['runs'][0]['misconfiguration_types_total']==13
    assert 'src/security_evaluator.py' in result['inputs_sha256']
    assert (tmp_path/'config.json').exists() and (tmp_path/'execution.log').exists()
    assert len(json.loads((tmp_path/'evidence.json').read_text(encoding='utf-8')))==90
