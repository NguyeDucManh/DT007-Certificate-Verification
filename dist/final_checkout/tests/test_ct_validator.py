"""Kiểm tra log matching, states, timestamp và semantics NotAfter."""

import base64
from dataclasses import replace
from datetime import datetime, timedelta

import pytest

from src.ct_log_analyzer import analyze_dataset, DatasetSummary
from src.ct_validator import interval_status, validate_ct
from src.sct_parser import SCTParseResult, SCTRecord


@pytest.fixture
def sct(reference_time: datetime) -> SCTRecord:
    return SCTRecord(base64.b64encode(b"\x01" * 32).decode("ascii"), reference_time - timedelta(hours=1), "v1")


@pytest.fixture
def dataset(sct: SCTRecord) -> DatasetSummary:
    return analyze_dataset({"operators": [{"name": "Fixture Operator", "logs": [{
        "log_id": sct.log_id, "description": "Fixture log", "key": "fixture-key",
        "url": "https://example.test/ct/", "mmd": 86400,
        "state": {"usable": {"timestamp": "2026-01-01T00:00:00Z"}},
        "temporal_interval": {"start_inclusive": "2026-07-01T00:00:00Z", "end_exclusive": "2027-01-01T00:00:00Z"},
    }]}]})


def test_known_log_id(sct: SCTRecord, dataset: DatasetSummary, reference_time: datetime) -> None:
    result = validate_ct(SCTParseResult((sct,)), dataset, reference_time, reference_time)
    assert result.matched_count == 1 and result.matches[0].log_id_match == "PASS"
    assert result.matches[0].log.operator == "Fixture Operator"
    assert result.matches[0].status == "PASS"
    assert result.status == "WARNING" and result.signature_validation == "NOT_VERIFIED"


def test_unknown_log_id(sct: SCTRecord, dataset: DatasetSummary, reference_time: datetime) -> None:
    unknown = replace(sct, log_id="unlisted")
    result = validate_ct(SCTParseResult((unknown,)), dataset, reference_time, reference_time)
    assert result.matched_count == 0 and result.status == "FAIL"
    assert any("Unknown CT log ID" in reason for reason in result.reasons)


@pytest.mark.parametrize("state,status", [
    ("usable", "PASS"), ("qualified", "WARNING"), ("readonly", "WARNING"),
    ("retired", "FAIL"), ("rejected", "FAIL"), ("pending", "WARNING"), ("new-state", "WARNING"),
])
def test_states(sct: SCTRecord, dataset: DatasetSummary, reference_time: datetime, state: str, status: str) -> None:
    log = replace(dataset.logs[0], state=state, state_timestamp="2026-10-01T00:00:00Z")
    result = validate_ct(SCTParseResult((sct,)), replace(dataset, logs=[log]), reference_time, reference_time)
    assert result.matches[0].state_status == status
    assert result.matches[0].status == status


def test_retired_after_sct(sct: SCTRecord, dataset: DatasetSummary, reference_time: datetime) -> None:
    log = replace(dataset.logs[0], state="retired", state_timestamp=reference_time.isoformat())
    result = validate_ct(SCTParseResult((sct,)), replace(dataset, logs=[log]), reference_time, reference_time)
    assert result.matches[0].status == "WARNING"
    assert "predates retirement" in result.matches[0].reasons[0]


def test_timestamp_inside_interval(sct: SCTRecord, dataset: DatasetSummary) -> None:
    assert interval_status(sct.timestamp, dataset.logs[0]) == "PASS"


def test_timestamp_outside_interval(sct: SCTRecord, dataset: DatasetSummary, reference_time: datetime) -> None:
    old_sct = replace(sct, timestamp=reference_time.replace(month=1))
    result = validate_ct(SCTParseResult((old_sct,)), dataset, reference_time, reference_time)
    assert result.matches[0].timestamp_interval == "NOT_APPLICABLE"
    assert result.matches[0].certificate_interval == "PASS"
    assert result.matches[0].status == "PASS"
    assert not any('SCT timestamp interval' in reason for reason in result.reasons)


def test_expiry_outside_interval(sct: SCTRecord, dataset: DatasetSummary, reference_time: datetime) -> None:
    result = validate_ct(SCTParseResult((sct,)), dataset, reference_time.replace(year=2027), reference_time)
    assert result.matches[0].certificate_interval == "FAIL" and result.status == "FAIL"


def test_interval_boundaries(dataset: DatasetSummary) -> None:
    log = dataset.logs[0]
    assert interval_status(datetime.fromisoformat(log.start_inclusive), log) == "PASS"
    assert interval_status(datetime.fromisoformat(log.end_exclusive), log) == "FAIL"


def test_missing_interval(sct: SCTRecord, dataset: DatasetSummary, reference_time: datetime) -> None:
    log = replace(dataset.logs[0], start_inclusive=None)
    result = validate_ct(SCTParseResult((sct,)), replace(dataset, logs=[log]), reference_time, reference_time)
    assert result.matches[0].certificate_interval == "UNKNOWN" and result.status == "WARNING"


def test_tiled_log(sct: SCTRecord, reference_time: datetime) -> None:
    dataset = analyze_dataset({"operators": [{"name": "Tiled Operator", "tiled_logs": [{
        "log_id": sct.log_id, "submission_url": "https://example.test/submit/", "state": {"usable": {}},
    }]}]})
    result = validate_ct(SCTParseResult((sct,)), dataset, reference_time, reference_time)
    assert result.matched_count == 1
    assert result.matches[0].log.source == "tiled_logs"
    assert result.matches[0].log.submission_url == "https://example.test/submit/"


def test_duplicate_log_id(sct: SCTRecord, dataset: DatasetSummary, reference_time: datetime) -> None:
    result = validate_ct(SCTParseResult((sct,)), replace(dataset, logs=dataset.logs * 2), reference_time, reference_time)
    assert result.status == "WARNING" and result.matched_count == 0


def test_optional_interval_absent(sct: SCTRecord, dataset: DatasetSummary, reference_time: datetime) -> None:
    log = replace(dataset.logs[0], start_inclusive=None, end_exclusive=None)
    result = validate_ct(SCTParseResult((sct,)), replace(dataset, logs=[log]), reference_time, reference_time)
    assert result.matches[0].certificate_interval == 'NOT_APPLICABLE'
    assert result.matches[0].status == 'PASS'
    assert result.inclusion_validation == result.signature_validation == 'NOT_VERIFIED'


def test_retired_without_timestamp_is_not_failure(sct: SCTRecord, dataset: DatasetSummary, reference_time: datetime) -> None:
    log = replace(dataset.logs[0], state='retired', state_timestamp=None)
    result = validate_ct(SCTParseResult((sct,)), replace(dataset, logs=[log]), reference_time, reference_time)
    assert result.matches[0].state_status == 'WARNING'
    assert 'Insufficient' in result.matches[0].reasons[0]


def test_no_sct(dataset: DatasetSummary) -> None:
    result = validate_ct(SCTParseResult(()), dataset)
    assert result.status == "WARNING" and "NO_SCT" in result.reasons[0]


def test_malformed_sct(dataset: DatasetSummary) -> None:
    result = validate_ct(SCTParseResult((), ("Malformed SCT",)), dataset)
    assert result.status == "WARNING" and result.reasons == ("Malformed SCT",)


def test_future_sct(sct: SCTRecord, dataset: DatasetSummary, reference_time: datetime) -> None:
    result = validate_ct(SCTParseResult((replace(sct, timestamp=reference_time + timedelta(hours=1)),)), dataset, reference_time, reference_time)
    assert result.status == "FAIL"


def test_timezone_naive_sct(sct: SCTRecord, dataset: DatasetSummary, reference_time: datetime) -> None:
    result = validate_ct(SCTParseResult((replace(sct, timestamp=sct.timestamp.replace(tzinfo=None)),)), dataset, reference_time, reference_time)
    assert result.status == "FAIL"


def test_unknown_version(sct: SCTRecord, dataset: DatasetSummary, reference_time: datetime) -> None:
    result = validate_ct(SCTParseResult((replace(sct, version="v2"),)), dataset, reference_time, reference_time)
    assert result.matches[0].status == "WARNING"
