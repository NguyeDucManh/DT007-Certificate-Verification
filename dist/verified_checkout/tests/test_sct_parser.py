"""Parse SCT extension thật và xử lý certificate không có/sai SCT."""

import base64
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from cryptography import x509

from src.sct_parser import parse_scts


def test_certificate_with_sct(sct_certificate_factory: Callable) -> None:
    result = parse_scts(sct_certificate_factory())
    assert result.status == "PASS" and len(result.scts) == 1
    assert result.scts[0].version == "v1" and not result.errors


def test_no_sct(certificate: x509.Certificate) -> None:
    result = parse_scts(certificate)
    assert result.status == "NO_SCT" and not result.scts


def test_log_id(sct_certificate_factory: Callable) -> None:
    log_id = bytes(range(32))
    result = parse_scts(sct_certificate_factory(log_ids=[log_id]))
    assert result.scts[0].log_id == base64.b64encode(log_id).decode("ascii")


def test_timestamp(sct_certificate_factory: Callable, reference_time: datetime) -> None:
    timestamp = reference_time - timedelta(minutes=2)
    result = parse_scts(sct_certificate_factory(timestamp=timestamp))
    assert result.scts[0].timestamp == timestamp
    assert result.scts[0].timestamp.tzinfo == timezone.utc


def test_malformed_sct(sct_certificate_factory: Callable) -> None:
    result = parse_scts(sct_certificate_factory(malformed=True))
    assert result.status == "WARNING" and result.errors and not result.scts


def test_multiple_scts(sct_certificate_factory: Callable) -> None:
    result = parse_scts(sct_certificate_factory(log_ids=[b"\x01" * 32, b"\x02" * 32, b"\x03" * 32]))
    assert len(result.scts) == 3
