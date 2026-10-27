"""Kiểm tra trạng thái thời gian, đầu mút và chuyển timezone."""

from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from cryptography import x509
import pytest

from src.validity_checker import check_validity


def test_valid(certificate: x509.Certificate, reference_time: datetime) -> None:
    result = check_validity(certificate, reference_time)
    assert result.status == "VALID" and result.message
    assert result.current_time == reference_time
    assert result.not_before == certificate.not_valid_before_utc
    assert result.not_after == certificate.not_valid_after_utc


def test_expired(certificate_factory: Callable, reference_time: datetime) -> None:
    cert = certificate_factory(not_before=reference_time - timedelta(days=10), not_after=reference_time - timedelta(days=1))
    assert check_validity(cert, reference_time).status == "EXPIRED"


def test_not_yet_valid(certificate_factory: Callable, reference_time: datetime) -> None:
    cert = certificate_factory(not_before=reference_time + timedelta(days=1), not_after=reference_time + timedelta(days=10))
    assert check_validity(cert, reference_time).status == "NOT_YET_VALID"


@pytest.mark.parametrize("endpoint", ["not_valid_before_utc", "not_valid_after_utc"])
def test_inclusive_boundary(certificate: x509.Certificate, endpoint: str) -> None:
    assert check_validity(certificate, getattr(certificate, endpoint)).status == "VALID"


def test_other_timezone(certificate: x509.Certificate, reference_time: datetime) -> None:
    local_time = reference_time.astimezone(timezone(timedelta(hours=7)))
    result = check_validity(certificate, local_time)
    assert result.status == "VALID"
    assert result.current_time.tzinfo == timezone.utc
    assert result.current_time == reference_time


def test_naive_datetime_rejected(certificate: x509.Certificate) -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        check_validity(certificate, datetime(2026, 10, 7))


def test_default_current_time(certificate: x509.Certificate) -> None:
    before = datetime.now(timezone.utc)
    result = check_validity(certificate)
    assert before <= result.current_time <= datetime.now(timezone.utc)
