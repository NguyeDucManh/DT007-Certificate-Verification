"""Kiểm tra thời hạn certificate bằng datetime timezone-aware."""

from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509


@dataclass(frozen=True)
class ValidityResult:
    """Trạng thái và các mốc thời gian chuẩn hóa UTC."""

    status: str
    message: str
    not_before: datetime
    not_after: datetime
    current_time: datetime


def check_validity(certificate: x509.Certificate, current_time: datetime | None = None) -> ValidityResult:
    """Kiểm tra khoảng hiệu lực gồm cả hai đầu mút; từ chối datetime naive."""
    current_time = datetime.now(timezone.utc) if current_time is None else current_time
    if current_time.tzinfo is None or current_time.utcoffset() is None:
        raise ValueError("current_time phải là datetime timezone-aware.")
    current_time = current_time.astimezone(timezone.utc)
    start, end = certificate.not_valid_before_utc, certificate.not_valid_after_utc
    if current_time < start:
        status, message = "NOT_YET_VALID", "Certificate chưa đến thời điểm có hiệu lực."
    elif current_time > end:
        status, message = "EXPIRED", "Certificate đã hết hạn."
    else:
        status, message = "VALID", "Certificate đang trong khoảng thời gian có hiệu lực."
    return ValidityResult(status, message, start, end, current_time)
