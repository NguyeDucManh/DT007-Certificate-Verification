"""Đối chiếu metadata SCT với CT dataset; chưa verify SCT signature."""

from dataclasses import dataclass
from datetime import datetime, timezone

from src.ct_log_analyzer import CTLog, DatasetSummary
from src.sct_parser import SCTParseResult, SCTRecord


@dataclass(frozen=True)
class SCTMatch:
    """Một SCT và các kết quả đối chiếu log/state/time."""

    sct: SCTRecord
    log: CTLog | None
    log_id_match: str
    state_status: str
    timestamp_interval: str
    certificate_interval: str
    status: str
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class CTResult:
    """Kết quả matching; không coi metadata matching là bằng chứng SCT hợp lệ."""

    matches: tuple[SCTMatch, ...]
    status: str
    reasons: tuple[str, ...]
    signature_validation: str = "NOT_VERIFIED"
    inclusion_validation: str = "NOT_VERIFIED"

    @property
    def matched_count(self) -> int:
        """Đếm SCT có log_id khớp dataset thực tế."""
        return sum(match.log_id_match == "PASS" for match in self.matches)


def parse_utc_timestamp(value: str | None) -> datetime | None:
    """ISO timestamp phải có timezone; timestamp thiếu/sai trả None."""
    if value is None:
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None or result.utcoffset() is None:
            return None
        return result.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def interval_status(timestamp: datetime, log: CTLog) -> str:
    """Kiểm tra start inclusive/end exclusive, UNKNOWN nếu bounds không đủ."""
    start, end = parse_utc_timestamp(log.start_inclusive), parse_utc_timestamp(log.end_exclusive)
    if start is None or end is None or start >= end:
        return "UNKNOWN"
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        return "UNKNOWN"
    return "PASS" if start <= timestamp < end else "FAIL"


def _state_rule(log: CTLog, sct: SCTRecord) -> tuple[str, str]:
    """Qualified/readonly cảnh báo; retired so sánh thời điểm chuyển state."""
    if log.state == "usable":
        return "PASS", "CT log is usable"
    if log.state in ("qualified", "readonly", "pending"):
        return "WARNING", f"CT log is {log.state}; matching policy requires review"
    if log.state == "retired":
        retired_at = parse_utc_timestamp(log.state_timestamp)
        if retired_at is None or sct.timestamp.tzinfo is None or sct.timestamp.utcoffset() is None:
            return "WARNING", "Insufficient retirement timestamp data"
        if retired_at is not None and sct.timestamp.tzinfo is not None and sct.timestamp < retired_at:
            return "WARNING", "CT log is retired; SCT predates retirement"
        return "FAIL", "CT log is retired; SCT is not proven to predate retirement"
    if log.state == "rejected":
        return "FAIL", "CT log is rejected"
    return "WARNING", f"Unknown CT log state: {log.state}"


def validate_ct(
    parsed: SCTParseResult, dataset: DatasetSummary,
    certificate_not_after: datetime | None = None,
    current_time: datetime | None = None,
) -> CTResult:
    """Match IDs/state; temporal_interval chỉ kiểm tra NotAfter certificate.

    Schema Google không quy định temporal_interval cho thời điểm phát hành SCT.
    Trường timestamp_interval giữ tương thích API, luôn NOT_APPLICABLE khi match.
    Overall không PASS khi chưa xác minh SCT signature/inclusion.
    """
    if not parsed.scts:
        return CTResult((), "WARNING", parsed.errors or ("NO_SCT: certificate has no embedded SCT; policy is WARNING",))
    current_time = datetime.now(timezone.utc) if current_time is None else current_time
    if current_time.tzinfo is None or current_time.utcoffset() is None:
        raise ValueError("current_time phải là datetime timezone-aware.")
    index: dict[str, list[CTLog]] = {}
    for log in dataset.logs:
        if log.log_id:
            index.setdefault(log.log_id, []).append(log)
    matches: list[SCTMatch] = []
    for sct in parsed.scts:
        candidates = index.get(sct.log_id, [])
        if len(candidates) != 1:
            message = "Unknown CT log ID" if not candidates else "Ambiguous CT log ID: duplicate dataset records"
            match_status = "FAIL" if not candidates else "WARNING"
            matches.append(SCTMatch(sct, None, match_status, "UNKNOWN", "NOT_APPLICABLE", "UNKNOWN", match_status, (message,)))
            continue
        log = candidates[0]
        reasons: list[str] = []
        state_status, state_message = _state_rule(log, sct)
        if state_status != "PASS":
            reasons.append(state_message)
        timestamp_interval = "NOT_APPLICABLE"
        cert_interval = ("NOT_APPLICABLE" if log.start_inclusive is None and log.end_exclusive is None
                         else interval_status(certificate_not_after, log) if certificate_not_after is not None else "UNKNOWN")
        status = state_status
        if cert_interval not in ("PASS", "NOT_APPLICABLE"):
            reasons.append(f"Certificate expiry interval: {cert_interval}")
            status = "FAIL" if cert_interval == "FAIL" else "WARNING" if status != "FAIL" else status
        if sct.timestamp.tzinfo is None or sct.timestamp.utcoffset() is None:
            status = "FAIL"
            reasons.append("SCT timestamp is not timezone-aware")
        elif sct.timestamp > current_time:
            status = "FAIL"
            reasons.append("SCT timestamp is in the future")
        if sct.version != "v1":
            reasons.append(f"Unsupported SCT version: {sct.version}")
            if status != "FAIL":
                status = "WARNING"
        matches.append(SCTMatch(sct, log, "PASS", state_status, timestamp_interval, cert_interval, status, tuple(reasons)))
    reasons = list(parsed.errors)
    for number, match in enumerate(matches, start=1):
        reasons.extend(f"SCT #{number}: {reason}" for reason in match.reasons)
    reasons.append("SCT signatures/inclusion proofs are NOT_VERIFIED; CT result covers dataset matching only")
    status = "FAIL" if any(match.status == "FAIL" for match in matches) else "WARNING"
    return CTResult(tuple(matches), status, tuple(reasons))
