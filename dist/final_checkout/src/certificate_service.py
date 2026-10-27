"""Service web: gọi engine hiện có và chuyển dữ liệu sang view model."""

from datetime import datetime
from pathlib import Path
import time
from typing import Any

from src.certificate_security import CertificateAnalysis, analyze_certificate
from src.hostname_validator import normalize_hostname
from src.chain_validator import verify_signature

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = PROJECT_ROOT / "data" / "log_list.json"
DEFAULT_POLICY = PROJECT_ROOT / "config" / "algorithm_policy.json"
INPUT_ERROR = "Tên miền không hợp lệ. Vui lòng nhập dạng google.com, không kèm http://, https:// hoặc khoảng trắng."


def validate_web_hostname(value: str) -> str:
    """Tái sử dụng validator hostname của engine, trả lỗi form bằng tiếng Việt."""
    try:
        if not isinstance(value, str) or any(character.isspace() for character in value):
            raise ValueError("Whitespace in hostname")
        return normalize_hostname(value)
    except ValueError as exc:
        raise ValueError(INPUT_ERROR) from exc


def _date(value: datetime) -> str:
    """Giữ timezone của engine khi hiển thị thời gian."""
    return value.isoformat()


def build_view_model(hostname: str, analysis: CertificateAnalysis, runtime_seconds: float) -> dict[str, Any]:
    """Chỉ chuyển metadata sang dữ liệu template, không tính lại security status."""
    info, host, validity = analysis.info, analysis.hostname, analysis.validity
    crypto = info.crypto if info is not None else None
    chain, policy, ct = analysis.chain, analysis.algorithm, analysis.ct
    certificates = chain.certificates if chain is not None else ()
    chain_items = []
    for index, certificate in enumerate(certificates):
        is_root = certificate.subject == certificate.issuer and verify_signature(certificate, certificate)
        is_anchor = chain.trust_anchor == certificate
        role = ('Leaf' if index == 0 else 'Root CA / Trust Anchor' if is_root and is_anchor
                else 'Root CA' if is_root else 'Intermediate Trust Anchor' if is_anchor else f'Intermediate #{index}')
        origin = ('Chưa thu thập chuỗi máy chủ gửi' if chain.peer_certificates is None
                  else 'Máy chủ gửi qua TLS' if certificate in chain.peer_certificates
                  else 'Bổ sung từ trust store / đường dẫn đã xác minh; không nằm trong chuỗi máy chủ gửi')
        chain_items.append({
            "role": role, "subject": certificate.subject.rfc4514_string(),
            "origin": origin, "is_trust_anchor": is_anchor,
            "issuer": certificate.issuer.rfc4514_string(),
            "not_before": _date(certificate.not_valid_before_utc),
            "not_after": _date(certificate.not_valid_after_utc),
        })
    scts = []
    if ct is not None:
        for match in ct.matches:
            log = match.log
            scts.append({
                "log_id": match.sct.log_id, "version": match.sct.version,
                "operator": log.operator if log else None, "description": log.description if log else None,
                "state": log.state if log else None, "mmd": log.mmd if log else None,
                "url": (log.url or log.submission_url) if log else None,
                "start_interval": log.start_inclusive if log else None,
                "end_interval": log.end_exclusive if log else None,
                "timestamp": _date(match.sct.timestamp),
                "timestamp_interval": match.timestamp_interval, "certificate_interval": match.certificate_interval,
                "log_id_match": match.log_id_match, "state_policy": match.state_status,
                "status": match.status, "reasons": list(match.reasons),
            })
    scan_error = None
    if "TLS Fetch" in analysis.errors:
        scan_error = analysis.errors["TLS Fetch"]
    elif info is None and "Certificate" in analysis.errors:
        scan_error = analysis.errors["Certificate"]
    return {
        "extensions": analysis.extensions,
        "hostname": hostname, "target": f"{hostname}:443", "runtime_seconds": runtime_seconds,
        "scan_error": scan_error,
        "certificate": {
            "subject": info.subject, "issuer": info.issuer, "serial_number": str(info.serial_number),
            "version": info.version, "not_before": _date(info.not_before), "not_after": _date(info.not_after),
        } if info else None,
        "hostname_validation": {
            "requested_hostname": host.requested_hostname, "san_count": host.san_count,
            "san": [str(name.value) for name in info.san] if info else [],
            "status": host.status, "message": host.message,
        } if host else None,
        "validity": {
            "status": validity.status, "message": validity.message,
            "not_before": _date(validity.not_before), "not_after": _date(validity.not_after),
            "current_time": _date(validity.current_time),
        } if validity else None,
        "cryptography": {
            "public_key_algorithm": crypto.public_key_algorithm, "key_size": crypto.public_key_size,
            "signature_algorithm": crypto.signature_algorithm_name, "signature_oid": crypto.signature_algorithm_oid,
            "hash_algorithm": crypto.signature_hash_algorithm,
        } if crypto else None,
        "chain": {
            "length": len(certificates), "certificates": chain_items,
            "issuer_subject_links": chain.issuer_subject_links, "signature_validation": chain.signature_validation,
            "ca_constraints": chain.ca_constraints, "validity": chain.validity,
            "tls_usage": chain.tls_usage,
            "trusted_root": chain.trust, "status": chain.status, "reasons": list(chain.reasons),
            "trust_anchor_subject": chain.trust_anchor.subject.rfc4514_string() if chain.trust_anchor else None,
            "trust_explanation": 'Đường dẫn đã được OpenSSL xác minh tới CA trong trust store độc lập. Điểm neo có thể là CA trung gian được tin cậy trực tiếp, không nhất thiết là root tự ký.' if chain.trust == 'PASS' else 'Chưa xác minh được đường dẫn tới điểm neo tin cậy độc lập.',
        } if chain else None,
        "algorithm_policy": {
            "algorithm": policy.info.public_key_algorithm, "key_size": policy.info.public_key_size,
            "hash_algorithm": policy.info.signature_hash_algorithm,
            "public_key": {"status": policy.public_key.status, "message": policy.public_key.message},
            "key_size_rule": {"status": policy.key_size.status, "message": policy.key_size.message},
            "hash_rule": {"status": policy.signature_hash.status, "message": policy.signature_hash.message},
            "status": policy.status, "reasons": list(policy.reasons),
        } if policy else None,
        "ct": {
            "sct_count": len(ct.matches), "matched_scts": ct.matched_count,
            "signature_validation": ct.signature_validation, "inclusion_validation": ct.inclusion_validation, "status": ct.status,
            "scts": scts, "reasons": list(ct.reasons),
        } if ct else None,
        "security": {"status": analysis.security.status, "checks": dict(analysis.security.checks),
                     "reasons": list(analysis.security.reasons)},
        "errors": [{"module": name, "message": message} for name, message in analysis.errors.items()],
    }


def scan_certificate(
    hostname: str, *, timeout: float = 10.0,
    dataset_path: Path = DEFAULT_DATASET, policy_path: Path = DEFAULT_POLICY,
    advanced: bool = False,
) -> dict[str, Any]:
    """Gọi trực tiếp pipeline 2B, đo runtime bằng perf_counter, không shell-out."""
    hostname = validate_web_hostname(hostname)
    start = time.perf_counter()
    analysis = analyze_certificate(hostname, 443, timeout, Path(dataset_path), Path(policy_path), **({"advanced": True} if advanced else {}))
    runtime = time.perf_counter() - start
    return build_view_model(hostname, analysis, runtime)
