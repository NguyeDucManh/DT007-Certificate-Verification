"""Bounded AIA intermediate completion; downloaded certificates never become anchors."""
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import AuthorityInformationAccessOID
from src.chain_validator import ChainResult, validate_chain, verify_signature
from src.revocation_network import FetchPolicy, fetch_bytes


@dataclass(frozen=True)
class AIAResult:
    """Only chain.status PASS is evidence of a verified path."""
    status: str
    reason: str
    chain: ChainResult
    downloads: tuple[dict, ...] = ()


def issuer_urls(cert: x509.Certificate) -> tuple[str, ...]:
    """Read only caIssuers URI, excluding OCSP locations."""
    try:
        extension = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
        return tuple(dict.fromkeys(item.access_location.value for item in extension if item.access_method == AuthorityInformationAccessOID.CA_ISSUERS and isinstance(item.access_location, x509.UniformResourceIdentifier)))
    except x509.ExtensionNotFound:
        return ()


def complete_chain(certificates: Sequence[x509.Certificate], anchors: Sequence[x509.Certificate], *, now: datetime | None = None,
                   fetcher: Callable = fetch_bytes, policy: FetchPolicy = FetchPolicy(max_bytes=262144), max_downloads: int = 4, max_depth: int = 6,
                   peer_chain: Sequence[x509.Certificate] | None = None) -> AIAResult:
    """Try DER/PEM single-cert AIA, then reuse all existing path/CA/purpose checks."""
    if not 1 <= max_downloads <= 4 or not 1 <= max_depth <= 8:
        raise ValueError("Giới hạn AIA không hợp lệ.")
    clock = now or datetime.now(timezone.utc)
    chain = list(certificates)
    result = validate_chain(chain, anchors, clock, peer_chain=peer_chain)
    if result.status == "PASS":
        return AIAResult("NOT_CHECKED", "Chuỗi đã xác minh; không cần tải AIA.", result)
    evidence: list[dict] = []
    visited: set[str] = set()
    seen = {c.fingerprint(hashes.SHA256()) for c in chain}
    while chain and len(chain) < max_depth and len(evidence) < max_downloads:
        added = False
        for url in issuer_urls(chain[-1]):
            if url in visited or len(evidence) >= max_downloads:
                continue
            visited.add(url)
            item = {"url": url, "status": "ERROR", "reason": "", "sha256": None}
            evidence.append(item)
            try:
                data = fetcher(url, policy=policy)
                if len(data) > policy.max_bytes:
                    raise ValueError("Chứng thư AIA vượt giới hạn kích thước.")
                candidate = x509.load_pem_x509_certificate(data) if data.startswith(b"-----BEGIN CERTIFICATE") else x509.load_der_x509_certificate(data)
                fingerprint = candidate.fingerprint(hashes.SHA256())
                item["sha256"] = fingerprint.hex()
                if fingerprint in seen:
                    raise ValueError("Phát hiện vòng lặp chứng thư AIA.")
                basic = candidate.extensions.get_extension_for_class(x509.BasicConstraints).value
                if not basic.ca or not verify_signature(chain[-1], candidate) or not candidate.not_valid_before_utc <= clock <= candidate.not_valid_after_utc:
                    raise ValueError("Chứng thư AIA sai issuer/chữ ký/CA hoặc thời hạn.")
                try:
                    if not candidate.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
                        raise ValueError("CA tải qua AIA không có quyền keyCertSign.")
                except x509.ExtensionNotFound:
                    pass
                chain.append(candidate)
                seen.add(fingerprint)
                item.update(status="ACCEPTED", reason="Chấp nhận làm intermediate chưa tin cậy; vẫn phải xác minh đường dẫn.")
                result = validate_chain(chain, anchors, clock, peer_chain=peer_chain)
                if result.status == "PASS":
                    return AIAResult("PASS", "Đã bổ sung AIA và xác minh đường dẫn tới trust anchor độc lập.", result, tuple(evidence))
                added = True
                break
            except Exception as exc:
                item["reason"] = str(exc) or type(exc).__name__
        if not added:
            break
    return AIAResult("FAIL", "Không xây dựng được đường dẫn tin cậy đầy đủ bằng AIA.", result, tuple(evidence))
