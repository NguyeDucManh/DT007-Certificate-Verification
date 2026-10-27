"""Điều phối 2A/2B, cô lập lỗi module và tạo kết quả để CLI hiển thị."""

from collections.abc import Callable
from dataclasses import dataclass, field, asdict, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeVar

from cryptography import x509

from src.algorithm_policy import AlgorithmResult, evaluate_algorithm, load_policy
from src.certificate_fetcher import TLSCertificates, fetch_peer_chain
from src.certificate_parser import CertificateInfo, extract_certificate_info, parse_certificate
from src.chain_validator import ChainResult, validate_chain
from src.crypto_info import get_crypto_info
from src.ct_log_analyzer import analyze_file
from src.ct_validator import CTResult, validate_ct
from src.hostname_validator import HostnameResult, validate_hostname
from src.sct_parser import parse_scts
from src.security_evaluator import SecurityResult, evaluate_security
from src.validity_checker import ValidityResult, check_validity
from src.revocation_checker import check_revocation
from src.aia_completion import complete_chain
from src.ct_crypto import verify_sct
from src.ct_registry import load_official_registry
from src.ct_signed_input import precert_input
from src.ct_inclusion import check_inclusion
from src.revocation_network import FetchPolicy
from src.untrusted_tls import collect_untrusted_peer
import ssl

T = TypeVar("T")


@dataclass(frozen=True)
class CertificateAnalysis:
    """Kết quả từng module có thể thiếu nếu lỗi, cùng final result."""

    info: CertificateInfo | None
    hostname: HostnameResult | None
    validity: ValidityResult | None
    chain: ChainResult | None
    algorithm: AlgorithmResult | None
    ct: CTResult | None
    security: SecurityResult
    errors: dict[str, str]
    extensions: dict = field(default_factory=dict)


def _run(label: str, action: Callable[[], T], errors: dict[str, str]) -> T | None:
    """Boundary cho lỗi module: ghi rõ lỗi, không bỏ các kiểm tra độc lập."""
    try:
        return action()
    except Exception as exc:
        errors[label] = f"{type(exc).__name__}: {exc}"
        return None


def analyze_certificate(
    hostname: str, port: int, timeout: float,
    dataset_path: Path, policy_path: Path,
    current_time: datetime | None = None,
    fetcher: Callable[[str, int, float], TLSCertificates] = fetch_peer_chain,
    *, advanced: bool = False,
) -> CertificateAnalysis:
    """Dùng một TLS session; giữ các module lỗi thành trạng thái fail/warning."""
    errors: dict[str, str] = {}
    current_time = datetime.now(timezone.utc) if current_time is None else current_time
    recovery = {"status": "NOT_CHECKED", "reason": "Không dùng thu thập TLS chưa tin cậy."}
    def fetch_with_recovery() -> TLSCertificates:
        """Only missing-issuer TLS errors permit opt-in untrusted inspection."""
        try:
            return fetcher(hostname, port, timeout)
        except Exception as exc:
            cause = exc if isinstance(exc, ssl.SSLCertVerificationError) else exc.__cause__
            if not advanced or not isinstance(cause, ssl.SSLCertVerificationError) or cause.verify_code not in (20, 21):
                raise
            recovered = collect_untrusted_peer(hostname, port, timeout)
            recovery.update(status="UNTRUSTED", reason="Thu thập riêng sau lỗi thiếu issuer; phải xác minh lại chain, hostname, thời hạn và chính sách.")
            return recovered
    fetched = _run("TLS Fetch", fetch_with_recovery, errors)
    cert = _run("Certificate", lambda: parse_certificate(fetched.leaf_der), errors) if fetched is not None else None
    info = host_result = validity = chain = algorithm = ct = None
    extensions = {
        "tls_collection": recovery,
        "revocation": {"status": "NOT_CHECKED", "reason": "Chưa bật kiểm tra OCSP/CRL; không suy ra chứng thư an toàn.", "evidence": []},
        "aia": {"status": "NOT_CHECKED", "reason": "Chưa yêu cầu bổ sung chuỗi qua AIA.", "downloads": []},
        "sct_verification": [],
        "inclusion": {"status": "NOT_VERIFIED", "reason": "Chưa có STH được xác thực và inclusion proof phù hợp; không suy ra đã được đưa vào log."},
    }
    if cert is not None:
        info = _run("Certificate", lambda: extract_certificate_info(cert), errors)
        host_result = _run("Hostname", lambda: validate_hostname(cert, hostname), errors)
        validity = _run("Validity", lambda: check_validity(cert, current_time), errors)

        def check_chain() -> ChainResult:
            """Parse chain và trust anchors độc lập, rồi verify thực sự."""
            assert fetched is not None
            certificates = [parse_certificate(der) for der in fetched.chain_der]
            if not certificates or certificates[0] != cert:
                raise ValueError("Chain leaf không khớp leaf certificate đang được phân tích.")
            # Ưu tiên terminal được tin cậy trực tiếp; nếu không có thì dùng
            # store độc lập để xây dựng phần đường dẫn còn thiếu.
            direct = [der for der in fetched.trust_anchors_der if der == fetched.chain_der[-1]]
            anchors = [parse_certificate(der) for der in direct or fetched.trust_anchors_der]
            peer = [parse_certificate(der) for der in fetched.peer_chain_der] if fetched.peer_chain_der is not None else None
            return validate_chain(certificates, anchors, current_time, peer_chain=peer)

        chain = _run("Certificate Chain", check_chain, errors)
        if advanced and fetched is not None and chain is not None:
            try:
                anchors = [parse_certificate(der) for der in fetched.trust_anchors_der]
                aia = complete_chain(chain.certificates, anchors, now=current_time, peer_chain=chain.peer_certificates)
                extensions["aia"] = {"status": aia.status, "reason": aia.reason, "downloads": list(aia.downloads)}
                chain = aia.chain
            except Exception as exc:
                extensions["aia"] = {"status": "ERROR", "reason": "Không hoàn tất AIA: " + str(exc), "downloads": []}
            try:
                issuer = chain.certificates[1] if len(chain.certificates) > 1 else None
                extensions["revocation"] = check_revocation(cert, issuer, issuer_trusted=chain.status == "PASS",
                    online=True, now=current_time, network_policy=FetchPolicy(timeout=min(timeout, 8.0))).to_dict()
            except Exception as exc:
                extensions["revocation"] = {"status": "ERROR", "reason": "Không kiểm tra được thu hồi: " + str(exc), "evidence": []}
        algorithm = _run("Algorithm Policy", lambda: evaluate_algorithm(get_crypto_info(cert), load_policy(policy_path)), errors)
        ct = _run("Certificate Transparency", lambda: validate_ct(
            parse_scts(cert), analyze_file(dataset_path), cert.not_valid_after_utc, current_time,
        ), errors)
        scts = parse_scts(cert).scts
        registry = None
        if advanced and scts:
            try:
                registry = load_official_registry()
                extensions["ct_key_source"] = {"status": "VALID", "reason": "Danh sách Google CT có chữ ký publisher hợp lệ với khóa đã pin.", "sha256": registry.sha256, "timestamp": registry.timestamp}
            except Exception as exc:
                extensions["ct_key_source"] = {"status": "NOT_VERIFIED", "reason": "Không xác thực được nguồn khóa CT: " + (str(exc) or type(exc).__name__)}
        proofs = []
        signatures = []
        for sct in scts:
            entry_args = {}
            if sct.entry_type == "PRE_CERTIFICATE" and registry is not None and chain is not None and chain.status == "PASS" and len(chain.certificates) > 1:
                try:
                    entry_args = precert_input(cert, chain.certificates[1])
                except Exception as exc:
                    signatures.append(dict(log_id=sct.log_id, status="NOT_VERIFIED", reason="Không dựng được precertificate: " + str(exc)))
                    continue
            evidence = verify_sct(sct, fetched.leaf_der, registry.keys if registry else {}, **entry_args)
            signatures.append(dict(log_id=sct.log_id, **asdict(evidence)))
            if evidence.status == "VALID" and len(proofs) < 2:
                proofs.append(check_inclusion(sct, fetched.leaf_der, registry, now=current_time, **entry_args))
        extensions["sct_verification"] = signatures
        if proofs:
            all_proved = len(proofs) == len(scts) and all(p["status"] == "VALID" for p in proofs)
            proof_status = "INVALID" if any(p["status"] == "INVALID" for p in proofs) else "VALID" if all_proved else "UNSUPPORTED" if len(proofs) == len(scts) and all(p["status"] == "UNSUPPORTED" for p in proofs) else "NOT_VERIFIED"
            extensions["inclusion"] = {"status": proof_status, "reason": "Kết quả từng SCT ở bằng chứng; giới hạn hai truy vấn proof, consistency chưa có checkpoint độc lập.", "evidence": proofs}
        if ct is not None and registry is not None and signatures:
            states = {s["status"] for s in signatures}
            sig_status = "INVALID" if "INVALID" in states else "VALID" if states == {"VALID"} else "NOT_VERIFIED"
            reasons = tuple(r for r in ct.reasons if not r.startswith("SCT signatures/inclusion proofs are NOT_VERIFIED"))
            reasons += ("Kiểm tra CT bổ sung: chữ ký " + sig_status + "; inclusion " + extensions["inclusion"]["status"] + "; chưa kiểm tra consistency với checkpoint độc lập.",)
            ct = replace(ct, signature_validation=sig_status, inclusion_validation=extensions["inclusion"]["status"], reasons=reasons)
    security = evaluate_security(validity, host_result, chain, algorithm, ct, errors)
    if advanced:
        revocation = extensions["revocation"]
        checks = dict(security.checks, Revocation="FAIL" if revocation["status"] == "REVOKED" else "PASS" if revocation["status"] == "GOOD" else "WARNING")
        if any(s["status"] == "INVALID" for s in extensions["sct_verification"]) or extensions["inclusion"]["status"] == "INVALID":
            checks["CT Cryptography"] = "FAIL"
        reasons = security.reasons + (() if revocation["status"] == "GOOD" else (revocation["reason"],))
        status = "FAIL" if "FAIL" in checks.values() else "WARNING" if "WARNING" in checks.values() else "PASS"
        security = SecurityResult(status, checks, reasons)
    return CertificateAnalysis(info, host_result, validity, chain, algorithm, ct, security, errors, extensions)
