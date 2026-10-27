"""OCSP (RFC 6960) and conservative complete/direct CRL (RFC 5280) validation.

Issuer trust must come from an independently verified chain, never a response.
This module does not modify historical security profiles or their final status.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID

from src.chain_validator import verify_signature
from src.revocation_network import FetchPolicy, fetch_bytes

RevocationStatus = Literal["GOOD", "REVOKED", "UNKNOWN", "NOT_CHECKED", "ERROR"]


@dataclass(frozen=True)
class RevocationSources:
    """Certificate-advertised sources; URLs themselves are not trusted."""
    ocsp_urls: tuple[str, ...] = ()
    crl_urls: tuple[str, ...] = ()
    unsupported_crl_scope: bool = False


@dataclass(frozen=True)
class RevocationEvidence:
    """One source outcome, with portable evidence and Vietnamese explanation."""
    method: str
    status: RevocationStatus
    reason: str
    source: str = "offline"
    sha256: str | None = None
    signature_verified: bool = False
    issuer_verified: bool = False
    this_update: str | None = None
    next_update: str | None = None
    revoked_at: str | None = None


@dataclass(frozen=True)
class RevocationResult:
    """GOOD is scoped revocation evidence, not a statement of website safety."""
    status: RevocationStatus
    reason: str
    evidence: tuple[RevocationEvidence, ...] = ()

    def to_dict(self) -> dict:
        """Return JSON/HTML/Web-ready values without exposing certificates/keys."""
        return asdict(self)


@dataclass(frozen=True)
class ValidationPolicy:
    """Freshness limits; no-nextUpdate OCSP is bounded, CRL requires nextUpdate."""
    clock_skew: timedelta = timedelta(minutes=5)
    max_ocsp_age: timedelta = timedelta(hours=24)
    max_response_bytes: int = 2 * 1024 * 1024

    def __post_init__(self) -> None:
        if not timedelta(0) <= self.clock_skew <= timedelta(minutes=10) or not timedelta(0) < self.max_ocsp_age <= timedelta(days=7) or not 0 < self.max_response_bytes <= 16 * 1024 * 1024:
            raise ValueError("Chính sách thời gian/kích thước thu hồi không hợp lệ.")


def extract_sources(cert: x509.Certificate) -> RevocationSources:
    """Read OCSP AIA and CRL Distribution Points, without following any URL."""
    urls: list[str] = []
    crls: list[str] = []
    scoped = False
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
        urls = [item.access_location.value for item in aia if item.access_method == AuthorityInformationAccessOID.OCSP and isinstance(item.access_location, x509.UniformResourceIdentifier)]
    except x509.ExtensionNotFound:
        pass
    try:
        points = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        for point in points:
            if point.reasons is not None or point.crl_issuer is not None or point.relative_name is not None:
                scoped = True
            crls.extend(name.value for name in point.full_name or () if isinstance(name, x509.UniformResourceIdentifier))
    except x509.ExtensionNotFound:
        pass
    return RevocationSources(tuple(dict.fromkeys(urls)), tuple(dict.fromkeys(crls)), scoped)


def _extension(obj: object, kind: type) -> object | None:
    try:
        return obj.extensions.get_extension_for_class(kind).value
    except x509.ExtensionNotFound:
        return None


def _clock(now: datetime | None) -> datetime:
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("Thời điểm kiểm tra phải có múi giờ.")
    return now.astimezone(timezone.utc)


def _issuer(cert: x509.Certificate, issuer: x509.Certificate, now: datetime, trusted: bool) -> None:
    if not trusted:
        raise ValueError("Chưa xác minh issuer qua trust store độc lập.")
    constraints = _extension(issuer, x509.BasicConstraints)
    usage = _extension(issuer, x509.KeyUsage)
    if constraints is None or not constraints.ca or (usage is not None and not usage.key_cert_sign):
        raise ValueError("Issuer không có quyền CA cấp chứng thư.")
    if not issuer.not_valid_before_utc <= now <= issuer.not_valid_after_utc:
        raise ValueError("Issuer không còn trong thời hạn hiệu lực.")
    if not verify_signature(cert, issuer):
        raise ValueError("Issuer hoặc chữ ký chứng thư mục tiêu không khớp.")


def _fresh(start: datetime, end: datetime | None, now: datetime, policy: ValidationPolicy, *, is_crl: bool = False) -> None:
    if start > now + policy.clock_skew or (end is not None and (end < start or now > end + policy.clock_skew)):
        raise ValueError("Phản hồi chưa có hiệu lực hoặc đã hết hạn.")
    if is_crl and end is None:
        raise ValueError("CRL thiếu nextUpdate; không đủ bằng chứng còn hiệu lực.")
    if not is_crl and now - start > policy.max_ocsp_age + policy.clock_skew:
        raise ValueError("Phản hồi OCSP quá cũ so với chính sách freshness.")


def _verify_ocsp_signature(response: ocsp.OCSPResponse, signer: x509.Certificate) -> None:
    """Verify supported exact signature schemes; never guess RSA-PSS parameters."""
    key = signer.public_key()
    oid = response.signature_algorithm_oid.dotted_string
    digest = response.signature_hash_algorithm
    if digest is not None and digest.name in ("md5", "sha1"):
        raise ValueError("Chữ ký phản hồi dùng thuật toán băm yếu, không được chấp nhận.")
    if isinstance(key, rsa.RSAPublicKey) and oid in ("1.2.840.113549.1.1.11", "1.2.840.113549.1.1.12", "1.2.840.113549.1.1.13"):
        key.verify(response.signature, response.tbs_response_bytes, padding.PKCS1v15(), digest)
    elif isinstance(key, ec.EllipticCurvePublicKey) and oid in ("1.2.840.10045.4.3.2", "1.2.840.10045.4.3.3", "1.2.840.10045.4.3.4"):
        key.verify(response.signature, response.tbs_response_bytes, ec.ECDSA(digest))
    elif isinstance(key, dsa.DSAPublicKey) and oid in ("2.16.840.1.101.3.4.3.2",):
        key.verify(response.signature, response.tbs_response_bytes, digest)
    elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)) and oid in ("1.3.101.112", "1.3.101.113"):
        key.verify(response.signature, response.tbs_response_bytes)
    else:
        raise ValueError("Thuật toán chữ ký OCSP chưa được hỗ trợ; không suy đoán tham số.")


def _responder_matches(response: ocsp.OCSPResponse, signer: x509.Certificate) -> bool:
    if response.responder_name is not None:
        return response.responder_name == signer.subject
    return response.responder_key_hash == x509.SubjectKeyIdentifier.from_public_key(signer.public_key()).digest


def validate_ocsp(data: bytes, cert: x509.Certificate, issuer: x509.Certificate, *, issuer_trusted: bool = False, now: datetime | None = None, source: str = "offline", policy: ValidationPolicy = ValidationPolicy(), expected_nonce: bytes | None = None) -> RevocationEvidence:
    """Validate signed target CertID, authorized signer and response freshness."""
    fingerprint = hashlib.sha256(data).hexdigest()
    signature_ok = issuer_ok = False
    start = end = revoked = None
    try:
        clock = _clock(now)
        _issuer(cert, issuer, clock, issuer_trusted)
        issuer_ok = True
        if len(data) > policy.max_response_bytes:
            raise ValueError("Phản hồi OCSP vượt giới hạn kích thước.")
        response = ocsp.load_der_ocsp_response(data)
        if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            raise ValueError(f"Nguồn OCSP trả lỗi giao thức: {response.response_status.name}.")
        if any(ext.critical for ext in response.extensions):
            raise ValueError("OCSP chứa extension critical chưa được hỗ trợ.")
        entries = list(response.responses)
        matches = []
        for entry in entries:
            request = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, entry.hash_algorithm).build()
            if entry.serial_number == request.serial_number and entry.issuer_name_hash == request.issuer_name_hash and entry.issuer_key_hash == request.issuer_key_hash:
                matches.append(entry)
        if len(matches) != 1:
            raise ValueError("OCSP CertID không khớp duy nhất với chứng thư và issuer.")
        # cryptography exposes single_extensions only for a single-entry response.
        if len(entries) != 1:
            raise ValueError("OCSP nhiều SingleResponse chưa được hỗ trợ kiểm tra extension đầy đủ.")
        if any(ext.critical for ext in response.single_extensions):
            raise ValueError("SingleResponse chứa extension critical chưa được hỗ trợ.")
        candidates = [issuer, *response.certificates]
        candidates = list({c.fingerprint(hashes.SHA256()): c for c in candidates}.values())
        signers = [c for c in candidates if _responder_matches(response, c)]
        if len(signers) != 1:
            raise ValueError("Không xác định duy nhất chứng thư ký phản hồi OCSP.")
        signer = signers[0]
        delegated = signer != issuer
        signer_usage = _extension(signer, x509.KeyUsage)
        if signer_usage is not None and not signer_usage.digital_signature:
            raise ValueError("Chứng thư ký phản hồi không có quyền digitalSignature.")
        if delegated:
            if not verify_signature(signer, issuer) or not signer.not_valid_before_utc <= clock <= signer.not_valid_after_utc:
                raise ValueError("OCSP responder không được issuer trực tiếp cấp hoặc hết hạn.")
            eku, usage = _extension(signer, x509.ExtendedKeyUsage), _extension(signer, x509.KeyUsage)
            if eku is None or ExtendedKeyUsageOID.OCSP_SIGNING not in eku or (usage is not None and not usage.digital_signature):
                raise ValueError("OCSP responder thiếu quyền ký OCSP.")
            if any(ext.critical and not isinstance(ext.value, (x509.BasicConstraints, x509.KeyUsage, x509.ExtendedKeyUsage)) for ext in signer.extensions):
                raise ValueError("OCSP responder có ràng buộc critical chưa hỗ trợ.")
        _verify_ocsp_signature(response, signer)
        signature_ok = True
        if expected_nonce is not None:
            if not 1 <= len(expected_nonce) <= 32:
                raise ValueError("OCSP nonce phải có 1–32 bytes.")
            response_nonce = _extension(response, x509.OCSPNonce)
            if response_nonce is None:
                return RevocationEvidence("OCSP", "UNKNOWN", "Responder không trả nonce được yêu cầu; không đủ cơ sở xác nhận freshness bằng nonce.", source, fingerprint, True, True)
            if not secrets.compare_digest(response_nonce.nonce, expected_nonce):
                raise ValueError("OCSP nonce phản hồi không khớp request.")
        entry = matches[0]
        start, end = entry.this_update_utc, entry.next_update_utc
        _fresh(start, end, clock, policy)
        produced = response.produced_at_utc
        if produced > clock + policy.clock_skew or produced < start - policy.clock_skew or not signer.not_valid_before_utc <= produced <= signer.not_valid_after_utc:
            raise ValueError("producedAt không hợp lệ hoặc ngoài hiệu lực chứng thư ký.")
        if delegated and _extension(signer, x509.OCSPNoCheck) is None:
            return RevocationEvidence("OCSP", "UNKNOWN", "Đã xác minh chữ ký nhưng chưa kiểm tra thu hồi của responder được ủy quyền (thiếu OCSPNoCheck).", source, fingerprint, True, True, start.isoformat(), end.isoformat() if end else None)
        status = entry.certificate_status.name
        if status == "REVOKED":
            revoked = entry.revocation_time_utc
            if revoked is None or revoked > clock + policy.clock_skew:
                raise ValueError("Thời điểm thu hồi không hợp lệ.")
        reason = {"GOOD": "OCSP có chữ ký hợp lệ xác nhận chứng thư chưa bị thu hồi tại thời điểm phản hồi.", "REVOKED": "OCSP có chữ ký hợp lệ xác nhận chứng thư đã bị thu hồi.", "UNKNOWN": "OCSP có chữ ký hợp lệ nhưng nguồn không xác định được trạng thái chứng thư."}[status]
        return RevocationEvidence("OCSP", status, reason, source, fingerprint, True, True, start.isoformat(), end.isoformat() if end else None, revoked.isoformat() if revoked else None)
    except Exception as exc:
        return RevocationEvidence("OCSP", "ERROR", "Không chấp nhận bằng chứng OCSP: " + (str(exc) or type(exc).__name__), source, fingerprint, signature_ok, issuer_ok, start.isoformat() if start else None, end.isoformat() if end else None)


def validate_crl(data: bytes, cert: x509.Certificate, issuer: x509.Certificate, *, issuer_trusted: bool = False, now: datetime | None = None, source: str = "offline", policy: ValidationPolicy = ValidationPolicy()) -> RevocationEvidence:
    """Accept only complete direct issuer CRLs; unsupported scopes never imply GOOD."""
    fingerprint = hashlib.sha256(data).hexdigest()
    signature_ok = issuer_ok = False
    start = end = None
    try:
        clock = _clock(now)
        _issuer(cert, issuer, clock, issuer_trusted)
        issuer_ok = True
        if len(data) > policy.max_response_bytes:
            raise ValueError("CRL vượt giới hạn kích thước.")
        crl = x509.load_pem_x509_crl(data) if data.startswith(b"-----BEGIN") else x509.load_der_x509_crl(data)
        if crl.issuer != issuer.subject:
            raise ValueError("Issuer của CRL không khớp CA cấp chứng thư.")
        usage = _extension(issuer, x509.KeyUsage)
        if usage is not None and not usage.crl_sign:
            raise ValueError("Issuer không có quyền ký CRL.")
        aki = _extension(crl, x509.AuthorityKeyIdentifier)
        ski = _extension(issuer, x509.SubjectKeyIdentifier) or x509.SubjectKeyIdentifier.from_public_key(issuer.public_key())
        if aki is not None and ((aki.key_identifier is not None and aki.key_identifier != ski.digest) or (aki.authority_cert_serial_number is not None and aki.authority_cert_serial_number != issuer.serial_number) or (aki.authority_cert_issuer is not None and x509.DirectoryName(issuer.issuer) not in aki.authority_cert_issuer)):
            raise ValueError("AuthorityKeyIdentifier của CRL không khớp issuer.")
        if crl.signature_hash_algorithm is not None and crl.signature_hash_algorithm.name in ("md5", "sha1"):
            raise ValueError("Chữ ký CRL dùng thuật toán băm yếu.")
        if not crl.is_signature_valid(issuer.public_key()):
            raise ValueError("Chữ ký CRL không hợp lệ.")
        signature_ok = True
        start, end = crl.last_update_utc, crl.next_update_utc
        _fresh(start, end, clock, policy, is_crl=True)
        idp = _extension(crl, x509.IssuingDistributionPoint)
        unsupported = _extension(crl, x509.DeltaCRLIndicator) is not None or extract_sources(cert).unsupported_crl_scope
        if idp is not None:
            constraints = _extension(cert, x509.BasicConstraints)
            is_ca = constraints is not None and constraints.ca
            if idp.only_contains_user_certs and is_ca or idp.only_contains_ca_certs and not is_ca:
                raise ValueError("Phạm vi CRL không áp dụng cho loại chứng thư mục tiêu.")
            if idp.indirect_crl or idp.only_some_reasons is not None or idp.only_contains_attribute_certs or idp.relative_name is not None:
                unsupported = True
            if idp.full_name is not None:
                advertised = set(extract_sources(cert).crl_urls)
                named = {name.value for name in idp.full_name if isinstance(name, x509.UniformResourceIdentifier)}
                if not named.intersection(advertised):
                    raise ValueError("IssuingDistributionPoint của CRL không khớp điểm phân phối của chứng thư.")
        if unsupported:
            return RevocationEvidence("CRL", "UNKNOWN", "CRL delta, gián tiếp hoặc giới hạn phạm vi chưa được hỗ trợ; không suy ra GOOD từ việc thiếu số sê-ri.", source, fingerprint, True, True, start.isoformat(), end.isoformat())
        if any(ext.critical and not isinstance(ext.value, (x509.AuthorityKeyIdentifier, x509.CRLNumber, x509.IssuingDistributionPoint)) for ext in crl.extensions):
            raise ValueError("CRL chứa extension critical chưa được hỗ trợ.")
        serials: set[int] = set()
        for item in crl:
            if item.serial_number in serials:
                raise ValueError("CRL có số sê-ri trùng lặp, không xác định duy nhất trạng thái.")
            serials.add(item.serial_number)
            if _extension(item, x509.CertificateIssuer) is not None or any(ext.critical for ext in item.extensions):
                raise ValueError("CRL entry chứa phạm vi hoặc extension critical chưa được hỗ trợ.")
        entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        if entry is not None:
            revoked = entry.revocation_date_utc
            if revoked > clock + policy.clock_skew:
                raise ValueError("Thời điểm thu hồi CRL nằm trong tương lai.")
            reason = _extension(entry, x509.CRLReason)
            if reason is not None and reason.reason == x509.ReasonFlags.remove_from_crl:
                raise ValueError("removeFromCRL không hợp lệ trong CRL đầy đủ.")
            return RevocationEvidence("CRL", "REVOKED", "Số sê-ri có trong CRL đầy đủ, còn hiệu lực và có chữ ký hợp lệ.", source, fingerprint, True, True, start.isoformat(), end.isoformat(), revoked.isoformat())
        return RevocationEvidence("CRL", "GOOD", "Số sê-ri không có trong CRL đầy đủ của issuer; chữ ký và thời hạn hợp lệ.", source, fingerprint, True, True, start.isoformat(), end.isoformat())
    except Exception as exc:
        return RevocationEvidence("CRL", "ERROR", "Không chấp nhận bằng chứng CRL: " + (str(exc) or type(exc).__name__), source, fingerprint, signature_ok, issuer_ok, start.isoformat() if start else None, end.isoformat() if end else None)


def check_revocation(cert: x509.Certificate, issuer: x509.Certificate | None = None, *, issuer_trusted: bool = False, now: datetime | None = None, online: bool = False, fixtures: Mapping[str, tuple[bytes, ...]] | None = None, fetcher: Callable = fetch_bytes, network_policy: FetchPolicy = FetchPolicy(), policy: ValidationPolicy = ValidationPolicy(), max_sources: int = 4, use_nonce: bool = False) -> RevocationResult:
    """Offline by default. Fetch at most four allowlisted-method sources when opted in.

    A valid REVOKED dominates; contradictory/error evidence prevents aggregate GOOD.
    Calling without data returns NOT_CHECKED, never an implicit safety conclusion.
    """
    if not isinstance(max_sources, int) or not 1 <= max_sources <= 4:
        raise ValueError("Số nguồn kiểm tra phải trong khoảng 1–4.")
    sources = extract_sources(cert)
    fixtures = fixtures or {}
    if any(method not in ("OCSP", "CRL") for method in fixtures):
        raise ValueError("Chỉ hỗ trợ fixture OCSP và CRL.")
    if sum(len(items) for items in fixtures.values()) > max_sources:
        raise ValueError("Số fixture vượt giới hạn nguồn.")
    if not online and not any(fixtures.values()):
        return RevocationResult("NOT_CHECKED", "Chưa kiểm tra thu hồi: chế độ offline không có dữ liệu OCSP/CRL. Không suy ra chứng thư an toàn.")
    if issuer is None or not issuer_trusted:
        return RevocationResult("NOT_CHECKED", "Chưa kiểm tra thu hồi: thiếu issuer đã được xác minh qua trust store độc lập.")
    evidence: list[RevocationEvidence] = []
    jobs = [(method, "offline", data) for method, items in fixtures.items() for data in items]
    if online:
        jobs += [("OCSP", url, None) for url in sources.ocsp_urls] + [("CRL", url, None) for url in sources.crl_urls]
    for method, url, data in jobs[:max_sources]:
        try:
            nonce = None
            if data is None:
                body = None
                if method == "OCSP":
                    builder = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA1())
                    if use_nonce:
                        nonce = secrets.token_bytes(32)
                        builder = builder.add_extension(x509.OCSPNonce(nonce), False)
                    body = builder.build().public_bytes(serialization.Encoding.DER)
                data = fetcher(url, body=body, policy=network_policy)
            validator = validate_ocsp if method == "OCSP" else validate_crl
            evidence.append(validator(data, cert, issuer, issuer_trusted=True, now=now, source=url, policy=policy, **({"expected_nonce": nonce} if nonce is not None else {})))
        except Exception as exc:
            evidence.append(RevocationEvidence(method, "ERROR", "Lỗi truy vấn nguồn thu hồi: " + (str(exc) or type(exc).__name__), url))
    statuses = {item.status for item in evidence}
    status = "REVOKED" if "REVOKED" in statuses else "ERROR" if "ERROR" in statuses else "UNKNOWN" if "UNKNOWN" in statuses else "GOOD" if "GOOD" in statuses else "NOT_CHECKED"
    reason = {"REVOKED": "Có bằng chứng hợp lệ xác nhận chứng thư đã bị thu hồi.", "ERROR": "Có lỗi kiểm tra; không đủ cơ sở xác nhận trạng thái chưa bị thu hồi.", "UNKNOWN": "Nguồn dữ liệu chưa xác định đầy đủ trạng thái thu hồi.", "GOOD": "Có bằng chứng thu hồi hợp lệ tại thời điểm kiểm tra; không phải kết luận website an toàn.", "NOT_CHECKED": "Chưa kiểm tra: chứng thư không cung cấp nguồn OCSP/CRL phù hợp."}[status]
    return RevocationResult(status, reason, tuple(evidence))
