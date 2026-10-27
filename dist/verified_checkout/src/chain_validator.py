"""Xác minh chain có thứ tự, chữ ký thật, CA constraints và trust anchor."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID
from OpenSSL import crypto

from src.validity_checker import check_validity


@dataclass(frozen=True)
class ChainResult:
    """Kết quả chi tiết cho chuỗi leaf -> CA -> trust anchor."""

    certificates: tuple[x509.Certificate, ...]
    issuer_subject_links: str
    signature_validation: str
    ca_constraints: str
    validity: str
    trust: str
    status: str
    reasons: tuple[str, ...]
    self_signed_leaf: bool = False
    trust_anchor: x509.Certificate | None = None
    peer_certificates: tuple[x509.Certificate, ...] | None = None
    tls_usage: str = "PASS"


def verify_signature(certificate: x509.Certificate, issuer: x509.Certificate) -> bool:
    """Verify tbsCertificate với tham số chữ ký thật, bao gồm RSA-PSS/SHA-1 cũ.

    Xác minh chữ ký không đồng nghĩa thuật toán được policy cho phép.
    """
    if certificate.issuer != issuer.subject:
        return False
    try:
        key = issuer.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(certificate.signature, certificate.tbs_certificate_bytes,
                       certificate.signature_algorithm_parameters, certificate.signature_hash_algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(certificate.signature, certificate.tbs_certificate_bytes, certificate.signature_algorithm_parameters)
        elif isinstance(key, dsa.DSAPublicKey):
            key.verify(certificate.signature, certificate.tbs_certificate_bytes, certificate.signature_hash_algorithm)
        elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            key.verify(certificate.signature, certificate.tbs_certificate_bytes)
        else:
            return False
        return True
    except (InvalidSignature, ValueError, TypeError, UnsupportedAlgorithm):
        return False


def validate_chain(
    chain: Sequence[x509.Certificate],
    trust_anchors: Sequence[x509.Certificate] = (),
    current_time: datetime | None = None,
    peer_chain: Sequence[x509.Certificate] | None = None,
) -> ChainResult:
    """Kiểm tra chain theo thứ tự và chạy OpenSSL path verification.

    Không tự tin cậy root tự ký; trust_anchors phải được cấp từ nguồn độc lập.
    Không tải AIA, không kiểm tra OCSP/CRL trong giai đoạn này.
    """
    certificates = tuple(chain)
    current_time = datetime.now(timezone.utc) if current_time is None else current_time
    if current_time.tzinfo is None or current_time.utcoffset() is None:
        raise ValueError("current_time phải là datetime timezone-aware.")
    current_time = current_time.astimezone(timezone.utc)
    if not certificates:
        return ChainResult((), "FAIL", "FAIL", "FAIL", "FAIL", "FAIL", "FAIL", ("Certificate chain is empty",))
    # Bổ sung issuer từ store độc lập, không tự tin cậy chứng thư server gửi.
    anchor_fingerprints = {cert.fingerprint(hashes.SHA256()) for cert in trust_anchors}
    if certificates[-1].fingerprint(hashes.SHA256()) not in anchor_fingerprints and trust_anchors:
        try:
            completion_store = crypto.X509Store()
            completion_store.set_flags(crypto.X509StoreFlags.PARTIAL_CHAIN)
            completion_store.set_time(current_time)
            for anchor in trust_anchors:
                completion_store.add_cert(crypto.X509.from_cryptography(anchor))
            built = tuple(cert.to_cryptography() for cert in crypto.X509StoreContext(
                completion_store, crypto.X509.from_cryptography(certificates[0]),
                [crypto.X509.from_cryptography(cert) for cert in certificates[1:]],
            ).get_verified_chain())
            if built[:len(certificates)] == certificates:
                certificates = built
        except (crypto.X509StoreContextError, crypto.Error, ValueError):
            pass  # Kiểm tra bên dưới ghi rõ FAIL nếu đường dẫn chưa hoàn tất.
    reasons: list[str] = []
    links, signatures, constraints, validity, trust = "PASS", "PASS", "PASS", "PASS", "PASS"
    fingerprints = [cert.fingerprint(hashes.SHA256()) for cert in certificates]
    if len(set(fingerprints)) != len(fingerprints):
        links = "FAIL"
        reasons.append("Broken chain: duplicate certificate/cycle")
    leaf = certificates[0]
    self_signed_leaf = leaf.subject == leaf.issuer and verify_signature(leaf, leaf)
    if self_signed_leaf:
        links = "FAIL"
        reasons.append("Self-signed leaf certificate")
    for index, cert in enumerate(certificates):
        result = check_validity(cert, current_time)
        if result.status != "VALID":
            validity = "FAIL"
            reasons.append(f"Certificate #{index + 1} validity: {result.status}")
    for index, (child, issuer) in enumerate(zip(certificates, certificates[1:])):
        if child.issuer != issuer.subject:
            links = "FAIL"
            reasons.append(f"Broken issuer/subject link at certificate #{index + 1}")
        if not verify_signature(child, issuer):
            signatures = "FAIL"
            reasons.append(f"Invalid signature/issuer at certificate #{index + 1}")
    for index, issuer in enumerate(certificates[1:], start=2):
        try:
            ca = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
            if not ca.ca:
                raise ValueError("CA=False")
        except (x509.ExtensionNotFound, ValueError):
            constraints = "FAIL"
            reasons.append(f"Issuer certificate #{index} is not a CA (BasicConstraints)")
        try:
            usage = issuer.extensions.get_extension_for_class(x509.KeyUsage).value
            if not usage.key_cert_sign:
                constraints = "FAIL"
                reasons.append(f"Issuer certificate #{index} lacks keyCertSign")
        except x509.ExtensionNotFound:
            pass
    terminal = certificates[-1]
    # X509StoreContext mặc định kiểm tra mục đích "any", không phải sslserver.
    # Áp dụng các ràng buộc EKU/KU hiện diện bằng API cryptography công khai;
    # không dùng API private của pyOpenSSL hoặc coi extension thiếu là lỗi.
    tls_usage = "PASS"
    permitted_eku = {ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE,
                     x509.ObjectIdentifier("1.3.6.1.4.1.311.10.3.3"),
                     x509.ObjectIdentifier("2.16.840.1.113730.4.1")}
    for index, cert in enumerate(certificates, start=1):
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            if not permitted_eku.intersection(eku):
                tls_usage = "FAIL"
                reasons.append(f"Certificate #{index} EKU does not permit TLS server authentication")
        except x509.ExtensionNotFound:
            pass
    try:
        usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
        if not (usage.digital_signature or usage.key_encipherment or usage.key_agreement):
            tls_usage = "FAIL"
            reasons.append("Leaf KeyUsage does not permit TLS server operation")
    except x509.ExtensionNotFound:
        pass
    anchor_fingerprints = {cert.fingerprint(hashes.SHA256()) for cert in trust_anchors}
    if terminal.fingerprint(hashes.SHA256()) not in anchor_fingerprints:
        trust = "FAIL"
        reasons.append("Missing issuer/trusted root: terminal certificate is not an independent trust anchor")
        if terminal.issuer != terminal.subject:
            links = "FAIL"
    if terminal.subject == terminal.issuer and not verify_signature(terminal, terminal):
        signatures = "FAIL"
        reasons.append("Invalid self-signature of root certificate")
    if len(certificates) < 2:
        links = "FAIL"
        reasons.append("Missing issuer: chain must contain a leaf and CA")
    # OpenSSL bổ sung path length, critical extensions và các ràng buộc X.509.
    if trust == "PASS" and not self_signed_leaf:
        try:
            store = crypto.X509Store()
            # TLS mặc định cho phép kết thúc ở CA được trust store tin cậy trực
            # tiếp dù CA đó không tự ký (ví dụ root cross-signed trên Windows).
            # Chỉ bật khi terminal đã khớp trust_anchors độc lập ở trên.
            store.set_flags(crypto.X509StoreFlags.PARTIAL_CHAIN)
            for anchor in trust_anchors:
                store.add_cert(crypto.X509.from_cryptography(anchor))
            store.set_time(current_time)
            crypto.X509StoreContext(
                store, crypto.X509.from_cryptography(leaf),
                [crypto.X509.from_cryptography(cert) for cert in certificates[1:-1]],
            ).verify_certificate()
        except (crypto.X509StoreContextError, crypto.Error, ValueError) as exc:
            trust = "FAIL"
            reasons.append(f"OpenSSL path verification failed: {exc}")
    if tls_usage == "FAIL":
        trust = "FAIL"
    status = "FAIL" if "FAIL" in (links, signatures, constraints, validity, trust, tls_usage) else "PASS"
    return ChainResult(certificates, links, signatures, constraints, validity, trust, status, tuple(reasons), self_signed_leaf,
                       terminal if trust == 'PASS' else None, tuple(peer_chain) if peer_chain is not None else None, tls_usage)
