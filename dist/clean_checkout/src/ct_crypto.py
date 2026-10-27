"""RFC 6962 v1 cryptographic primitives, separate from metadata policy.

Trusted SPKI must be supplied independently. No implicit trust in dataset keys.
Precertificate TBSCertificate must be supplied exactly; never guessed from a leaf.
"""
import base64
from dataclasses import dataclass
import hashlib
from datetime import datetime, timezone
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from src.sct_parser import SCTRecord


@dataclass(frozen=True)
class CryptoEvidence:
    """Cryptographic status does not imply inclusion or metadata acceptance."""
    status: str
    reason: str
    signed_data_sha256: str | None = None


def signed_entry(sct: SCTRecord, certificate_der: bytes | None, *, precertificate_tbs: bytes | None = None, issuer_key_hash: bytes | None = None) -> bytes:
    """Encode v1 CertificateTimestamp (version/signature_type/timestamp/entry)."""
    if sct.timestamp.tzinfo is None or sct.timestamp.utcoffset() is None:
        raise ValueError("SCT timestamp thiếu múi giờ.")
    delta = sct.timestamp.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    if delta.microseconds % 1000:
        raise ValueError("SCT timestamp không biểu diễn chính xác theo millisecond.")
    timestamp = (delta.days * 86400 + delta.seconds) * 1000 + delta.microseconds // 1000
    if sct.entry_type == "X509_CERTIFICATE":
        if not certificate_der:
            raise ValueError("Thiếu DER chứng thư X.509 được log ký.")
        x509.load_der_x509_certificate(certificate_der)
        entry = b"\x00\x00" + len(certificate_der).to_bytes(3, "big") + certificate_der
    elif sct.entry_type == "PRE_CERTIFICATE":
        if not precertificate_tbs or issuer_key_hash is None or len(issuer_key_hash) != 32:
            raise ValueError("Thiếu TBSCertificate precertificate chính xác và hash khóa issuer; không suy đoán từ chứng thư cuối.")
        entry = b"\x00\x01" + issuer_key_hash + len(precertificate_tbs).to_bytes(3, "big") + precertificate_tbs
    else:
        raise NotImplementedError("Loại signed entry chưa được hỗ trợ.")
    return b"\x00\x00" + timestamp.to_bytes(8, "big") + entry + len(sct.extensions).to_bytes(2, "big") + sct.extensions


def _verify(key_der: bytes, signature: bytes, data: bytes, algorithm: str | None, digest: str | None) -> None:
    key = serialization.load_der_public_key(key_der)
    if digest != "sha256":
        raise NotImplementedError("Chỉ hỗ trợ chữ ký CT v1 SHA256.")
    if isinstance(key, ec.EllipticCurvePublicKey) and algorithm == "ECDSA":
        key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    elif isinstance(key, rsa.RSAPublicKey) and algorithm == "RSA":
        key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
    else:
        raise NotImplementedError("Khóa hoặc thuật toán CT chưa hỗ trợ.")


def verify_sct(sct: SCTRecord, certificate_der: bytes | None, trusted_keys: dict[str, bytes], *, precertificate_tbs: bytes | None = None, issuer_key_hash: bytes | None = None) -> CryptoEvidence:
    """Verify only when trusted key and exact signed input are present."""
    if sct.version != "v1":
        return CryptoEvidence("UNSUPPORTED", "Chỉ hỗ trợ SCT v1 theo RFC 6962.")
    if sct.log_id not in trusted_keys:
        return CryptoEvidence("NOT_VERIFIED", "Chưa có khóa CT Log được tin cậy độc lập cho Log ID này.")
    if not sct.signature:
        return CryptoEvidence("NOT_VERIFIED", "Thiếu chữ ký SCT wire data.")
    try:
        key = trusted_keys[sct.log_id]
        if base64.b64encode(hashlib.sha256(key).digest()).decode("ascii") != sct.log_id:
            return CryptoEvidence("INVALID", "Hash SPKI không khớp Log ID.")
        try:
            data = signed_entry(sct, certificate_der, precertificate_tbs=precertificate_tbs, issuer_key_hash=issuer_key_hash)
        except ValueError as exc:
            return CryptoEvidence("NOT_VERIFIED", str(exc))
        fingerprint = hashlib.sha256(data).hexdigest()
        _verify(key, sct.signature, data, sct.signature_algorithm, sct.hash_algorithm)
        return CryptoEvidence("VALID", "Chữ ký SCT hợp lệ với khóa log tin cậy; chưa chứng minh inclusion.", fingerprint)
    except InvalidSignature:
        return CryptoEvidence("INVALID", "Chữ ký SCT không hợp lệ.")
    except NotImplementedError as exc:
        return CryptoEvidence("UNSUPPORTED", str(exc))
    except Exception as exc:
        return CryptoEvidence("ERROR", "Không xác minh được SCT: " + str(exc))


def verify_inclusion(leaf: bytes, index: int, size: int, path: tuple[bytes, ...], root: bytes) -> bool:
    """RFC 6962 audit path, including unbalanced trees; caller must authenticate STH."""
    if not 0 <= index < size or len(root) != 32 or len(path) > 64 or any(len(p) != 32 for p in path):
        return False
    node = hashlib.sha256(b"\x00" + leaf).digest()
    fn, sn = index, size - 1
    for sibling in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            node = hashlib.sha256(b"\x01" + sibling + node).digest()
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            node = hashlib.sha256(b"\x01" + node + sibling).digest()
        fn >>= 1
        sn >>= 1
    return sn == 0 and node == root


def verify_sth(key_der: bytes, timestamp_ms: int, tree_size: int, root: bytes, signature: bytes, algorithm: str = "ECDSA") -> CryptoEvidence:
    """Authenticate a v1 Signed Tree Head; freshness/consistency are separate."""
    try:
        if len(root) != 32 or tree_size < 1:
            raise ValueError("STH không hợp lệ.")
        data = b"\x00\x01" + timestamp_ms.to_bytes(8, "big") + tree_size.to_bytes(8, "big") + root
        _verify(key_der, signature, data, algorithm, "sha256")
        return CryptoEvidence("VALID", "Chữ ký STH hợp lệ; chưa kiểm tra freshness/consistency.")
    except InvalidSignature:
        return CryptoEvidence("INVALID", "Chữ ký STH không hợp lệ.")
    except NotImplementedError as exc:
        return CryptoEvidence("UNSUPPORTED", str(exc))
    except Exception as exc:
        return CryptoEvidence("ERROR", str(exc))


def verify_consistency(first: int, second: int, old_root: bytes, new_root: bytes, path: tuple[bytes, ...]) -> bool:
    """RFC6962 prefix consistency proof for nonempty authenticated checkpoints."""
    if not 0 < first <= second or len(old_root) != 32 or len(new_root) != 32 or len(path) > 64 or any(len(p) != 32 for p in path):
        return False
    if first == second:
        return not path and old_root == new_root
    fn, sn = first-1, second-1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    if fn == 0:
        old = new = old_root
    else:
        if not path:
            return False
        old = new = path[0]
        path = path[1:]
    for sibling in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            old = hashlib.sha256(b"\x01"+sibling+old).digest()
            new = hashlib.sha256(b"\x01"+sibling+new).digest()
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            new = hashlib.sha256(b"\x01"+new+sibling).digest()
        fn >>= 1
        sn >>= 1
    return sn == 0 and old == old_root and new == new_root
