"""DER-preserving precertificate reconstruction, RFC6962 section 3.2."""
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ObjectIdentifier
from src.chain_validator import verify_signature


def tlvs(data: bytes) -> list[tuple[int, bytes, bytes]]:
    """Strict single-byte DER tags and definite, minimally encoded lengths."""
    result = []
    offset = 0
    while offset < len(data):
        start = offset
        tag = data[offset]
        offset += 1
        if tag & 31 == 31 or offset >= len(data):
            raise ValueError("DER tag/length không hợp lệ.")
        length = data[offset]
        offset += 1
        if length & 128:
            count = length & 127
            if not 1 <= count <= 4 or offset+count > len(data) or data[offset] == 0:
                raise ValueError("DER length không hợp lệ.")
            length = int.from_bytes(data[offset:offset+count], "big")
            offset += count
            if length < 128:
                raise ValueError("DER length không tối giản.")
        if offset+length > len(data):
            raise ValueError("DER bị cắt ngắn.")
        payload = data[offset:offset+length]
        offset += length
        result.append((tag, payload, data[start:offset]))
    return result


def wrap(tag: int, payload: bytes) -> bytes:
    """Encode canonical DER length while preserving inner bytes."""
    size = len(payload)
    raw = size.to_bytes(max(1, (size.bit_length()+7)//8), "big")
    length = bytes([size]) if size < 128 else bytes([128+len(raw)]) + raw
    return bytes([tag]) + length + payload


def _sequence(data: bytes) -> bytes:
    items = tlvs(data)
    if len(items) != 1 or items[0][0] != 48:
        raise ValueError("Thiếu DER SEQUENCE.")
    return items[0][1]


def _oid(extension: bytes) -> bytes:
    fields = tlvs(_sequence(extension))
    if not fields or fields[0][0] != 6:
        raise ValueError("Extension thiếu OID.")
    return fields[0][1]


SCT_OID = bytes.fromhex("2b06010401d679020402")
POISON_OID = bytes.fromhex("2b06010401d679020403")
AKI_OID = bytes.fromhex("551d23")


def precert_input(cert: x509.Certificate, issuer: x509.Certificate, *, preissuer: x509.Certificate | None = None) -> dict[str, bytes]:
    """Final leaf: remove SCT. Precert: remove poison, rewrite delegated issuer/AKI.

    Issuer must actually sign the final leaf, or certify an authorized preissuer.
    This proves binding, not issuer trust: pipeline verifies its path independently.
    """
    signer = preissuer or issuer
    if not verify_signature(cert, signer):
        raise ValueError("Không xác minh được issuer của signed entry.")
    if preissuer is not None:
        eku = preissuer.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        basic = preissuer.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not basic.ca or ObjectIdentifier("1.3.6.1.4.1.11129.2.4.4") not in eku or not verify_signature(preissuer, issuer):
            raise ValueError("Preissuer không có quyền hoặc không được final issuer trực tiếp cấp.")
        try:
            if not preissuer.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
                raise ValueError("Preissuer không có quyền keyCertSign.")
        except x509.ExtensionNotFound:
            pass
    fields = tlvs(_sequence(cert.tbs_certificate_bytes))
    extension_indices = [i for i, item in enumerate(fields) if item[0] == 163]
    if len(extension_indices) != 1:
        raise ValueError("Không xác định duy nhất extensions của precertificate.")
    idx = extension_indices[0]
    entries = tlvs(_sequence(fields[idx][1]))
    removed = [e for e in entries if _oid(e[2]) in (SCT_OID, POISON_OID)]
    if len(removed) != 1:
        raise ValueError("Cần đúng một SCT hoặc poison extension.")
    oid = "1.3.6.1.4.1.11129.2.4.3" if _oid(removed[0][2]) == POISON_OID else "1.3.6.1.4.1.11129.2.4.2"
    actual = cert.extensions.get_extension_for_oid(ObjectIdentifier(oid))
    if actual.critical != (oid.endswith(".3")):
        raise ValueError("Poison phải critical, SCT extension phải noncritical.")
    entries = [e[2] for e in entries if _oid(e[2]) not in (SCT_OID, POISON_OID)]
    if preissuer is not None:
        if _oid(removed[0][2]) != POISON_OID:
            raise ValueError("Luồng preissuer yêu cầu precertificate poison, không sửa final leaf.")
        issuer_index = 3 if fields[0][0] == 160 else 2
        fields[issuer_index] = (48, b"", issuer.subject.public_bytes())
        pre_fields = tlvs(_sequence(preissuer.tbs_certificate_bytes))
        pre_extensions = [e for f in pre_fields if f[0] == 163 for e in tlvs(_sequence(f[1]))]
        aki = [e[2] for e in pre_extensions if _oid(e[2]) == AKI_OID]
        if any(_oid(e) == AKI_OID for e in entries):
            if len(aki) != 1:
                raise ValueError("Preissuer thiếu AKI cần thiết để dựng signed entry.")
            entries = [aki[0] if _oid(e) == AKI_OID else e for e in entries]
    replacement = wrap(163, wrap(48, b"".join(entries))) if entries else b""
    tbs = wrap(48, b"".join(replacement if i == idx else field[2] for i, field in enumerate(fields)))
    spki = issuer.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(spki)
    return {"precertificate_tbs": tbs, "issuer_key_hash": digest.finalize()}
