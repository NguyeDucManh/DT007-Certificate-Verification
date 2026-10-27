"""Đọc metadata SCT nhúng trong certificate, không verify chữ ký SCT."""

import base64
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm


def _algorithm_name(sct: object, attribute: str) -> str | None:
    """Preserve metadata/wire bytes even if cryptography cannot name a scheme."""
    try:
        return getattr(sct, attribute).name
    except (UnsupportedAlgorithm, ValueError, AttributeError):
        return None


def _wire_fallback(certificate: x509.Certificate) -> tuple["SCTRecord", ...]:
    """Decode bounded v1 wire independently if the library rejects an algorithm."""
    from src.ct_signed_input import tlvs
    top = tlvs(certificate.tbs_certificate_bytes)
    if len(top) != 1 or top[0][0] != 48:
        raise ValueError("TBSCertificate không hợp lệ.")
    records = []
    seen = set()
    for tag,payload,_ in tlvs(top[0][1]):
        if tag != 163:
            continue
        seq = tlvs(payload)
        if len(seq) != 1 or seq[0][0] != 48:
            raise ValueError("Extensions không hợp lệ.")
        for ext_tag,ext_payload,_ in tlvs(seq[0][1]):
            fields=tlvs(ext_payload)
            if ext_tag != 48 or len(fields)<2 or fields[0][0] != 6 or fields[-1][0] != 4:
                raise ValueError("Extension không hợp lệ.")
            oid=fields[0][1]
            if oid in seen:
                raise ValueError("Extension trùng lặp.")
            seen.add(oid)
            if oid not in (bytes.fromhex("2b06010401d679020402"),bytes.fromhex("2b06010401d679020405")):
                continue
            inner=tlvs(fields[-1][1])
            if len(inner)!=1 or inner[0][0]!=4:
                raise ValueError("SCT list thiếu OCTET STRING.")
            wire=inner[0][1]
            if len(wire)<2 or int.from_bytes(wire[:2],"big") != len(wire)-2:
                raise ValueError("SCT list length không hợp lệ.")
            offset=2
            while offset<len(wire):
                if offset+2>len(wire):
                    raise ValueError("SCT bị cắt ngắn.")
                size=int.from_bytes(wire[offset:offset+2],"big")
                offset+=2
                raw=wire[offset:offset+size]
                offset+=size
                if len(raw)!=size or size<47 or raw[0]!=0:
                    raise ValueError("SCT version/length chưa hỗ trợ hoặc không hợp lệ.")
                ext_size=int.from_bytes(raw[41:43],"big")
                pos=43+ext_size
                if pos+4>len(raw) or pos+4+int.from_bytes(raw[pos+2:pos+4],"big")!=len(raw):
                    raise ValueError("SCT signature length không hợp lệ.")
                timestamp=datetime(1970,1,1,tzinfo=timezone.utc)+timedelta(milliseconds=int.from_bytes(raw[33:41],"big"))
                records.append(SCTRecord(base64.b64encode(raw[1:33]).decode("ascii"),timestamp,"v1",raw[43:pos],raw[pos+4:],
                    {2:"sha1",4:"sha256",5:"sha384",6:"sha512"}.get(raw[pos]),{1:"RSA",2:"DSA",3:"ECDSA"}.get(raw[pos+1]),
                    "PRE_CERTIFICATE" if oid[-1]==2 else "X509_CERTIFICATE"))
    return tuple(records)


@dataclass(frozen=True)
class SCTRecord:
    """Log ID Base64 tương thích Google list, timestamp UTC và version."""

    log_id: str
    timestamp: datetime
    version: str
    extensions: bytes = b""
    signature: bytes = b""
    hash_algorithm: str | None = None
    signature_algorithm: str | None = None
    entry_type: str | None = None


@dataclass(frozen=True)
class SCTParseResult:
    """SCT metadata và lỗi parse; SCT thiếu không phải exception."""

    scts: tuple[SCTRecord, ...]
    errors: tuple[str, ...] = ()

    @property
    def status(self) -> str:
        """Phân biệt parse lỗi, không có SCT và có metadata."""
        return "WARNING" if self.errors else "PASS" if self.scts else "NO_SCT"


def parse_scts(certificate: x509.Certificate) -> SCTParseResult:
    """Đọc SCT extension pre-certificate/certificate; xử lý dữ liệu lỗi an toàn.

    Không thu thập SCT qua TLS extension hoặc OCSP; không xác minh log signature
    hay inclusion proof. Log matching không chứng minh log đã ghi certificate.
    """
    records: list[SCTRecord] = []
    errors: list[str] = []
    try:
        extensions = certificate.extensions
        for extension_class in (x509.PrecertificateSignedCertificateTimestamps, x509.SignedCertificateTimestamps):
            try:
                extension = extensions.get_extension_for_class(extension_class).value
            except x509.ExtensionNotFound:
                continue
            for sct in extension:
                try:
                    if len(sct.log_id) != 32:
                        raise ValueError("log_id phải có 32 bytes")
                    timestamp = sct.timestamp
                    # Cryptography SCT timestamp được định nghĩa là UTC, có thể naive.
                    timestamp = timestamp.replace(tzinfo=timezone.utc) if timestamp.tzinfo is None else timestamp.astimezone(timezone.utc)
                    records.append(SCTRecord(base64.b64encode(sct.log_id).decode("ascii"), timestamp, sct.version.name,
                        sct.extension_bytes, sct.signature, _algorithm_name(sct,"signature_hash_algorithm"),
                        _algorithm_name(sct,"signature_algorithm"), sct.entry_type.name))
                except (ValueError, TypeError, AttributeError, OverflowError) as exc:
                    errors.append(f"Malformed SCT: {exc}")
    except (ValueError, TypeError, x509.DuplicateExtension, UnsupportedAlgorithm) as exc:
        errors.append(f"Không thể parse SCT extension: {exc}")
        try:
            records=list(_wire_fallback(certificate))
        except (ValueError, TypeError, OverflowError) as fallback_error:
            errors.append(f"Không thể đọc SCT wire data: {fallback_error}")
    return SCTParseResult(tuple(records), tuple(errors))
