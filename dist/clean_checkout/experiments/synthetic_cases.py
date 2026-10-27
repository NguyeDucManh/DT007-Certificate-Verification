"""Tạo chứng thư và chạy negative cases offline bằng validators thật.

Không import fixtures từ pytest; không dùng dataset tổng hợp thay dữ liệu Google.
Chỉ fixtures CT local sử dụng chữ ký SCT placeholder vì scope là metadata matching.
"""

import base64
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import hashlib
from typing import Any
import warnings

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtensionOID, NameOID
from OpenSSL import crypto

from src.algorithm_policy import evaluate_algorithm
from src.chain_validator import validate_chain
from src.crypto_info import get_crypto_info
from src.ct_log_analyzer import analyze_dataset
from src.ct_validator import validate_ct
from src.hostname_validator import validate_hostname
from src.sct_parser import parse_scts
from src.security_evaluator import evaluate_security
from src.validity_checker import check_validity

CASE_TYPES = frozenset({
    "EXPIRED_CERTIFICATE", "NOT_YET_VALID_CERTIFICATE", "HOSTNAME_MISMATCH",
    "RSA_1024", "SHA1_SIGNATURE", "MD5_SIGNATURE", "BROKEN_CHAIN",
    "INVALID_SIGNATURE", "NON_CA_INTERMEDIATE", "SELF_SIGNED_LEAF",
    "UNKNOWN_CT_LOG", "RETIRED_CT_LOG", "SCT_TIMESTAMP_OUTSIDE_INTERVAL", "NO_SCT",
})


class UnsupportedSyntheticCase(RuntimeError):
    """Backend không tạo được fixture; runner ghi SKIPPED và lý do."""


@dataclass(frozen=True)
class SyntheticOutcome:
    """Kết quả thực tế và bằng chứng phát hiện đúng lỗi đang khảo sát."""

    status: str
    reasons: tuple[str, ...]
    detected: bool
    evaluation_scope: str
    generation_method: str
    evidence: dict[str, Any] = field(default_factory=dict)


def _sct_extension(log_id: bytes, timestamp: datetime) -> x509.UnrecognizedExtension:
    """Encode SCT v1 wire format trong DER OCTET STRING; signature là placeholder."""
    signature = b"\x30\x06\x02\x01\x01\x02\x01\x01"
    sct = (b"\x00" + log_id + int(timestamp.timestamp() * 1000).to_bytes(8, "big")
           + b"\x00\x00\x04\x03" + len(signature).to_bytes(2, "big") + signature)
    entry = len(sct).to_bytes(2, "big") + sct
    payload = len(entry).to_bytes(2, "big") + entry
    size = len(payload)
    encoded_size = size.to_bytes((size.bit_length() + 7) // 8, "big")
    length = bytes([size]) if size < 128 else bytes([0x80 | len(encoded_size)]) + encoded_size
    return x509.UnrecognizedExtension(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS, b"\x04" + length + payload)


class SyntheticLab:
    """Lab local có root tin cậy riêng và clock cố định, không kết nối mạng."""

    def __init__(self, reference_time: datetime, policy: dict[str, Any]) -> None:
        """Tạo key material dùng chung; thời gian setup được runner đo riêng."""
        if reference_time.tzinfo is None or reference_time.utcoffset() is None:
            raise ValueError("Synthetic reference time phải timezone-aware.")
        self.clock = reference_time
        self.policy = policy
        self.root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.intermediate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DT007 Lab Root")])
        self.intermediate_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DT007 Lab Intermediate")])
        self.leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test")])
        spki = self.root_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        self.log_id = hashlib.sha256(spki).digest()

    def _issue(
        self, subject: x509.Name, issuer: x509.Name, key: rsa.RSAPrivateKey,
        signer: rsa.RSAPrivateKey, *, ca: bool,
        not_before: datetime | None = None, not_after: datetime | None = None,
        sct: x509.UnrecognizedExtension | None = None,
    ) -> x509.Certificate:
        """Tạo certificate có chữ ký thật bằng cryptography."""
        start = self.clock - timedelta(days=30) if not_before is None else not_before
        end = self.clock + timedelta(days=30) if not_after is None else not_after
        builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(start).not_valid_after(end)
                   .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
        if subject == self.leaf_name:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName("example.test")]), critical=False)
        if sct is not None:
            builder = builder.add_extension(sct, critical=False)
        return builder.sign(signer, hashes.SHA256())

    def _legacy_signature(self, certificate: x509.Certificate, digest: str) -> x509.Certificate:
        """Tạo SHA-1/MD5 thật bằng backend OpenSSL; verify signature fixture riêng.

        Cryptography X.509 builder không cho ký SHA-1/MD5. Không fake CryptoInfo.
        Chỉ API legacy này có deprecation warning được capture trong scope local.
        """
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                legacy = crypto.X509.from_cryptography(certificate)
                legacy.sign(crypto.PKey.from_cryptography_key(self.intermediate_key), digest)
                signed = legacy.to_cryptography()
            algorithm = hashes.SHA1() if digest == "sha1" else hashes.MD5()
            self.intermediate_key.public_key().verify(
                signed.signature, signed.tbs_certificate_bytes, padding.PKCS1v15(), algorithm,
            )
            if signed.signature_hash_algorithm.name != digest:
                raise ValueError("Fixture hash không khớp thuật toán yêu cầu.")
            return signed
        except (crypto.Error, ValueError, TypeError, AttributeError, InvalidSignature, UnsupportedAlgorithm) as exc:
            raise UnsupportedSyntheticCase(f"Không tạo/xác minh được RSA/{digest} certificate trên backend này: {exc}") from exc

    def run(self, case_type: str, *, profile: str = 'extended') -> SyntheticOutcome:
        """Mutate một điều kiện đã định nghĩa; không nhận expected_result từ runner."""
        if profile not in ('baseline','extended'):
            raise ValueError('Unknown evaluation profile')
        if case_type not in CASE_TYPES and case_type != 'VALID_CONTROL':
            raise ValueError(f"Unknown synthetic case type: {case_type}")
        root = self._issue(self.root_name, self.root_name, self.root_key, self.root_key, ca=True)
        intermediate = self._issue(self.intermediate_name, self.root_name, self.intermediate_key,
                                   self.root_key, ca=case_type != "NON_CA_INTERMEDIATE")
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=1024) if case_type == "RSA_1024" else self.leaf_key
        sct_time = self.clock - timedelta(hours=1)
        if case_type == "SCT_TIMESTAMP_OUTSIDE_INTERVAL":
            sct_time = self.clock - timedelta(days=10)
        sct_id = hashlib.sha256(b"unlisted DT007 log").digest() if case_type == "UNKNOWN_CT_LOG" else self.log_id
        extension = None if case_type == "NO_SCT" else _sct_extension(sct_id, sct_time)
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Broken Issuer")]) if case_type == "BROKEN_CHAIN" else self.intermediate_name
        signer = self.root_key if case_type == "INVALID_SIGNATURE" else self.intermediate_key
        start = self.clock + timedelta(days=1) if case_type == "NOT_YET_VALID_CERTIFICATE" else self.clock - timedelta(days=30)
        end = self.clock - timedelta(days=1) if case_type == "EXPIRED_CERTIFICATE" else self.clock + timedelta(days=30)
        leaf = self._issue(self.leaf_name, issuer, leaf_key, signer, ca=False, not_before=start, not_after=end, sct=extension)
        if case_type == "SELF_SIGNED_LEAF":
            leaf = self._issue(self.leaf_name, self.leaf_name, leaf_key, leaf_key, ca=False, sct=extension)
        generation = "cryptography X.509; SCT metadata fixture, signatures not verified"
        if case_type in ("SHA1_SIGNATURE", "MD5_SIGNATURE"):
            digest = "sha1" if case_type == "SHA1_SIGNATURE" else "md5"
            leaf = self._legacy_signature(leaf, digest)
            generation = f"cryptography X.509 + pyOpenSSL RSA/{digest}; fixture signature verified"
        # Parse DER lại, đảm bảo validators nhận certificate thực chứ không mock.
        leaf = x509.load_der_x509_certificate(leaf.public_bytes(Encoding.DER))
        crypto_info = get_crypto_info(leaf)
        algorithm = evaluate_algorithm(crypto_info, self.policy)
        evidence: dict[str, Any] = {
            "certificate": {
                "subject": leaf.subject.rfc4514_string(), "issuer": leaf.issuer.rfc4514_string(),
                "serial": str(leaf.serial_number), "sha256": leaf.fingerprint(hashes.SHA256()).hex(),
                "not_before": leaf.not_valid_before_utc.isoformat(), "not_after": leaf.not_valid_after_utc.isoformat(),
                "key_algorithm": crypto_info.public_key_algorithm, "key_size": crypto_info.public_key_size,
                "signature_hash": crypto_info.signature_hash_algorithm,
            },
            "input_type": "Chứng thư X.509 thực được tạo trong RAM; serialize/parse DER lại",
            "modules": ["crypto_info.get_crypto_info", "algorithm_policy.evaluate_algorithm"],
            "mock_used": False,
            "structured_ct": None,
        }
        if case_type in ("RSA_1024", "SHA1_SIGNATURE", "MD5_SIGNATURE"):
            rule = algorithm.key_size if case_type == "RSA_1024" else algorithm.signature_hash
            return SyntheticOutcome(algorithm.status, algorithm.reasons,
                                    rule.status == "FAIL", "Algorithm Policy (isolated)", generation, evidence)
        name = "other.example.test" if case_type == "HOSTNAME_MISMATCH" else "example.test"
        validity = check_validity(leaf, self.clock)
        hostname = validate_hostname(leaf, name)
        chain = validate_chain([leaf] if case_type == "SELF_SIGNED_LEAF" else [leaf, intermediate, root], [root], self.clock)
        if profile == 'baseline':
            evidence['modules'].extend(['validity_checker.check_validity','hostname_validator.validate_hostname',
                                       'chain_validator.validate_chain','security_evaluator.evaluate_security'])
            final = evaluate_security(validity, hostname, chain, algorithm, None, include_ct=False)
            detected = {
                'EXPIRED_CERTIFICATE': validity.status == 'EXPIRED',
                'NOT_YET_VALID_CERTIFICATE': validity.status == 'NOT_YET_VALID',
                'HOSTNAME_MISMATCH': hostname.status == 'FAIL',
                'BROKEN_CHAIN': chain.issuer_subject_links == 'FAIL',
                'INVALID_SIGNATURE': chain.signature_validation == 'FAIL' and leaf.issuer == intermediate.subject,
                'NON_CA_INTERMEDIATE': chain.ca_constraints == 'FAIL',
                'SELF_SIGNED_LEAF': chain.self_signed_leaf and chain.status == 'FAIL',
            }.get(case_type, False)
            return SyntheticOutcome(final.status, final.reasons, bool(detected), 'Baseline without CT (ablation)', generation, evidence)
        retired_at = self.clock - timedelta(days=1)
        log_state = {"retired": {"timestamp": retired_at.isoformat()}} if case_type == "RETIRED_CT_LOG" else {"usable": {"timestamp": (self.clock - timedelta(days=30)).isoformat()}}
        dataset = analyze_dataset({"operators": [{"name": "DT007 Synthetic Operator", "logs": [{
            "log_id": base64.b64encode(self.log_id).decode("ascii"), "description": "Local metadata fixture",
            "mmd": 86400, "url": "https://ct.example.test/",
            "state": log_state, "temporal_interval": {
                "start_inclusive": (self.clock - timedelta(days=5)).isoformat(),
                "end_exclusive": (self.clock + timedelta(days=60)).isoformat(),
            },
        }]}]})
        parsed = parse_scts(leaf)
        ct = validate_ct(parsed, dataset, leaf.not_valid_after_utc, self.clock)
        final = evaluate_security(validity, hostname, chain, algorithm, ct)
        evidence["modules"].extend([
            "validity_checker.check_validity", "hostname_validator.validate_hostname",
            "chain_validator.validate_chain", "ct_log_analyzer.analyze_dataset",
            "sct_parser.parse_scts", "ct_validator.validate_ct", "security_evaluator.evaluate_security",
        ])
        evidence["input_type"] += "; SCT và CT Log là dữ liệu giả lập có cấu trúc"
        evidence["structured_ct"] = {
            "requested_hostname": name, "sct_count": len(parsed.scts),
            "log_id": base64.b64encode(self.log_id).decode("ascii"),
            "state": next(iter(log_state)), "state_timestamp": next(iter(log_state.values()))["timestamp"],
            "interval_start": (self.clock - timedelta(days=5)).isoformat(),
            "interval_end": (self.clock + timedelta(days=60)).isoformat(),
            "sct_timestamp": sct_time.isoformat() if parsed.scts else None,
            "signature_verified": False,
        }
        detected = {
            "VALID_CONTROL": False,
            "EXPIRED_CERTIFICATE": validity.status == "EXPIRED",
            "NOT_YET_VALID_CERTIFICATE": validity.status == "NOT_YET_VALID",
            "HOSTNAME_MISMATCH": hostname.status == "FAIL",
            "BROKEN_CHAIN": chain.issuer_subject_links == "FAIL",
            "INVALID_SIGNATURE": chain.signature_validation == "FAIL" and leaf.issuer == intermediate.subject,
            "NON_CA_INTERMEDIATE": chain.ca_constraints == "FAIL",
            "SELF_SIGNED_LEAF": chain.self_signed_leaf and chain.status == "FAIL",
            "UNKNOWN_CT_LOG": bool(ct.matches) and ct.matches[0].log_id_match == "FAIL",
            "RETIRED_CT_LOG": bool(ct.matches) and ct.matches[0].state_status == "FAIL",
            "SCT_TIMESTAMP_OUTSIDE_INTERVAL": bool(ct.matches) and sct_time < self.clock - timedelta(days=5) and ct.matches[0].timestamp_interval == "NOT_APPLICABLE" and ct.matches[0].certificate_interval == "PASS",
            "NO_SCT": not parsed.scts and any("NO_SCT" in reason for reason in ct.reasons),
        }[case_type]
        return SyntheticOutcome(final.status, final.reasons, bool(detected), "Offline validator aggregation", generation, evidence)
