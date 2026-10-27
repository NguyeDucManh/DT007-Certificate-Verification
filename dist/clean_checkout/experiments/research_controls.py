"""Predeclared valid X.509 controls with public DER and an external oracle."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from OpenSSL import crypto

from experiments.synthetic_cases import SyntheticOutcome
from src.algorithm_policy import evaluate_algorithm
from src.chain_validator import validate_chain
from src.crypto_info import get_crypto_info
from src.ct_log_analyzer import analyze_dataset
from src.ct_validator import validate_ct
from src.hostname_validator import validate_hostname
from src.sct_parser import parse_scts
from src.security_evaluator import evaluate_security
from src.validity_checker import check_validity


@dataclass(frozen=True)
class ControlSpec:
    """Input properties and labels fixed independently of the observed result."""
    case_id: str
    key_type: str
    bits: int
    digest: str


CONTROLS = (
    ControlSpec("control_rsa2048", "RSA", 2048, "sha256"),
    ControlSpec("control_rsa3072", "RSA", 3072, "sha384"),
    ControlSpec("control_ec256", "EC", 256, "sha256"),
    ControlSpec("control_ec384", "EC", 384, "sha384"),
    ControlSpec("control_ed25519", "Ed25519", 256, "sha256"),
)


class ControlLab:
    """Real locally trusted certificates; no mock, no website claims."""

    def __init__(self, clock: datetime, policy: dict[str, Any]) -> None:
        self.clock, self.policy = clock, policy
        self.root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DT007 Control Root")])
        self.root = self._issue(self.root_name, self.root_name, self.root_key.public_key(), True, hashes.SHA256())

    def _issue(self, subject, issuer, public_key, ca: bool, digest) -> x509.Certificate:
        builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
                   .public_key(public_key).serial_number(x509.random_serial_number())
                   .not_valid_before(self.clock - timedelta(days=10))
                   .not_valid_after(self.clock + timedelta(days=30))
                   .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True))
        if not ca:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName("control.example.test")]), critical=False)
        return builder.sign(self.root_key, digest)

    def run(self, spec: ControlSpec, profile: str) -> SyntheticOutcome:
        """Validate labels before executing unchanged DT007 validators."""
        if spec not in CONTROLS or profile not in ("baseline", "extended"):
            raise ValueError("Ca đối chứng hoặc profile không được định nghĩa")
        if spec.key_type == "RSA":
            key = rsa.generate_private_key(public_exponent=65537, key_size=spec.bits)
        elif spec.key_type == "EC":
            key = ec.generate_private_key(ec.SECP256R1() if spec.bits == 256 else ec.SECP384R1())
        else:
            key = ed25519.Ed25519PrivateKey.generate()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "control.example.test")])
        cert = self._issue(subject, self.root_name, key.public_key(), False, hashes.SHA256() if spec.digest == "sha256" else hashes.SHA384())
        cert = x509.load_der_x509_certificate(cert.public_bytes(Encoding.DER))
        # Label checks deliberately do not call DT007 functions. This oracle shares
        # OpenSSL with chain_validator; it is an independent invocation, not an
        # independent cryptographic implementation or a population ground truth.
        store = crypto.X509Store()
        store.add_cert(crypto.X509.from_cryptography(self.root))
        store.set_time(self.clock)
        crypto.X509StoreContext(store, crypto.X509.from_cryptography(cert)).verify_certificate()
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        oracle = (cert.not_valid_before_utc <= self.clock < cert.not_valid_after_utc
                  and "control.example.test" in names
                  and not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                  and cert.signature_hash_algorithm.name == spec.digest
                  and (not hasattr(cert.public_key(), "key_size") or cert.public_key().key_size == spec.bits))
        if not oracle:
            raise ValueError("Nhãn đối chứng không khớp chứng thư sinh ra; dừng ca, không sửa kỳ vọng")
        info = get_crypto_info(cert)
        algorithm = evaluate_algorithm(info, self.policy)
        validity = check_validity(cert, self.clock)
        hostname = validate_hostname(cert, "control.example.test")
        chain = validate_chain((cert,), (self.root,), self.clock, peer_chain=(cert,))
        ct = validate_ct(parse_scts(cert), analyze_dataset({"operators": []}), cert.not_valid_after_utc, self.clock) if profile == "extended" else None
        result = evaluate_security(validity, hostname, chain, algorithm, ct, include_ct=profile == "extended")
        evidence = {
            "input_type": "Chứng thư X.509 thực, DER công khai; không có SCT",
            "mock_used": False, "label_source": "Thuộc tính định trước + OpenSSL store verification độc lập trước engine",
            "oracle_verified": oracle, "oracle_limit": "Dùng chung backend OpenSSL; nhãn chỉ về chứng thư trong trust store lab, không về website/CT đầy đủ",
            "certificate": {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(), "key_algorithm": info.public_key_algorithm, "key_size": info.public_key_size, "signature_hash": info.signature_hash_algorithm},
            "leaf_pem": cert.public_bytes(Encoding.PEM).decode("ascii"),
            "anchor_pem": self.root.public_bytes(Encoding.PEM).decode("ascii"),
            "checks": result.checks,
            "modules": ["crypto_info", "algorithm_policy", "validity_checker", "hostname_validator", "chain_validator", "security_evaluator"] + (["sct_parser", "ct_validator"] if ct else []),
        }
        return SyntheticOutcome(result.status, result.reasons, False, "Valid control; CT absence reported separately", "cryptography X.509 + independent OpenSSL invocation", evidence)
