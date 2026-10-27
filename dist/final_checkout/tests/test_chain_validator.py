"""Xác minh chain thật bằng certificate được ký trong fixture."""

from collections.abc import Callable
from datetime import datetime
from unittest.mock import MagicMock

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec, ed25519, ed448
import pytest

from src.chain_validator import validate_chain, verify_signature


def test_valid_chain(chain_factory: Callable, reference_time: datetime) -> None:
    chain = chain_factory()
    result = validate_chain(chain, [chain[-1]], reference_time)
    assert result.status == "PASS" and not result.reasons
    assert result.signature_validation == "PASS" and result.trust == "PASS"
    assert len(result.certificates) == 3


def test_broken_issuer_link(chain_factory: Callable, reference_time: datetime) -> None:
    chain = chain_factory(broken_link=True)
    result = validate_chain(chain, [chain[-1]], reference_time)
    assert result.status == "FAIL" and result.issuer_subject_links == "FAIL"


def test_invalid_signature(chain_factory: Callable, reference_time: datetime) -> None:
    chain = chain_factory(invalid_signature=True)
    assert chain[0].issuer == chain[1].subject  # Đúng text nhưng sai signer key.
    assert not verify_signature(chain[0], chain[1])
    result = validate_chain(chain, [chain[-1]], reference_time)
    assert result.signature_validation == "FAIL" and result.status == "FAIL"


def test_non_ca_issuer(chain_factory: Callable, reference_time: datetime) -> None:
    chain = chain_factory(intermediate_ca=False)
    result = validate_chain(chain, [chain[-1]], reference_time)
    assert result.ca_constraints == "FAIL" and result.status == "FAIL"


def test_expired_intermediate(chain_factory: Callable, reference_time: datetime) -> None:
    chain = chain_factory(expired_intermediate=True)
    result = validate_chain(chain, [chain[-1]], reference_time)
    assert result.validity == "FAIL" and result.status == "FAIL"
    assert any("EXPIRED" in reason for reason in result.reasons)


def test_self_signed_leaf(certificate: x509.Certificate, reference_time: datetime) -> None:
    result = validate_chain([certificate], [certificate], reference_time)
    assert result.self_signed_leaf is True and result.status == "FAIL"


def test_missing_issuer(chain_factory: Callable, reference_time: datetime) -> None:
    chain = chain_factory()
    result = validate_chain(chain[:1], [chain[-1]], reference_time)
    assert result.status == "FAIL" and any("Missing issuer" in reason for reason in result.reasons)


def test_untrusted_root(chain_factory: Callable, reference_time: datetime) -> None:
    result = validate_chain(chain_factory(), [], reference_time)
    assert result.trust == "FAIL" and result.status == "FAIL"


def test_explicitly_trusted_non_self_signed_anchor(chain_factory: Callable, reference_time: datetime) -> None:
    """Windows có thể trust trực tiếp cross-signed CA; không cần root tự ký."""
    leaf, intermediate, root = chain_factory()
    assert intermediate.subject != intermediate.issuer
    result = validate_chain([leaf, intermediate], [intermediate], reference_time)
    assert result.status == "PASS" and result.signature_validation == "PASS"
    # Root trong store hoàn tất đường dẫn; intermediate không bị tự tin cậy.
    completed = validate_chain([leaf, intermediate], [root], reference_time)
    assert completed.status == 'PASS' and completed.trust_anchor == root


def test_missing_root(chain_factory: Callable, reference_time: datetime) -> None:
    chain = chain_factory()
    result = validate_chain(chain[:2], [chain[-1]], reference_time)
    assert result.trust == "PASS" and result.status == "PASS"
    assert result.certificates == tuple(chain) and result.trust_anchor == chain[-1]


def test_duplicate_cycle(chain_factory: Callable, reference_time: datetime) -> None:
    chain = chain_factory()
    result = validate_chain([*chain, chain[-1]], [chain[-1]], reference_time)
    assert result.issuer_subject_links == "FAIL"


def test_path_length_enforced(chain_factory: Callable, reference_time: datetime) -> None:
    chain = chain_factory(root_path_length=0)
    result = validate_chain(chain, [chain[-1]], reference_time)
    assert result.status == "FAIL"
    assert any("OpenSSL path verification" in reason for reason in result.reasons)


def test_key_cert_sign_enforced(chain_factory: Callable, reference_time: datetime) -> None:
    chain = chain_factory(key_cert_sign=False)
    assert validate_chain(chain, [chain[-1]], reference_time).ca_constraints == "FAIL"


def test_future_intermediate(chain_factory: Callable, reference_time: datetime) -> None:
    chain = chain_factory(future_intermediate=True)
    result = validate_chain(chain, [chain[-1]], reference_time)
    assert result.status == "FAIL" and any("NOT_YET_VALID" in reason for reason in result.reasons)


def test_invalid_root_self_signature(chain_factory: Callable, reference_time: datetime) -> None:
    chain = chain_factory(invalid_root_signature=True)
    assert validate_chain(chain, [chain[-1]], reference_time).signature_validation == "FAIL"


def test_empty_chain() -> None:
    assert validate_chain([]).status == "FAIL"


def test_naive_time(chain_factory: Callable) -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        validate_chain(chain_factory(), current_time=datetime(2026, 10, 7))


def test_legacy_sha1_signature_verifies(rsa_key: object) -> None:
    """Verify thực sự RSA/SHA-1 bytes; cryptographic validity khác policy."""
    data = b"test legacy root tbs bytes"
    signature = rsa_key.sign(data, padding.PKCS1v15(), hashes.SHA1())
    cert = MagicMock()
    cert.issuer = cert.subject = x509.Name([])
    cert.public_key.return_value = rsa_key.public_key()
    cert.signature = signature
    cert.tbs_certificate_bytes = data
    cert.signature_algorithm_parameters = padding.PKCS1v15()
    cert.signature_hash_algorithm = hashes.SHA1()
    assert verify_signature(cert, cert)
    cert.tbs_certificate_bytes = b"tampered"
    assert not verify_signature(cert, cert)


@pytest.mark.parametrize("key_factory", [
    lambda: ec.generate_private_key(ec.SECP256R1()), ed25519.Ed25519PrivateKey.generate, ed448.Ed448PrivateKey.generate,
])
def test_signature_key_types(certificate_factory: Callable, key_factory: Callable) -> None:
    cert = certificate_factory(key=key_factory())
    assert verify_signature(cert, cert)


def test_rsa_pss_certificate(rsa_key: object, certificate: x509.Certificate) -> None:
    cert = (x509.CertificateBuilder().subject_name(certificate.subject).issuer_name(certificate.subject)
            .public_key(rsa_key.public_key()).serial_number(123)
            .not_valid_before(certificate.not_valid_before_utc).not_valid_after(certificate.not_valid_after_utc)
            .sign(rsa_key, hashes.SHA256(), rsa_padding=padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)))
    assert verify_signature(cert, cert)
