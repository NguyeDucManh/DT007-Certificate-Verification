"""Kiểm tra key types, hash không áp dụng và thuật toán chưa hỗ trợ."""

from collections.abc import Callable
from unittest.mock import MagicMock, PropertyMock

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448
from cryptography.x509.oid import ObjectIdentifier, SignatureAlgorithmOID
import pytest

from src.crypto_info import describe_public_key, get_crypto_info


def test_rsa(certificate: x509.Certificate) -> None:
    info = get_crypto_info(certificate)
    assert (info.public_key_algorithm, info.public_key_size) == ("RSA", 2048)
    assert info.signature_algorithm_name == "RSA_WITH_SHA256"
    assert info.signature_algorithm_oid == SignatureAlgorithmOID.RSA_WITH_SHA256.dotted_string
    assert info.signature_hash_algorithm == "sha256"


def test_ec(certificate_factory: Callable) -> None:
    cert = certificate_factory(key=ec.generate_private_key(ec.SECP256R1()))
    info = get_crypto_info(cert)
    assert (info.public_key_algorithm, info.public_key_size) == ("EC", 256)
    assert info.signature_algorithm_name == "ECDSA_WITH_SHA256"
    assert info.signature_hash_algorithm == "sha256"


def test_dsa(certificate_factory: Callable) -> None:
    cert = certificate_factory(key=dsa.generate_private_key(key_size=2048))
    info = get_crypto_info(cert)
    assert (info.public_key_algorithm, info.public_key_size) == ("DSA", 2048)
    assert info.signature_hash_algorithm == "sha256"


@pytest.mark.parametrize("key_class, name", [(ed25519.Ed25519PrivateKey, "Ed25519"), (ed448.Ed448PrivateKey, "Ed448")])
def test_edwards(certificate_factory: Callable, key_class: type, name: str) -> None:
    info = get_crypto_info(certificate_factory(key=key_class.generate()))
    assert info.public_key_algorithm == name
    assert info.public_key_size is None  # Không dùng độ dài mã hóa thay cho key_size.
    assert info.signature_hash_algorithm is None
    assert info.signature_algorithm_name != "UNKNOWN"


def test_unknown_key() -> None:
    assert describe_public_key(object()) == ("UNKNOWN", None)


def test_unsupported_algorithm() -> None:
    cert = MagicMock()
    cert.public_key.side_effect = UnsupportedAlgorithm("unknown key")
    cert.signature_algorithm_oid = ObjectIdentifier("1.2.3.4")
    type(cert).signature_hash_algorithm = PropertyMock(side_effect=UnsupportedAlgorithm("unknown hash"))
    info = get_crypto_info(cert)
    assert (info.public_key_algorithm, info.public_key_size) == ("UNKNOWN", None)
    assert info.signature_algorithm_name == "UNKNOWN"
    assert info.signature_algorithm_oid == "1.2.3.4"
    assert info.signature_hash_algorithm == "UNKNOWN"
