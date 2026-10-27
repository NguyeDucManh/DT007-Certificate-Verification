"""Thu thập thông tin mật mã, chưa áp dụng chính sách thuật toán."""

from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.oid import SignatureAlgorithmOID


@dataclass(frozen=True)
class CryptoInfo:
    """Thông tin public key và chữ ký; không có kết luận policy PASS/FAIL."""

    public_key_algorithm: str
    public_key_size: int | None
    signature_algorithm_oid: str
    signature_algorithm_name: str
    signature_hash_algorithm: str | None


def describe_public_key(public_key: object) -> tuple[str, int | None]:
    """Nhận diện các key phổ biến; key chưa hỗ trợ trả UNKNOWN/None."""
    for key_type, name in (
        (rsa.RSAPublicKey, "RSA"), (ec.EllipticCurvePublicKey, "EC"),
        (dsa.DSAPublicKey, "DSA"),
    ):
        if isinstance(public_key, key_type):
            return name, public_key.key_size
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", None
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", None
    return "UNKNOWN", None


def get_crypto_info(certificate: x509.Certificate) -> CryptoInfo:
    """Đọc key, OID/name chữ ký và hash, xử lý thuật toán không được hỗ trợ."""
    try:
        algorithm, key_size = describe_public_key(certificate.public_key())
    except UnsupportedAlgorithm:
        algorithm, key_size = "UNKNOWN", None
    oid = certificate.signature_algorithm_oid
    name = next((name for name, value in vars(SignatureAlgorithmOID).items() if value == oid), "UNKNOWN")
    try:
        hash_algorithm = certificate.signature_hash_algorithm
        hash_name = hash_algorithm.name if hash_algorithm is not None else None
    except UnsupportedAlgorithm:
        hash_name = "UNKNOWN"
    return CryptoInfo(algorithm, key_size, oid.dotted_string, name, hash_name)
