"""Certificate fixtures tự ký, không cần Internet hay file khóa trên đĩa."""

from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.oid import NameOID
import pytest

PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | dsa.DSAPrivateKey | ed25519.Ed25519PrivateKey | ed448.Ed448PrivateKey


@pytest.fixture(scope="session")
def rsa_key() -> rsa.RSAPrivateKey:
    """Khóa RSA dùng lại cho các trường hợp metadata/hostname/validity."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def reference_time() -> datetime:
    """Mốc cố định giúp tests không phụ thuộc thời gian thực."""
    return datetime(2026, 10, 7, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def certificate_factory(rsa_key: rsa.RSAPrivateKey, reference_time: datetime) -> Callable[..., x509.Certificate]:
    """Tạo certificate có thể tùy biến SAN, key và khoảng hiệu lực."""
    def build(
        *, key: PrivateKey | None = None,
        san: list[x509.GeneralName] | None = None,
        include_san: bool = True,
        common_name: str = "example.com",
        not_before: datetime | None = None,
        not_after: datetime | None = None,
    ) -> x509.Certificate:
        """Tạo và ký một certificate phục vụ unit test."""
        key = rsa_key if key is None else key
        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DT007 Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        builder = (
            x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(123456)
            .not_valid_before(not_before if not_before is not None else reference_time - timedelta(days=1))
            .not_valid_after(not_after if not_after is not None else reference_time + timedelta(days=1))
        )
        if include_san:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san if san is not None else [x509.DNSName("example.com")]),
                critical=False,
            )
        algorithm = None if isinstance(key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)) else hashes.SHA256()
        return builder.sign(key, algorithm)
    return build


@pytest.fixture
def certificate(certificate_factory: Callable[..., x509.Certificate]) -> x509.Certificate:
    """Certificate RSA với SAN example.com."""
    return certificate_factory()


@pytest.fixture(scope="session")
def chain_signing_keys() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePrivateKey]:
    """Khóa CA cho tests chain, độc lập với khóa leaf RSA."""
    return ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def chain_factory(rsa_key: rsa.RSAPrivateKey, chain_signing_keys: tuple, reference_time: datetime) -> Callable:
    """Tạo chain leaf/intermediate/root với biến thể lỗi kiểm soát được."""
    root_key, intermediate_key = chain_signing_keys
    def build(
        *, broken_link: bool = False, invalid_signature: bool = False,
        intermediate_ca: bool = True, expired_intermediate: bool = False,
        root_path_length: int | None = None, key_cert_sign: bool = True,
        future_intermediate: bool = False, invalid_root_signature: bool = False,
        at: datetime | None = None,
    ) -> tuple[x509.Certificate, x509.Certificate, x509.Certificate]:
        root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DT007 Test Root")])
        intermediate_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DT007 Intermediate")])
        leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])

        def issue(subject: x509.Name, issuer: x509.Name, public_key: object, signer: PrivateKey,
                  ca: bool, start: datetime, end: datetime, path_length: int | None = None) -> x509.Certificate:
            builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
                       .public_key(public_key).serial_number(x509.random_serial_number())
                       .not_valid_before(start).not_valid_after(end)
                       .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True))
            if subject == intermediate_name:
                builder = builder.add_extension(x509.KeyUsage(
                    digital_signature=True, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=key_cert_sign,
                    crl_sign=key_cert_sign, encipher_only=False, decipher_only=False,
                ), critical=True)
            if subject == leaf_name:
                builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False)
            return builder.sign(signer, hashes.SHA256())

        clock = reference_time if at is None else at
        start, end = clock - timedelta(days=10), clock + timedelta(days=10)
        root = issue(root_name, root_name, root_key.public_key(), intermediate_key if invalid_root_signature else root_key,
                     True, start, end, root_path_length)
        intermediate_start = clock + timedelta(days=1) if future_intermediate else start
        intermediate_end = clock - timedelta(days=1) if expired_intermediate else end
        intermediate = issue(intermediate_name, root_name, intermediate_key.public_key(), root_key,
                             intermediate_ca, intermediate_start, intermediate_end)
        leaf_issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Wrong Issuer")]) if broken_link else intermediate_name
        leaf = issue(leaf_name, leaf_issuer, rsa_key.public_key(), root_key if invalid_signature else intermediate_key,
                     False, start, end)
        return leaf, intermediate, root
    return build


@pytest.fixture
def sct_certificate_factory(rsa_key: rsa.RSAPrivateKey, reference_time: datetime) -> Callable:
    """Tạo SCT wire bytes thật trong extension, không mock parser cryptography."""
    def build(log_ids: list[bytes] | None = None, timestamp: datetime | None = None,
              malformed: bool = False) -> x509.Certificate:
        from cryptography.x509.oid import ExtensionOID
        timestamp = reference_time - timedelta(hours=1) if timestamp is None else timestamp
        log_ids = [b"\x01" * 32] if log_ids is None else log_ids
        encoded = []
        for log_id in log_ids:
            signature = b"\x30\x06\x02\x01\x01\x02\x01\x01"
            sct = (b"\x00" + log_id + int(timestamp.timestamp() * 1000).to_bytes(8, "big")
                   + b"\x00\x00" + b"\x04\x03" + len(signature).to_bytes(2, "big") + signature)
            encoded.append(len(sct).to_bytes(2, "big") + sct)
        payload = b"".join(encoded)
        value = len(payload).to_bytes(2, "big") + payload
        if malformed:
            value = b"\x00\x50broken"
        length = len(value)
        length_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
        der_length = bytes([length]) if length < 128 else bytes([0x80 | len(length_bytes)]) + length_bytes
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SCT test")])
        return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(rsa_key.public_key()).serial_number(234567)
                .not_valid_before(reference_time - timedelta(days=1)).not_valid_after(reference_time + timedelta(days=1))
                .add_extension(x509.UnrecognizedExtension(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS,
                                                        b"\x04" + der_length + value), critical=False)
                .sign(rsa_key, hashes.SHA256()))
    return build
