"""TLS purpose must not be inferred from generic path verification."""
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID
import pytest
from src.chain_validator import validate_chain


def reissue(cert, signer, extension):
    builder = (x509.CertificateBuilder().subject_name(cert.subject).issuer_name(cert.issuer)
               .public_key(cert.public_key()).serial_number(cert.serial_number)
               .not_valid_before(cert.not_valid_before_utc).not_valid_after(cert.not_valid_after_utc))
    for item in cert.extensions:
        if item.oid != extension.oid:
            builder = builder.add_extension(item.value, item.critical)
    return builder.add_extension(extension, critical=True).sign(signer, hashes.SHA256())


@pytest.mark.parametrize("index", [0, 1, 2])
def test_client_auth_only_chain_cannot_verify_tls_server(chain_factory, chain_signing_keys, reference_time, index):
    chain = list(chain_factory())
    root_key, intermediate_key = chain_signing_keys
    signer = intermediate_key if index == 0 else root_key
    chain[index] = reissue(chain[index], signer, x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]))
    result = validate_chain(chain, [chain[-1]], reference_time)
    assert result.status == "FAIL"
    assert result.trust == "FAIL" and result.trust_anchor is None
    assert any("TLS server" in reason for reason in result.reasons)


@pytest.mark.parametrize("eku", [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE])
def test_server_or_unrestricted_eku_retains_valid_chain(chain_factory, chain_signing_keys, reference_time, eku):
    chain = list(chain_factory())
    chain[0] = reissue(chain[0], chain_signing_keys[1], x509.ExtendedKeyUsage([eku]))
    assert validate_chain(chain, [chain[-1]], reference_time).status == "PASS"


def test_leaf_without_tls_key_usage_is_rejected(chain_factory, chain_signing_keys, reference_time):
    chain = list(chain_factory())
    usage = x509.KeyUsage(False, True, False, False, False, False, False, False, False)
    chain[0] = reissue(chain[0], chain_signing_keys[1], usage)
    result = validate_chain(chain, [chain[-1]], reference_time)
    assert result.status == "FAIL" and result.trust == "FAIL"


def test_missing_optional_usage_does_not_invent_failure(chain_factory, reference_time):
    chain = chain_factory()
    assert validate_chain(chain, [chain[-1]], reference_time).status == "PASS"
