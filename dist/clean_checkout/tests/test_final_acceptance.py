"""Recovery cannot turn an untrusted handshake into trusted certificate output."""
from pathlib import Path
import ssl
from cryptography.hazmat.primitives import serialization
import pytest
import src.certificate_security as engine
from src.certificate_fetcher import TLSCertificates
from src.revocation_checker import RevocationResult


@pytest.fixture(autouse=True)
def offline_registry(monkeypatch):
    def unavailable():
        raise OSError("offline fixture")
    monkeypatch.setattr(engine, "load_official_registry", unavailable)


@pytest.mark.parametrize("advanced,code,hostname,anchor,expected", [
    (False, 20, "example.com", True, "FAIL"),
    (True, 10, "example.com", True, "FAIL"),
    (True, 20, "example.com", True, "WARNING"),
    (True, 21, "wrong.example.com", True, "FAIL"),
    (True, 20, "example.com", False, "FAIL"),
])
def test_recovery_gate_and_independent_validation(chain_factory, reference_time, monkeypatch, advanced, code, hostname, anchor, expected):
    certs = chain_factory()
    der = tuple(c.public_bytes(serialization.Encoding.DER) for c in certs)
    error = ssl.SSLCertVerificationError("missing issuer")
    error.verify_code = code
    def failed(*a):
        raise error
    calls = []
    def inspect(*a):
        calls.append(True)
        return TLSCertificates(der[0], der[:2], (der[-1],) if anchor else (), der[:2])
    monkeypatch.setattr(engine, "collect_untrusted_peer", inspect)
    monkeypatch.setattr(engine, "check_revocation", lambda *a, **kw: RevocationResult("NOT_CHECKED", "Offline integration"))
    result = engine.analyze_certificate(hostname, 443, 1, Path("data/log_list.json"), Path("config/algorithm_policy.json"), reference_time, failed, advanced=advanced)
    assert result.security.status == expected
    assert bool(calls) == (advanced and code in (20, 21))
    if not anchor and calls:
        assert result.chain.trust == "FAIL"
    if calls:
        assert result.chain.peer_certificates == certs[:2]


def test_untrusted_collection_rejects_nonstandard_port():
    from src.untrusted_tls import collect_untrusted_peer
    with pytest.raises(ValueError):
        collect_untrusted_peer("example.com", 8443, 1)


def test_aia_real_false_ca_rejected(chain_factory, chain_signing_keys, reference_time):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import AuthorityInformationAccessOID
    from src.aia_completion import complete_chain
    leaf, intermediate, root = chain_factory(intermediate_ca=False)
    builder = x509.CertificateBuilder().subject_name(leaf.subject).issuer_name(leaf.issuer).public_key(leaf.public_key()).serial_number(leaf.serial_number).not_valid_before(leaf.not_valid_before_utc).not_valid_after(leaf.not_valid_after_utc)
    for ext in leaf.extensions:
        builder = builder.add_extension(ext.value, ext.critical)
    leaf = builder.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier("https://example.com/ca"))]), False).sign(chain_signing_keys[1], hashes.SHA256())
    result = complete_chain([leaf], [root], now=reference_time, fetcher=lambda *a, **kw: intermediate.public_bytes(serialization.Encoding.DER))
    assert result.status == "FAIL" and result.chain.trust != "PASS"
