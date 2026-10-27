"""AIA and CT crypto use real signed fixtures; no canned PASS/FAIL engines."""
import base64
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import AuthorityInformationAccessOID
import pytest
from src.aia_completion import complete_chain
from src.ct_crypto import signed_entry, verify_sct, verify_inclusion, verify_sth
from src.sct_parser import SCTRecord


@pytest.fixture(autouse=True)
def offline_registry(monkeypatch):
    def unavailable():
        raise OSError("offline fixture")
    monkeypatch.setattr("src.certificate_security.load_official_registry", unavailable)


def test_aia_real_intermediate(chain_factory, chain_signing_keys, reference_time):
    leaf, intermediate, root = chain_factory()
    builder = (x509.CertificateBuilder().subject_name(leaf.subject).issuer_name(leaf.issuer)
               .public_key(leaf.public_key()).serial_number(leaf.serial_number)
               .not_valid_before(leaf.not_valid_before_utc).not_valid_after(leaf.not_valid_after_utc))
    for extension in leaf.extensions:
        builder = builder.add_extension(extension.value, extension.critical)
    leaf = builder.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier("https://ca.example.com/issuer"))]), False).sign(chain_signing_keys[1], hashes.SHA256())
    der = intermediate.public_bytes(serialization.Encoding.DER)
    fetch = lambda *a, **kw: der
    result = complete_chain([leaf], [root], now=reference_time, fetcher=fetch)
    assert result.status == "PASS" and result.chain.trust_anchor == root
    assert complete_chain([leaf], [], now=reference_time, fetcher=fetch).status == "FAIL"
    for bad in (b"garbage", leaf.public_bytes(serialization.Encoding.DER), root.public_bytes(serialization.Encoding.DER)):
        assert complete_chain([leaf], [root], now=reference_time, fetcher=lambda *a, **kw: bad).status == "FAIL"
    def failure(*a, **kw):
        raise TimeoutError("offline")
    assert complete_chain([leaf], [root], now=reference_time, fetcher=failure).status == "FAIL"


def test_aia_does_not_download_verified_path(chain_factory, reference_time):
    leaf, intermediate, root = chain_factory()
    def forbidden(*a, **kw):
        raise AssertionError("must not download")
    assert complete_chain([leaf, intermediate], [root], now=reference_time, fetcher=forbidden).status == "NOT_CHECKED"
    with pytest.raises(ValueError):
        complete_chain([leaf], [root], max_downloads=100)


@pytest.fixture
def signed_sct(certificate):
    key = ec.generate_private_key(ec.SECP256R1())
    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    log_id = base64.b64encode(hashlib.sha256(spki).digest()).decode()
    sct = SCTRecord(log_id, datetime(2026, 10, 7, tzinfo=timezone.utc), "v1", signature=b"placeholder", hash_algorithm="sha256", signature_algorithm="ECDSA", entry_type="X509_CERTIFICATE")
    der = certificate.public_bytes(serialization.Encoding.DER)
    data = signed_entry(sct, der)
    return key, spki, replace(sct, signature=key.sign(data, ec.ECDSA(hashes.SHA256()))), der


def test_sct_signature_actual_crypto(signed_sct):
    _, spki, sct, der = signed_sct
    keys = {sct.log_id: spki}
    assert verify_sct(sct, der, keys).status == "VALID"
    assert verify_sct(replace(sct, extensions=b"changed"), der, keys).status == "INVALID"
    assert verify_sct(sct, der, {}).status == "NOT_VERIFIED"
    assert verify_sct(replace(sct, signature=b""), der, keys).status == "NOT_VERIFIED"
    assert verify_sct(replace(sct, version="v2"), der, keys).status == "UNSUPPORTED"
    assert verify_sct(replace(sct, entry_type="PRE_CERTIFICATE"), None, keys).status == "NOT_VERIFIED"
    assert verify_sct(replace(sct, hash_algorithm="sha384"), der, keys).status == "UNSUPPORTED"
    timed = replace(sct, timestamp=sct.timestamp.replace(microsecond=123000))
    assert int.from_bytes(signed_entry(timed, der)[2:10], "big") == 1791331200123


def test_precertificate_explicit_signed_input(signed_sct):
    key, spki, sct, _ = signed_sct
    sct = replace(sct, entry_type="PRE_CERTIFICATE")
    args = dict(precertificate_tbs=b"explicit-local-TBS", issuer_key_hash=b"x"*32)
    data = signed_entry(sct, None, **args)
    sct = replace(sct, signature=key.sign(data, ec.ECDSA(hashes.SHA256())))
    assert verify_sct(sct, None, {sct.log_id: spki}, **args).status == "VALID"


def test_merkle_and_sth_separate(signed_sct):
    key, spki, _, _ = signed_sct
    leaf = b"exact-MerkleTreeLeaf"
    root = hashlib.sha256(b"\x00" + leaf).digest()
    assert verify_inclusion(leaf, 0, 1, (), root)
    assert not verify_inclusion(b"bad", 0, 1, (), root)
    assert not verify_inclusion(leaf, 1, 1, (), root)
    data = b"\x00\x01" + (1).to_bytes(8, "big") + (1).to_bytes(8, "big") + root
    signature = key.sign(data, ec.ECDSA(hashes.SHA256()))
    assert verify_sth(spki, 1, 1, root, signature).status == "VALID"
    assert verify_sth(spki, 2, 1, root, signature).status == "INVALID"


def test_unbalanced_merkle_tree():
    leaves = [b"a", b"b", b"c"]
    digests = [hashlib.sha256(b"\x00" + leaf).digest() for leaf in leaves]
    left = hashlib.sha256(b"\x01" + digests[0] + digests[1]).digest()
    root = hashlib.sha256(b"\x01" + left + digests[2]).digest()
    assert verify_inclusion(leaves[0], 0, 3, (digests[1], digests[2]), root)
    assert verify_inclusion(leaves[1], 1, 3, (digests[0], digests[2]), root)
    assert verify_inclusion(leaves[2], 2, 3, (left,), root)
    assert not verify_inclusion(leaves[2], 2, 3, (), root)


@pytest.mark.parametrize("state,expected", [("REVOKED", "FAIL"), ("ERROR", "WARNING"), ("NOT_CHECKED", "WARNING"), ("GOOD", "WARNING")])
def test_integration_preserves_ct_warning_and_revocation_failure(chain_factory, reference_time, monkeypatch, state, expected):
    from pathlib import Path
    import src.certificate_security as module
    from src.certificate_fetcher import TLSCertificates
    from src.revocation_checker import RevocationResult
    from src.certificate_service import build_view_model
    leaf, intermediate, root = chain_factory()
    encode = lambda c: c.public_bytes(serialization.Encoding.DER)
    tls = TLSCertificates(encode(leaf), tuple(map(encode, (leaf, intermediate, root))), (encode(root),))
    # Inject extension state only to test orchestration, not cryptographic validation.
    monkeypatch.setattr(module, "check_revocation", lambda *a, **kw: RevocationResult(state, "Kết quả kiểm thử boundary"))
    analysis = module.analyze_certificate("example.com", 443, 1, Path("data/log_list.json"), Path("config/algorithm_policy.json"), reference_time, lambda *a: tls, advanced=True)
    assert analysis.security.status == expected
    assert build_view_model("example.com", analysis, .1)["extensions"]["revocation"]["status"] == state


def test_extension_exception_does_not_crash_analysis(chain_factory, reference_time, monkeypatch):
    from pathlib import Path
    import src.certificate_security as module
    from src.certificate_fetcher import TLSCertificates
    certs = chain_factory()
    der = tuple(c.public_bytes(serialization.Encoding.DER) for c in certs)
    def failure(*a, **kw):
        raise RuntimeError("network error")
    monkeypatch.setattr(module, "check_revocation", failure)
    result = module.analyze_certificate("example.com", 443, 1, Path("data/log_list.json"), Path("config/algorithm_policy.json"), reference_time, lambda *a: TLSCertificates(der[0], der, (der[-1],)), advanced=True)
    assert result.extensions["revocation"]["status"] == "ERROR"
    assert result.security.status == "WARNING"
