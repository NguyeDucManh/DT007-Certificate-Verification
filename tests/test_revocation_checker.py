"""Real signed OCSP/CRL offline fixtures, not canned validator outcomes."""
from datetime import datetime, timedelta, timezone
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID, AuthorityInformationAccessOID, ExtendedKeyUsageOID
import pytest

from src.revocation_checker import check_revocation, extract_sources, validate_crl, validate_ocsp


@pytest.fixture
def material():
    """Issuer and leaf are real local certificates; never website certificates."""
    now = datetime.now(timezone.utc).replace(microsecond=0)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DT007 Offline CA")])

    def cert(subject, pubkey, signer, ca=False, extensions=()):
        builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(name).public_key(pubkey)
                   .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=2))
                   .not_valid_after(now+timedelta(days=30)).add_extension(x509.BasicConstraints(ca, None), True))
        for extension in extensions:
            builder = builder.add_extension(extension, False)
        return builder.sign(signer, hashes.SHA256())

    issuer = cert(name, key.public_key(), key, True)
    leaf = cert(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "offline.example.test")]), key.public_key(), key, extensions=(
        x509.AuthorityInformationAccess([x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier("https://ocsp.example.com/status"))]),
        x509.CRLDistributionPoints([x509.DistributionPoint([x509.UniformResourceIdentifier("https://crl.example.com/list")], None, None, None)]),
    ))

    def response(status=ocsp.OCSPCertStatus.GOOD, *, signer=None, signer_cert=None, target=None, stale=False, by_name=False, nonce=None):
        signer = signer or key
        signer_cert = signer_cert or issuer
        builder = (ocsp.OCSPResponseBuilder().add_response(target or leaf, issuer, hashes.SHA256(), status,
                   now-timedelta(days=3) if stale else now-timedelta(minutes=1),
                   now-timedelta(days=2) if stale else now+timedelta(hours=1),
                   now-timedelta(hours=1) if status == ocsp.OCSPCertStatus.REVOKED else None, None)
                   .responder_id(ocsp.OCSPResponderEncoding.NAME if by_name else ocsp.OCSPResponderEncoding.HASH, signer_cert))
        if signer_cert != issuer:
            builder = builder.certificates([signer_cert])
        if nonce is not None:
            builder = builder.add_extension(x509.OCSPNonce(nonce), False)
        return builder.sign(signer, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    def crl(*, revoked=False, signer=None, stale=False, delta=False, wrong_name=False, idp=None, next_update=True):
        builder = (x509.CertificateRevocationListBuilder().issuer_name(leaf.subject if wrong_name else name)
                   .last_update(now-timedelta(days=3) if stale else now-timedelta(minutes=1)))
        if next_update:
            builder = builder.next_update(now-timedelta(days=2) if stale else now+timedelta(hours=1))
        if idp is not None:
            builder = builder.add_extension(idp, True)
        if revoked:
            builder = builder.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(leaf.serial_number).revocation_date(now-timedelta(hours=1)).build())
        if delta:
            builder = builder.add_extension(x509.DeltaCRLIndicator(1), True)
        return builder.sign(signer or key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
    return now, key, issuer, leaf, cert, response, crl


@pytest.mark.parametrize("status", list(ocsp.OCSPCertStatus))
@pytest.mark.parametrize("by_name", [True, False])
def test_ocsp_signed_states(material, status, by_name):
    now, _, issuer, leaf, _, response, _ = material
    result = validate_ocsp(response(status, by_name=by_name), leaf, issuer, issuer_trusted=True, now=now)
    assert result.status == status.name and result.signature_verified and result.issuer_verified


@pytest.mark.parametrize("revoked", [True, False])
def test_crl_signed_states(material, revoked):
    now, _, issuer, leaf, _, _, crl = material
    result = validate_crl(crl(revoked=revoked), leaf, issuer, issuer_trusted=True, now=now)
    assert result.status == ("REVOKED" if revoked else "GOOD") and result.signature_verified


@pytest.mark.parametrize("method", ["OCSP", "CRL"])
@pytest.mark.parametrize("fault", ["bad_signature", "stale", "garbage", "untrusted", "wrong_issuer"])
def test_invalid_evidence_never_good(material, method, fault):
    now, _, issuer, leaf, cert, response, crl = material
    validator, factory = (validate_ocsp, response) if method == "OCSP" else (validate_crl, crl)
    data = factory(signer=ec.generate_private_key(ec.SECP256R1())) if fault == "bad_signature" and method == "CRL" else factory(stale=True) if fault == "stale" else b"not ASN.1" if fault == "garbage" else factory()
    if fault == "bad_signature" and method == "OCSP":
        data = data[:-1] + bytes([data[-1] ^ 1])
    if fault == "wrong_issuer":
        key = ec.generate_private_key(ec.SECP256R1())
        issuer = cert(issuer.subject, key.public_key(), key, True)
    result = validator(data, leaf, issuer, issuer_trusted=fault != "untrusted", now=now)
    assert result.status == "ERROR"


def test_wrong_target_and_crl_issuer(material):
    now, _, issuer, leaf, _, response, crl = material
    assert validate_ocsp(response(target=issuer), leaf, issuer, issuer_trusted=True, now=now).status == "ERROR"
    assert validate_crl(crl(wrong_name=True), leaf, issuer, issuer_trusted=True, now=now).status == "ERROR"


def test_delegated_responder_permissions(material):
    now, key, issuer, leaf, cert, response, _ = material
    signer = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Responder")])
    for eku, nocheck, expected in ((False, False, "ERROR"), (True, False, "UNKNOWN"), (True, True, "GOOD")):
        extensions = ([x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING])] if eku else []) + ([x509.OCSPNoCheck()] if nocheck else [])
        signer_cert = cert(name, signer.public_key(), key, extensions=extensions)
        result = validate_ocsp(response(signer=signer, signer_cert=signer_cert), leaf, issuer, issuer_trusted=True, now=now)
        assert result.status == expected


def test_delta_scope_is_unknown(material):
    now, _, issuer, leaf, _, _, crl = material
    assert validate_crl(crl(delta=True), leaf, issuer, issuer_trusted=True, now=now).status == "UNKNOWN"


def test_offline_default_and_no_issuer(material):
    _, _, _, leaf, _, _, _ = material
    assert check_revocation(leaf).status == "NOT_CHECKED"
    assert check_revocation(leaf, online=True).status == "NOT_CHECKED"
    sources = extract_sources(leaf)
    assert len(sources.ocsp_urls) == len(sources.crl_urls) == 1


@pytest.mark.parametrize("status", list(ocsp.OCSPCertStatus))
def test_orchestration_reexecutes_real_validators(material, status):
    now, _, issuer, leaf, _, response, _ = material
    result = check_revocation(leaf, issuer, issuer_trusted=True, now=now, fixtures={"OCSP": (response(status),)})
    assert result.status == status.name
    assert json.loads(json.dumps(result.to_dict()))["evidence"][0]["signature_verified"]


def test_network_failure_is_error_and_calls_bounded_sources(material):
    now, _, issuer, leaf, _, _, _ = material
    calls = []
    def failed(url, **kwargs):
        calls.append(url)
        raise TimeoutError("timeout")
    result = check_revocation(leaf, issuer, issuer_trusted=True, online=True, now=now, fetcher=failed)
    assert result.status == "ERROR" and len(calls) == 2


def test_revoked_dominates_but_errors_prevent_good(material):
    now, _, issuer, leaf, _, response, crl = material
    assert check_revocation(leaf, issuer, issuer_trusted=True, now=now, fixtures={"OCSP": (response(),), "CRL": (b"bad",)}).status == "ERROR"
    assert check_revocation(leaf, issuer, issuer_trusted=True, now=now, fixtures={"OCSP": (b"bad",), "CRL": (crl(revoked=True),)}).status == "REVOKED"


def test_no_sources_is_not_checked(material):
    now, _, issuer, _, _, _, _ = material
    assert check_revocation(issuer, issuer, issuer_trusted=True, online=True, now=now).status == "NOT_CHECKED"


@pytest.mark.parametrize("url,indirect,reasons,ca,expected", [
    ("https://crl.example.com/list", False, None, False, "GOOD"),
    ("https://wrong.example.com/list", False, None, False, "ERROR"),
    ("https://crl.example.com/list", True, None, False, "UNKNOWN"),
    ("https://crl.example.com/list", False, frozenset([x509.ReasonFlags.key_compromise]), False, "UNKNOWN"),
    ("https://crl.example.com/list", False, None, True, "ERROR"),
])
def test_crl_distribution_scope(material, url, indirect, reasons, ca, expected):
    now, _, issuer, leaf, _, _, crl = material
    idp = x509.IssuingDistributionPoint([x509.UniformResourceIdentifier(url)], None, False, ca, reasons, indirect, False)
    assert validate_crl(crl(idp=idp), leaf, issuer, issuer_trusted=True, now=now).status == expected


def test_crl_without_next_update_is_error(material):
    from src.revocation_checker import _fresh, ValidationPolicy
    now = material[0]
    # The cryptography CRL builder itself requires nextUpdate; test our guard directly.
    with pytest.raises(ValueError, match="nextUpdate"):
        _fresh(now, None, now, ValidationPolicy(), is_crl=True)


def test_ocsp_protocol_error_and_size(material):
    from src.revocation_checker import ValidationPolicy
    now, _, issuer, leaf, _, response, _ = material
    error = ocsp.OCSPResponseBuilder.build_unsuccessful(ocsp.OCSPResponseStatus.TRY_LATER).public_bytes(serialization.Encoding.DER)
    assert validate_ocsp(error, leaf, issuer, issuer_trusted=True, now=now).status == "ERROR"
    assert validate_ocsp(response(), leaf, issuer, issuer_trusted=True, now=now, policy=ValidationPolicy(max_response_bytes=1)).status == "ERROR"


def test_ocsp_missing_next_update_and_future_guard(material):
    from src.revocation_checker import _fresh, ValidationPolicy
    now = material[0]
    _fresh(now-timedelta(hours=1), None, now, ValidationPolicy())
    with pytest.raises(ValueError):
        _fresh(now-timedelta(days=2), None, now, ValidationPolicy())
    with pytest.raises(ValueError):
        _fresh(now+timedelta(hours=1), None, now, ValidationPolicy())


def test_rsa_signed_ocsp_and_crl(material, rsa_key):
    now, _, old_issuer, _, cert, _, _ = material
    issuer = cert(old_issuer.subject, rsa_key.public_key(), rsa_key, True)
    leaf = cert(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RSA leaf")]), rsa_key.public_key(), rsa_key)
    result = (ocsp.OCSPResponseBuilder().add_response(leaf, issuer, hashes.SHA1(), ocsp.OCSPCertStatus.GOOD, now-timedelta(minutes=1), now+timedelta(hours=1), None, None)
              .responder_id(ocsp.OCSPResponderEncoding.HASH, issuer).sign(rsa_key, hashes.SHA256()))
    assert validate_ocsp(result.public_bytes(serialization.Encoding.DER), leaf, issuer, issuer_trusted=True, now=now).status == "GOOD"
    crl = x509.CertificateRevocationListBuilder().issuer_name(issuer.subject).last_update(now-timedelta(minutes=1)).next_update(now+timedelta(hours=1)).sign(rsa_key, hashes.SHA256())
    assert validate_crl(crl.public_bytes(serialization.Encoding.DER), leaf, issuer, issuer_trusted=True, now=now).status == "GOOD"


def test_ca_key_usage_restrictions(material):
    now, key, old_issuer, leaf, cert, response, crl = material
    usage = x509.KeyUsage(False, False, False, False, False, True, False, False, False)
    issuer = cert(old_issuer.subject, key.public_key(), key, True, [usage])
    assert validate_ocsp(response(), leaf, issuer, issuer_trusted=True, now=now).status == "ERROR"
    assert validate_crl(crl(), leaf, issuer, issuer_trusted=True, now=now).status == "ERROR"


def test_orchestration_input_limits(material):
    leaf = material[3]
    with pytest.raises(ValueError):
        check_revocation(leaf, max_sources=100)
    with pytest.raises(ValueError):
        check_revocation(leaf, fixtures={"SHELL": (b"x",)})
    with pytest.raises(ValueError):
        check_revocation(leaf, fixtures={"CRL": (b"x",)*5})


@pytest.mark.parametrize("returned,expected", [(b"n"*32,"GOOD"),(b"wrong","ERROR"),(None,"UNKNOWN")])
def test_ocsp_nonce_signed_binding(material, returned, expected):
    now, _, issuer, leaf, _, response, _ = material
    result = validate_ocsp(response(nonce=returned),leaf,issuer,issuer_trusted=True,now=now,expected_nonce=b"n"*32)
    assert result.status == expected


def test_ocsp_nonce_request_roundtrip(material):
    now, _, issuer, leaf, _, response, crl = material
    seen=[]
    def endpoint(url, *, body, **kwargs):
        if body is None:
            return crl()
        request = ocsp.load_der_ocsp_request(body)
        nonce = request.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
        seen.append(nonce)
        return response(nonce=nonce)
    assert check_revocation(leaf,issuer,issuer_trusted=True,online=True,now=now,fetcher=endpoint,use_nonce=True).status == "GOOD"
    assert len(seen) == 1 and len(seen[0]) == 32
