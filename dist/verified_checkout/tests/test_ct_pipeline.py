"""Signed list, precertificate reconstruction and endpoint integration fixtures."""
import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.x509.oid import ExtensionOID, ObjectIdentifier
import pytest
from src.ct_registry import validate_registry, TrustedRegistry
from src.ct_signed_input import precert_input, wrap, tlvs
from src.ct_crypto import signed_entry, verify_sct, verify_consistency
from src.ct_inclusion import check_inclusion
from src.sct_parser import SCTRecord, parse_scts


def _builder(cert, issuer=None):
    builder = x509.CertificateBuilder().subject_name(cert.subject).issuer_name(issuer or cert.issuer).public_key(cert.public_key()).serial_number(cert.serial_number).not_valid_before(cert.not_valid_before_utc).not_valid_after(cert.not_valid_after_utc)
    for ext in cert.extensions:
        builder = builder.add_extension(ext.value, ext.critical)
    return builder


@pytest.fixture
def ct_material(chain_factory, chain_signing_keys, reference_time):
    leaf, issuer, root = chain_factory()
    issuer_key = chain_signing_keys[1]
    key = ec.generate_private_key(ec.SECP256R1())
    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ident = base64.b64encode(hashlib.sha256(spki).digest()).decode()
    sct = SCTRecord(ident, reference_time-timedelta(minutes=1), "v1", signature=b"fixture", hash_algorithm="sha256", signature_algorithm="ECDSA", entry_type="PRE_CERTIFICATE")
    poison = _builder(leaf).add_extension(x509.PrecertPoison(), True).sign(issuer_key, hashes.SHA256())
    args = precert_input(poison, issuer)
    data = signed_entry(sct, None, **args)
    signature = key.sign(data, ec.ECDSA(hashes.SHA256()))
    ms = int(sct.timestamp.timestamp())*1000
    raw = b"\x00"+base64.b64decode(ident)+ms.to_bytes(8,"big")+b"\x00\x00\x04\x03"+len(signature).to_bytes(2,"big")+signature
    payload = len(raw).to_bytes(2,"big")+raw
    value = len(payload).to_bytes(2,"big")+payload
    final = _builder(leaf).add_extension(x509.UnrecognizedExtension(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS, wrap(4,value)), False).sign(issuer_key, hashes.SHA256())
    sct = parse_scts(final).scts[0]
    return final, issuer, key, spki, sct, args


def test_reconstructed_final_leaf_matches_poison_and_valid_signature(ct_material):
    final, issuer, _, spki, sct, original = ct_material
    reconstructed = precert_input(final, issuer)
    assert reconstructed == original
    assert verify_sct(sct, final.public_bytes(serialization.Encoding.DER), {sct.log_id: spki}, **reconstructed).status == "VALID"
    wrong = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert verify_sct(sct, None, {sct.log_id: wrong}, **reconstructed).status == "INVALID"
    assert verify_sct(replace(sct, signature=b"wrong"), None, {sct.log_id: spki}, **reconstructed).status == "INVALID"


def test_rsa_sct_signature(certificate, rsa_key, reference_time):
    spki = rsa_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ident = base64.b64encode(hashlib.sha256(spki).digest()).decode()
    sct = SCTRecord(ident, reference_time, "v1", signature=b"placeholder", hash_algorithm="sha256", signature_algorithm="RSA", entry_type="X509_CERTIFICATE")
    der = certificate.public_bytes(serialization.Encoding.DER)
    sct = replace(sct, signature=rsa_key.sign(signed_entry(sct, der), padding.PKCS1v15(), hashes.SHA256()))
    assert verify_sct(sct, der, {ident:spki}).status == "VALID"
    assert verify_sct(replace(sct, extensions=b"wrong"), der, {ident:spki}).status == "INVALID"


def test_registry_signature_not_just_log_id(ct_material, rsa_key, reference_time):
    _, _, _, spki, sct, _ = ct_material
    obj = {"log_list_timestamp":reference_time.isoformat(), "operators":[{"name":"Local fixture", "logs":[{"log_id":sct.log_id,"key":base64.b64encode(spki).decode(),"url":"https://log.example/"}]}]}
    data = json.dumps(obj).encode()
    pem = rsa_key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    signature = rsa_key.sign(data,padding.PKCS1v15(),hashes.SHA256())
    assert validate_registry(data, signature, pem, now=reference_time, require_pin=False).keys[sct.log_id] == spki
    with pytest.raises(InvalidSignature):
        validate_registry(data+b" ", signature, pem, now=reference_time, require_pin=False)
    with pytest.raises(ValueError):
        validate_registry(data, signature, pem, now=reference_time, require_pin=True)
    with pytest.raises(ValueError):
        validate_registry(data, signature, pem, now=reference_time+timedelta(days=15), require_pin=False)


@pytest.mark.parametrize("fault", [None, "root", "signature", "stale", "network", "static", "checkpoint", "consistency"])
def test_inclusion_endpoint_binding(ct_material, reference_time, fault):
    final, _, key, spki, sct, args = ct_material
    leaf = signed_entry(sct, None, **args)
    root = hashlib.sha256(b"\x00"+leaf).digest()
    old_root = root
    size=1
    branch=[]
    if fault == "consistency":
        branch = [hashlib.sha256(b"\x00"+v).digest() for v in (b"other-leaf-b",b"other-leaf-c")]
        root = hashlib.sha256(b"\x01"+hashlib.sha256(b"\x01"+root+branch[0]).digest()+branch[1]).digest()
        size=3
    if fault == "root":
        root = b"x"*32
    stamp = int(reference_time.timestamp())*1000
    if fault == "stale":
        stamp -= 2*86400000
    sig = key.sign(b"\x00\x01"+stamp.to_bytes(8,"big")+size.to_bytes(8,"big")+root, ec.ECDSA(hashes.SHA256()))
    if fault == "signature":
        sig = b"wrong"
    sth = {"timestamp":stamp,"tree_size":size,"sha256_root_hash":base64.b64encode(root).decode(),"tree_head_signature":base64.b64encode(b"\x04\x03"+len(sig).to_bytes(2,"big")+sig).decode()}
    checkpoint=sth if fault=="checkpoint" else None
    if fault=="consistency":
        old_sig=key.sign(b"\x00\x01"+(stamp-1000).to_bytes(8,"big")+(1).to_bytes(8,"big")+old_root,ec.ECDSA(hashes.SHA256()))
        checkpoint={"timestamp":stamp-1000,"tree_size":1,"sha256_root_hash":base64.b64encode(old_root).decode(),"tree_head_signature":base64.b64encode(b"\x04\x03"+len(old_sig).to_bytes(2,"big")+old_sig).decode()}
    registry = TrustedRegistry({sct.log_id:spki},{sct.log_id:{"protocol":"static" if fault == "static" else "rfc6962","url":"https://log.example/"}},"test",reference_time.isoformat())
    calls=[]
    def fetch(url, **kwargs):
        calls.append(url)
        if fault == "network":
            raise TimeoutError("fixture timeout")
        payload={"consistency":[base64.b64encode(v).decode() for v in branch]} if "get-sth-consistency" in url else sth if "get-sth" in url else {"leaf_index":0,"audit_path":[base64.b64encode(v).decode() for v in branch]}
        return json.dumps(payload).encode()
    result = check_inclusion(sct, final.public_bytes(serialization.Encoding.DER), registry, now=reference_time, fetcher=fetch, previous_sth=checkpoint, **args)
    expected = "VALID" if fault in (None,"checkpoint","consistency") else "INVALID" if fault in ("root","signature") else "UNSUPPORTED" if fault == "static" else "NOT_VERIFIED"
    assert result["status"] == expected
    if fault is None:
        assert "hash=" in calls[1] and result["consistency"] == "NOT_VERIFIED"
    if fault in ("checkpoint","consistency"):
        assert result["consistency"] == "VALID"


def test_engine_calls_authenticated_sct_and_proof(ct_material, reference_time, tmp_path, monkeypatch):
    import src.certificate_security as engine
    from src.certificate_fetcher import TLSCertificates
    from src.revocation_checker import RevocationResult
    final, issuer, key, spki, sct, args = ct_material
    registry = TrustedRegistry({sct.log_id:spki},{sct.log_id:{"protocol":"rfc6962","url":"https://log.example/"}},"fixture",reference_time.isoformat())
    dataset = tmp_path/"logs.json"
    dataset.write_text(json.dumps({"version":"test", "operators":[{"name":"Fixture","logs":[{"description":"Local log", "log_id":sct.log_id,"key":base64.b64encode(spki).decode(),"state":{"usable":{"timestamp":reference_time.isoformat()}},"url":"https://log.example/"}]}]}),encoding="utf8")
    monkeypatch.setattr(engine,"load_official_registry",lambda:registry)
    monkeypatch.setattr(engine,"check_revocation",lambda *a,**kw:RevocationResult("GOOD","fixture"))
    leaf = signed_entry(sct,None,**args)
    root = hashlib.sha256(b"\x00"+leaf).digest()
    stamp = int(reference_time.timestamp())*1000
    sig = key.sign(b"\x00\x01"+stamp.to_bytes(8,"big")+(1).to_bytes(8,"big")+root,ec.ECDSA(hashes.SHA256()))
    sth = {"timestamp":stamp,"tree_size":1,"sha256_root_hash":base64.b64encode(root).decode(),"tree_head_signature":base64.b64encode(b"\x04\x03"+len(sig).to_bytes(2,"big")+sig).decode()}
    def endpoint(url, **kwargs):
        return json.dumps(sth if "get-sth" in url else {"leaf_index":0,"audit_path":[]}).encode()
    monkeypatch.setattr(engine,"check_inclusion",lambda *a,**kw:check_inclusion(*a,fetcher=endpoint,**kw))
    der = final.public_bytes(serialization.Encoding.DER)
    ca = issuer.public_bytes(serialization.Encoding.DER)
    result = engine.analyze_certificate("example.com",443,1,dataset,__import__('pathlib').Path("config/algorithm_policy.json"),reference_time,lambda *a:TLSCertificates(der,(der,ca),(ca,)),advanced=True)
    assert result.ct.signature_validation == result.ct.inclusion_validation == "VALID"
    assert result.extensions["sct_verification"][0]["status"] == "VALID"
    assert result.security.status == "WARNING"  # consistency/metadata policy remains explicit


def test_consistency_prefix_proof():
    a,b,c = [hashlib.sha256(b"\x00"+x).digest() for x in (b"a",b"b",b"c")]
    ab = hashlib.sha256(b"\x01"+a+b).digest()
    abc = hashlib.sha256(b"\x01"+ab+c).digest()
    assert verify_consistency(1,3,a,abc,(b,c))
    assert verify_consistency(2,3,ab,abc,(c,))
    assert verify_consistency(3,3,abc,abc,())
    assert not verify_consistency(2,3,ab,abc,(a,))
    # Independently generate recursive RFC subproofs, verify all small tree shapes.
    leaves=[bytes([i]) for i in range(1,18)]
    def root(items):
        if len(items)==1:
            return hashlib.sha256(b"\x00"+items[0]).digest()
        split=1<<((len(items)-1).bit_length()-1)
        return hashlib.sha256(b"\x01"+root(items[:split])+root(items[split:])).digest()
    def subproof(m,items,complete):
        if m==len(items):
            return [] if complete else [root(items)]
        split=1<<((len(items)-1).bit_length()-1)
        return subproof(m,items[:split],complete)+[root(items[split:])] if m<=split else subproof(m-split,items[split:],False)+[root(items[:split])]
    for second in range(2,18):
        for first in range(1,second):
            assert verify_consistency(first,second,root(leaves[:first]),root(leaves[:second]),tuple(subproof(first,leaves[:second],True)))


def test_preissuer_rewrites_issuer_and_aki(chain_factory, chain_signing_keys):
    from cryptography.x509.oid import NameOID
    leaf, issuer, _ = chain_factory()
    prekey = ec.generate_private_key(ec.SECP256R1())
    pre = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"Local preissuer")]))
           .issuer_name(issuer.subject).public_key(prekey.public_key()).serial_number(123)
           .not_valid_before(leaf.not_valid_before_utc).not_valid_after(leaf.not_valid_after_utc)
           .add_extension(x509.BasicConstraints(True,None),True)
           .add_extension(x509.ExtendedKeyUsage([ObjectIdentifier("1.3.6.1.4.1.11129.2.4.4")]),False)
           .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.public_key()),False)
           .sign(chain_signing_keys[1],hashes.SHA256()))
    final = _builder(leaf).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.public_key()),False).sign(chain_signing_keys[1],hashes.SHA256())
    precert = _builder(leaf,pre.subject).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(pre.public_key()),False).add_extension(x509.PrecertPoison(),True).sign(prekey,hashes.SHA256())
    assert precert_input(precert,issuer,preissuer=pre)["precertificate_tbs"] == final.tbs_certificate_bytes
    with pytest.raises(ValueError):
        precert_input(precert,issuer)  # must not guess away delegated issuer


def test_noncritical_poison_rejected(chain_factory, chain_signing_keys):
    leaf,issuer,_ = chain_factory()
    malformed = _builder(leaf).add_extension(x509.PrecertPoison(),False).sign(chain_signing_keys[1],hashes.SHA256())
    with pytest.raises(ValueError,match="critical"):
        precert_input(malformed,issuer)


def test_unknown_wire_hash_retains_metadata(ct_material, chain_signing_keys):
    final,_,_,_,sct,_ = ct_material
    ms=int(sct.timestamp.timestamp())*1000
    raw=b"\x00"+base64.b64decode(sct.log_id)+ms.to_bytes(8,"big")+b"\x00\x00\x00\x03"+len(sct.signature).to_bytes(2,"big")+sct.signature
    payload=len(raw).to_bytes(2,"big")+raw
    value=len(payload).to_bytes(2,"big")+payload
    builder=x509.CertificateBuilder().subject_name(final.subject).issuer_name(final.issuer).public_key(final.public_key()).serial_number(final.serial_number).not_valid_before(final.not_valid_before_utc).not_valid_after(final.not_valid_after_utc)
    for ext in final.extensions:
        if ext.oid != ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS:
            builder=builder.add_extension(ext.value,ext.critical)
    unknown=builder.add_extension(x509.UnrecognizedExtension(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS,wrap(4,value)),False).sign(chain_signing_keys[1],hashes.SHA256())
    parsed=parse_scts(unknown)
    assert len(parsed.scts)==1 and parsed.scts[0].log_id==sct.log_id
    assert parsed.scts[0].hash_algorithm is None and parsed.scts[0].signature==sct.signature


@pytest.mark.parametrize("data", [b"\x30\x80", b"\x30\x81\x01x", b"\x30\x02x"])
def test_der_rejects_noncanonical_and_truncated(data):
    with pytest.raises(ValueError):
        tlvs(data)
