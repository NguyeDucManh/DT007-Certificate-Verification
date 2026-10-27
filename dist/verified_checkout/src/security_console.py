"""Hiển thị báo cáo terminal cho Certificate Security Verifier (không HTML)."""

from typing import Iterable

from src.certificate_security import CertificateAnalysis


def _display(value: object) -> str:
    """Giữ trường thiếu rõ ràng trên console."""
    return "N/A" if value is None else str(value)


def _section(title: str, fields: Iterable[tuple[str, object]]) -> None:
    """In nhóm trường song song."""
    print(f"\n[{title}]")
    for label, value in fields:
        print(f"{label:<25}: {_display(value)}")


def print_security_analysis(analysis: CertificateAnalysis, hostname: str, port: int) -> None:
    """In tất cả sections ngay cả khi TLS/module lỗi; hiển thị final reasons."""
    border = "=" * 40
    print(f"{border}\n DT007 - CERTIFICATE SECURITY VERIFIER\n{border}\n")
    print(f"Target                   : {hostname}:{port}")
    info, host, validity = analysis.info, analysis.hostname, analysis.validity
    _section("Certificate", (
        ("Subject", info.subject if info else None),
        ("Issuer", info.issuer if info else None),
        ("Serial Number", info.serial_number if info else None),
        ("Version", info.version if info else None),
        ("Not Before", info.not_before.isoformat() if info else None),
        ("Not After", info.not_after.isoformat() if info else None),
    ))
    _section("Hostname", (
        ("Requested Hostname", hostname), ("SAN Count", host.san_count if host else None),
        ("SAN", ", ".join(str(name.value) for name in info.san) if info and info.san else None),
        ("Status", host.status if host else "FAIL"), ("Message", host.message if host else "Hostname check unavailable"),
    ))
    _section("Validity", (
        ("Status", validity.status if validity else "FAIL"),
        ("Message", validity.message if validity else "Validity check unavailable"),
        ("Current Time (UTC)", validity.current_time.isoformat() if validity else None),
    ))
    crypto = info.crypto if info else None
    _section("Public Key", (("Algorithm", crypto.public_key_algorithm if crypto else None), ("Key Size", crypto.public_key_size if crypto else None)))
    _section("Signature", (
        ("Algorithm", crypto.signature_algorithm_name if crypto else None),
        ("OID", crypto.signature_algorithm_oid if crypto else None),
        ("Hash Algorithm", crypto.signature_hash_algorithm if crypto else None),
    ))
    chain = analysis.chain
    certificates = chain.certificates if chain else ()
    _section("Certificate Chain", (
        ("Chain Length", len(certificates)),
        ("Leaf", certificates[0].subject.rfc4514_string() if certificates else None),
        ("Intermediate", " -> ".join(cert.subject.rfc4514_string() for cert in certificates[1:-1]) or None),
        ("Terminal CA", certificates[-1].subject.rfc4514_string() if len(certificates) > 1 else None),
        ("Verified Trust Anchor", chain.trust_anchor.subject.rfc4514_string() if chain and chain.trust_anchor else None),
        ("Issuer/Subject Links", chain.issuer_subject_links if chain else "FAIL"),
        ("Signature Validation", chain.signature_validation if chain else "FAIL"),
        ("CA Constraints", chain.ca_constraints if chain else "FAIL"),
        ("Chain Validity", chain.validity if chain else "FAIL"),
        ("Trust Path", chain.trust if chain else "FAIL"),
        ("Self-signed Leaf", chain.self_signed_leaf if chain else None),
        ("Chain Status", chain.status if chain else "FAIL"),
    ))
    algorithm = analysis.algorithm
    _section("Algorithm Policy", (
        ("Public Key Algorithm", algorithm.info.public_key_algorithm if algorithm else None),
        ("Key Size", algorithm.info.public_key_size if algorithm else None),
        ("Hash Algorithm", algorithm.info.signature_hash_algorithm if algorithm else None),
        ("Public Key Policy", algorithm.public_key.status if algorithm else "FAIL"),
        ("Key Size Policy", algorithm.key_size.status if algorithm else "FAIL"),
        ("Hash Policy", algorithm.signature_hash.status if algorithm else "FAIL"),
        ("Algorithm Status", algorithm.status if algorithm else "FAIL"),
    ))
    ct = analysis.ct
    _section("Certificate Transparency", (
        ("SCT Count", len(ct.matches) if ct else None),
        ("Matched SCTs", ct.matched_count if ct else None),
        ("SCT Signatures", ct.signature_validation if ct else "NOT_VERIFIED"),
        ("CT Inclusion Proofs", ct.inclusion_validation if ct else "NOT_VERIFIED"),
    ))
    if ct:
        for index, match in enumerate(ct.matches, start=1):
            log = match.log
            print(f"\nSCT #{index}")
            for label, value in (
                ("Log ID", match.sct.log_id), ("Version", match.sct.version),
                ("Operator", log.operator if log else None),
                ("Log", log.description if log else None),
                ("State", log.state if log else None), ("MMD", log.mmd if log else None),
                ("URL / Submission URL", (log.url or log.submission_url) if log else None),
                ("Start interval", log.start_inclusive if log else None),
                ("End interval", log.end_exclusive if log else None),
                ("Timestamp", match.sct.timestamp.isoformat()),
                ("SCT vs NotAfter Interval", match.timestamp_interval),
                ("Cert Expiry Interval", match.certificate_interval),
                ("Log ID Match", match.log_id_match), ("State Policy", match.state_status),
                ("Status", match.status),
            ):
                print(f"{label:<25}: {_display(value)}")
    print(f"\nCT Overall Status        : {ct.status if ct else 'WARNING'}")
    if analysis.errors:
        _section("Module Errors", analysis.errors.items())
    _section("Security Summary", analysis.security.checks.items())
    print(f"\nFINAL RESULT: {analysis.security.status}")
    if analysis.security.reasons:
        print("Reasons:")
        for reason in analysis.security.reasons:
            print(f"- {reason}")
    print(f"\n{border}")
