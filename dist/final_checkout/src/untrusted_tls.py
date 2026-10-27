"""Isolated collection for AIA recovery, never a verified TLS result.

Only opt-in callers may use this data and must independently validate every check.
The ordinary verified TLS fetcher is not modified.
"""
import socket
import ssl
import time
from src.certificate_fetcher import TLSCertificates
from src.hostname_validator import normalize_hostname
from src.revocation_network import validate_destination, _remaining


def collect_untrusted_peer(hostname: str, port: int, timeout: float) -> TLSCertificates:
    """Pin public destination, capture peer chain, retain independent system anchors."""
    hostname = normalize_hostname(hostname)
    if port != 443 or not 0 < timeout <= 60:
        raise ValueError("Thu thập AIA chỉ hỗ trợ cổng 443 và timeout tối đa 60 giây.")
    deadline = time.monotonic() + timeout
    _, host, _, _, addresses = validate_destination(f"https://{hostname}", deadline)
    trusted = ssl.create_default_context()
    anchors = tuple(trusted.get_ca_certs(binary_form=True))
    # This context is inspection-only. It is never used by fetch_peer_chain.
    inspection = ssl.create_default_context()
    inspection.check_hostname = False
    inspection.verify_mode = ssl.CERT_NONE
    family, kind, protocol, _, address = addresses[0]
    with socket.socket(family, kind, protocol) as raw:
        raw.settimeout(_remaining(deadline))
        raw.connect(address)
        raw.settimeout(_remaining(deadline))
        with inspection.wrap_socket(raw, server_hostname=host) as tls:
            leaf = tls.getpeercert(binary_form=True)
            peer = tuple(tls.get_unverified_chain())
            if not leaf or not peer or peer[0] != leaf or len(peer) > 8 or sum(map(len, peer)) > 262144:
                raise ValueError("Chuỗi chưa tin cậy thiếu leaf hoặc vượt giới hạn.")
            return TLSCertificates(leaf, peer, anchors, peer)
