"""Actual local TLS/HTTP end-to-end, not live Internet; policy bypass confined to test."""
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import ssl
import threading
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import AuthorityInformationAccessOID
from src.certificate_security import analyze_certificate
import src.untrusted_tls as inspection
import src.revocation_network as transport


def test_missing_intermediate_recovered_over_real_local_tls(chain_factory, chain_signing_keys, rsa_key, tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    def no_internet_registry():
        raise OSError("local test: no Internet CT fetch")
    monkeypatch.setattr("src.certificate_security.load_official_registry", no_internet_registry)
    leaf, intermediate, root = chain_factory(at=now)
    builder = x509.CertificateBuilder().subject_name(leaf.subject).issuer_name(leaf.issuer).public_key(leaf.public_key()).serial_number(leaf.serial_number).not_valid_before(leaf.not_valid_before_utc).not_valid_after(leaf.not_valid_after_utc)
    for ext in leaf.extensions:
        builder = builder.add_extension(ext.value, ext.critical)
    leaf = builder.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier("http://ca.example.test/issuer.der"))]), False).sign(chain_signing_keys[1], hashes.SHA256())
    for name, cert in (("leaf", leaf), ("root", root)):
        (tmp_path/f"{name}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile = tmp_path/"key.pem"
    keyfile.write_bytes(rsa_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    issuer_der = intermediate.public_bytes(serialization.Encoding.DER)
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(issuer_der)))
            self.end_headers()
            self.wfile.write(issuer_der)
        def log_message(self, *args):
            pass
    http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=http.serve_forever, daemon=True).start()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(10)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(tmp_path/"leaf.pem", keyfile)
    def serve():
        for _ in range(2):
            try:
                raw, _ = listener.accept()
                with raw:
                    try:
                        with server_context.wrap_socket(raw, server_side=True):
                            pass
                    except ssl.SSLError:
                        pass
            except OSError:
                break
    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    original_context = ssl.create_default_context
    def trusted_context(*args, **kwargs):
        context = original_context(*args, **kwargs)
        context.load_verify_locations(tmp_path/"root.pem")
        return context
    monkeypatch.setattr(ssl, "create_default_context", trusted_context)
    def route(url, deadline):
        is_tls = url.startswith("https:")
        port = listener.getsockname()[1] if is_tls else http.server_port
        return ("https" if is_tls else "http", "example.com" if is_tls else "ca.example.test", 443 if is_tls else 80, "/issuer.der", [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", port))])
    monkeypatch.setattr(inspection, "validate_destination", route)
    monkeypatch.setattr(transport, "validate_destination", route)
    def verified_fetch(host, port, timeout):
        with socket.create_connection(listener.getsockname(), timeout=timeout) as raw:
            with trusted_context().wrap_socket(raw, server_hostname=host):
                raise AssertionError("Server sent leaf only: verified handshake must fail")
    try:
        result = analyze_certificate("example.com", 443, 10, Path("data/log_list.json"), Path("config/algorithm_policy.json"), now, verified_fetch, advanced=True)
        assert result.extensions["tls_collection"]["status"] == "UNTRUSTED", result.errors
        assert result.extensions["aia"]["status"] == "PASS", result.extensions["aia"]
        assert result.chain.trust_anchor == root
        assert result.hostname.status == "PASS" and result.chain.status == "PASS"
        assert result.security.status == "WARNING"  # no SCT/revocation data, never cosmetic PASS
    finally:
        listener.close()
        http.shutdown()
        http.server_close()
        worker.join(timeout=3)
