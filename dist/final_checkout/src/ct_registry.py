"""Authenticated Google CT list, separate from immutable research snapshot."""
import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from src.revocation_network import fetch_bytes, FetchPolicy

ORIGIN = "https://www.gstatic.com/ct/log_list/v3/"
PIN_PEM_SHA256 = "a284e4ad744211a6636a03c59aca9446ecd5ff2c14d7cb6edd69f7ba2108bf95"
KEY_PATH = Path(__file__).resolve().parents[1]/"config/ct_log_list_pubkey.pem"


@dataclass(frozen=True)
class TrustedRegistry:
    """Trust is established by pinned publisher signature, not matching Log ID."""
    keys: dict[str, bytes]
    logs: dict[str, dict]
    sha256: str
    timestamp: str


def validate_registry(data: bytes, signature: bytes, pem: bytes, *, now: datetime | None = None, require_pin: bool = True) -> TrustedRegistry:
    """Verify exact JSON bytes before parsing keys; reject stale/ambiguous entries."""
    if require_pin and hashlib.sha256(pem).hexdigest() != PIN_PEM_SHA256:
        raise ValueError("Khóa publisher không khớp pin chính thức.")
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("Publisher key không phải RSA.")
    key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
    obj = json.loads(data)
    stamp = datetime.fromisoformat(obj["log_list_timestamp"].replace("Z", "+00:00"))
    clock = now or datetime.now(timezone.utc)
    if stamp.tzinfo is None or clock-stamp > timedelta(days=14) or stamp-clock > timedelta(minutes=5):
        raise ValueError("Danh sách khóa CT quá cũ hoặc timestamp không hợp lệ.")
    keys, logs = {}, {}
    for operator in obj["operators"]:
        for kind in ("logs", "tiled_logs"):
            for log in operator.get(kind, []):
                ident, raw = log["log_id"], base64.b64decode(log["key"], validate=True)
                serialization.load_der_public_key(raw)
                if base64.b64encode(hashlib.sha256(raw).digest()).decode() != ident or ident in keys:
                    raise ValueError("Log ID/key trùng hoặc không khớp.")
                keys[ident] = raw
                logs[ident] = dict(log, protocol="rfc6962" if kind == "logs" else "static", operator=operator["name"])
    return TrustedRegistry(keys, logs, hashlib.sha256(data).hexdigest(), stamp.isoformat())


def load_official_registry(*, fetcher=fetch_bytes) -> TrustedRegistry:
    """Three fixed Google URLs, no redirects; no mutation of research dataset."""
    policy = FetchPolicy(timeout=8, max_bytes=2*1024*1024, max_redirects=0)
    data = fetcher(ORIGIN+"log_list.json", policy=policy)
    signature = fetcher(ORIGIN+"log_list.sig", policy=policy)
    return validate_registry(data, signature, KEY_PATH.read_bytes())
