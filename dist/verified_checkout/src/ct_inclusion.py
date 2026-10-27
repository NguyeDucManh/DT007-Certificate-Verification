"""Bounded RFC6962 STH and inclusion client, never applied to static/tiled logs."""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from urllib.parse import urlencode
from src.ct_crypto import signed_entry, verify_inclusion, verify_sct, verify_sth, verify_consistency
from src.ct_registry import TrustedRegistry
from src.revocation_network import fetch_bytes, FetchPolicy
from src.sct_parser import SCTRecord


def _integer(value: object) -> int:
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError("Số nguyên CT không hợp lệ.")
    return value


def check_inclusion(sct: SCTRecord, certificate_der: bytes, registry: TrustedRegistry, *, now: datetime | None = None,
                    fetcher=fetch_bytes, previous_sth: dict | None = None, **entry_args) -> dict:
    """Bind trusted log, valid SCT, exact leaf, fresh signed STH and audit path.

    No previous checkpoint: do not claim append-only consistency or gossip.
    A supplied checkpoint is authenticated and requires a valid consistency proof.
    """
    result = {"status": "NOT_VERIFIED", "reason": "Chưa đủ bằng chứng inclusion.", "log_id": sct.log_id, "consistency": "NOT_VERIFIED"}
    log = registry.logs.get(sct.log_id)
    if log is None:
        return dict(result, reason="Không có CT Log trong registry đã xác thực.")
    if log["protocol"] != "rfc6962":
        return dict(result, status="UNSUPPORTED", reason="Tiled/static CT không dùng endpoint RFC6962; chưa hỗ trợ proof protocol này.")
    verified = verify_sct(sct, certificate_der, registry.keys, **entry_args)
    if verified.status != "VALID":
        return dict(result, reason="Chưa có SCT với chữ ký hợp lệ để liên kết inclusion: " + verified.reason)
    policy = FetchPolicy(timeout=5, max_bytes=262144, max_redirects=0)
    try:
        url = log["url"].rstrip("/") + "/ct/v1/"
        sth = json.loads(fetcher(url+"get-sth", policy=policy))
        stamp, size = _integer(sth["timestamp"]), _integer(sth["tree_size"])
        if size == 0:
            return dict(result, reason="Cây log rỗng; chưa có bằng chứng đưa vào cây.")
        root = base64.b64decode(sth["sha256_root_hash"], validate=True)
        signature = base64.b64decode(sth["tree_head_signature"], validate=True)
        if len(signature) < 4 or len(signature) != int.from_bytes(signature[2:4], "big")+4:
            raise ValueError("DigitallySigned STH không hợp lệ.")
        if signature[0] != 4 or signature[1] not in (1, 3):
            return dict(result, status="UNSUPPORTED", reason="Thuật toán chữ ký STH chưa hỗ trợ.")
        auth = verify_sth(registry.keys[sct.log_id], stamp, size, root, signature[4:], "RSA" if signature[1] == 1 else "ECDSA")
        if auth.status != "VALID":
            return dict(result, status=auth.status, reason=auth.reason)
        clock = now or datetime.now(timezone.utc)
        when = datetime.fromtimestamp(stamp/1000, tz=timezone.utc)
        if when > clock+timedelta(minutes=5) or clock-when > timedelta(hours=24) or when < sct.timestamp:
            return dict(result, reason="STH quá cũ, nằm trong tương lai hoặc trước SCT; chưa đủ bằng chứng inclusion hiện tại.")
        if previous_sth is not None:
            old_size, old_stamp = _integer(previous_sth["tree_size"]), _integer(previous_sth["timestamp"])
            old_root = base64.b64decode(previous_sth["sha256_root_hash"], validate=True)
            old_sig = base64.b64decode(previous_sth["tree_head_signature"], validate=True)
            if len(old_sig) < 4 or old_sig[0] != 4 or old_sig[1] not in (1, 3) or len(old_sig) != int.from_bytes(old_sig[2:4], "big")+4:
                raise ValueError("Chữ ký checkpoint trước không hợp lệ.")
            old_auth = verify_sth(registry.keys[sct.log_id], old_stamp, old_size, old_root, old_sig[4:], "RSA" if old_sig[1] == 1 else "ECDSA")
            if old_auth.status != "VALID" or old_stamp > stamp or old_size > size:
                return dict(result, status="INVALID", reason="Checkpoint trước không được xác thực hoặc cây log bị lùi.")
            consistency = json.loads(fetcher(url+"get-sth-consistency?"+urlencode({"first": old_size, "second": size}), policy=policy))["consistency"] if old_size != size else []
            if not isinstance(consistency, list) or len(consistency) > 64 or not verify_consistency(old_size, size, old_root, root, tuple(base64.b64decode(p, validate=True) for p in consistency)):
                return dict(result, status="INVALID", reason="Không xác minh được append-only consistency giữa hai STH.")
            result["consistency"] = "VALID"
        leaf = signed_entry(sct, certificate_der, **entry_args)
        leaf_hash = hashlib.sha256(b"\x00"+leaf).digest()
        query = urlencode({"hash": base64.b64encode(leaf_hash).decode(), "tree_size": size})
        proof = json.loads(fetcher(url+"get-proof-by-hash?"+query, policy=policy))
        index = _integer(proof["leaf_index"])
        if not isinstance(proof["audit_path"], list) or len(proof["audit_path"]) > 64:
            raise ValueError("Merkle audit path không hợp lệ.")
        path = tuple(base64.b64decode(p, validate=True) for p in proof["audit_path"])
        if not verify_inclusion(leaf, index, size, path, root):
            return dict(result, status="INVALID", reason="Merkle path không khớp leaf hoặc root trong STH đã xác thực.")
        explanation = "Đã kiểm tra consistency với checkpoint; chưa có gossip." if result["consistency"] == "VALID" else "Chưa kiểm tra consistency/gossip."
        return dict(result, status="VALID", reason="SCT có chữ ký hợp lệ; leaf khớp inclusion proof trong STH còn mới đã xác thực. " + explanation,
                    leaf_hash=base64.b64encode(leaf_hash).decode(), tree_size=size, leaf_index=index, sth_timestamp=stamp, source=url,
                    signed_tree_head=sth, audit_path=proof["audit_path"], registry_sha256=registry.sha256)
    except Exception as exc:
        return dict(result, reason="Không đủ bằng chứng endpoint hoặc lỗi dữ liệu CT: " + (str(exc) or type(exc).__name__))
