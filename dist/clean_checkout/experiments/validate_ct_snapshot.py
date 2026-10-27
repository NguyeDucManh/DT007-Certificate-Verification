"""Offline quality checks against an archived official schema, without mutation."""
from __future__ import annotations
import base64
import binascii
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_der_public_key
from jsonschema import FormatChecker, validators
from experiments.dataset_profile import profile, ROOT


def validate(path: Path, schema_path: Path) -> dict:
    """Report schema, ID/SPKI and interval failures; no authenticity claims."""
    data = json.loads(path.read_bytes())
    schema = json.loads(schema_path.read_bytes())
    validator_type = validators.validator_for(schema)
    validator_type.check_schema(schema)
    errors = [f"{'/'.join(map(str, e.absolute_path))}: {e.message}" for e in validator_type(schema, format_checker=FormatChecker()).iter_errors(data)]
    key_errors = []
    checked = 0
    for i, operator in enumerate(data.get("operators", [])):
        if not isinstance(operator, dict):
            continue
        for kind in ("logs", "tiled_logs"):
            logs = operator.get(kind, [])
            if not isinstance(logs, list):
                continue
            for j, log in enumerate(logs):
                label = f"operators/{i}/{kind}/{j}"
                try:
                    if not isinstance(log, dict):
                        raise ValueError("log không phải object")
                    key = base64.b64decode(log["key"], validate=True)
                    ident = base64.b64decode(log["log_id"], validate=True)
                    load_der_public_key(key)
                    if len(ident) != 32 or hashlib.sha256(key).digest() != ident:
                        raise ValueError("Log ID không khớp SHA256 của DER public key")
                    checked += 1
                except (KeyError, TypeError, ValueError, binascii.Error) as exc:
                    key_errors.append(f"{label}: {exc}")
    return {"dataset_profile": profile(path), "schema_sha256": hashlib.sha256(schema_path.read_bytes()).hexdigest(), "schema_errors": errors, "public_keys_and_ids_verified": checked, "key_errors": key_errors,
            "publisher_signature": "NOT_VERIFIED: không có detached signature của snapshot tương ứng", "license": "Chrome CT Log Lists Acceptable Use Policy đã lưu; không xác nhận quyền tái phân phối không giới hạn", "source_policy": "https://github.com/GoogleChrome/CertificateTransparency/blob/main/log_lists.md"}


if __name__ == "__main__":
    result = validate(ROOT / "data/log_list.json", ROOT / "reports/research_sources/20261010/ct_log_list_schema.json")
    out = ROOT / "reports/ct_snapshot_validation.json"
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print("schema_errors", len(result["schema_errors"]), "key_errors", len(result["key_errors"]), "verified_keys", result["public_keys_and_ids_verified"])
