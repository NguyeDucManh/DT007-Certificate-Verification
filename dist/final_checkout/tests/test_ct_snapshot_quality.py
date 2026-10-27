"""Official schema and independent SPKI/Log ID quality checks."""
import json
from pathlib import Path
import pytest
from experiments.validate_ct_snapshot import validate

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data/log_list.json"
SCHEMA = ROOT / "reports/research_sources/20261010/ct_log_list_schema.json"


def test_current_snapshot_schema_and_keys():
    result = validate(DATA, SCHEMA)
    assert result["schema_errors"] == [] and result["key_errors"] == []
    counts = result["dataset_profile"]["logs_by_type"]
    assert result["public_keys_and_ids_verified"] == sum(counts.values())
    assert result["publisher_signature"].startswith("NOT_VERIFIED")


@pytest.mark.parametrize("field,value", [("log_id", "!invalid!"), ("key", "AAAA"), ("mmd", "not-a-number")])
def test_corrupt_snapshot_is_reported(tmp_path, field, value):
    data = json.loads(DATA.read_bytes())
    log = next(log for operator in data["operators"] for log in operator.get("logs", []))
    log[field] = value
    path = tmp_path / "corrupt.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    result = validate(path, SCHEMA)
    assert result["schema_errors"] or result["key_errors"]


def test_log_id_hash_mismatch_cannot_be_hidden(tmp_path):
    data = json.loads(DATA.read_bytes())
    log = next(log for operator in data["operators"] for log in operator.get("logs", []))
    log["log_id"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    path = tmp_path / "corrupt.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    assert any("SHA256" in e for e in validate(path, SCHEMA)["key_errors"])
