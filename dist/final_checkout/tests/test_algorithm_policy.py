"""Kiểm tra policy từ JSON, thresholds, blocked và field thiếu."""

from pathlib import Path

import pytest

from src.algorithm_policy import PolicyError, evaluate_algorithm, load_policy
from src.crypto_info import CryptoInfo


@pytest.fixture
def policy() -> dict:
    return load_policy(Path(__file__).resolve().parents[1] / "config" / "algorithm_policy.json")


@pytest.mark.parametrize("algorithm,size,hash_name,status", [
    ("RSA", 2048, "sha256", "PASS"), ("RSA", 4096, "sha256", "PASS"),
    ("RSA", 1024, "sha256", "FAIL"), ("EC", 256, "sha256", "PASS"),
    ("EC", 224, "sha256", "FAIL"), ("RSA", 2048, "sha384", "PASS"),
    ("RSA", 2048, "sha512", "PASS"), ("RSA", 2048, "sha1", "FAIL"),
    ("RSA", 2048, "md5", "FAIL"), ("DSA", 2048, "sha256", "FAIL"),
    ("UNKNOWN", None, "sha256", "FAIL"), ("RSA", None, "sha256", "FAIL"),
    ("RSA", 2048, "unknown-hash", "FAIL"),
])
def test_algorithm_rules(policy: dict, algorithm: str, size: int | None, hash_name: str, status: str) -> None:
    info = CryptoInfo(algorithm, size, "1.2.3", "TEST_SIGNATURE", hash_name)
    result = evaluate_algorithm(info, policy)
    assert result.status == status
    assert bool(result.reasons) == (status != "PASS")


@pytest.mark.parametrize("algorithm", ["Ed25519", "Ed448"])
def test_native_signature_hash(policy: dict, algorithm: str) -> None:
    info = CryptoInfo(algorithm, None, "1.2.3", algorithm.upper(), None)
    assert evaluate_algorithm(info, policy).status == "PASS"


def test_unknown_hashless_signature(policy: dict) -> None:
    info = CryptoInfo("RSA", 2048, "1.2.3", "UNKNOWN", None)
    assert evaluate_algorithm(info, policy).signature_hash.status == "FAIL"


def test_blocked_overrides_allowed(policy: dict) -> None:
    policy["public_key_algorithms"]["allowed"].append("DSA")
    assert evaluate_algorithm(CryptoInfo("DSA", 2048, "1.2.3", "DSA_WITH_SHA256", "sha256"), policy).public_key.status == "FAIL"


def test_dsa_size_rule(policy: dict) -> None:
    result = evaluate_algorithm(CryptoInfo("DSA", 1024, "1.2.3", "DSA_WITH_SHA256", "sha256"), policy)
    assert result.public_key.status == "FAIL" and result.key_size.status == "FAIL"


@pytest.mark.parametrize("field", ["rsa", "hash", "public_key_algorithms"])
def test_missing_policy_field(policy: dict, field: str) -> None:
    del policy[field]
    result = evaluate_algorithm(CryptoInfo("RSA", 2048, "1.2.3", "RSA_WITH_SHA256", "sha256"), policy)
    assert result.status == "FAIL" and result.reasons


@pytest.mark.parametrize("minimum", [None, -1, True, "2048"])
def test_invalid_minimum(policy: dict, minimum: object) -> None:
    policy["rsa"]["minimum_key_size"] = minimum
    assert evaluate_algorithm(CryptoInfo("RSA", 2048, "1.2.3", "RSA_WITH_SHA256", "sha256"), policy).status == "FAIL"


def test_empty_policy() -> None:
    assert evaluate_algorithm(CryptoInfo("RSA", 2048, "1.2.3", "RSA_WITH_SHA256", "sha256"), {}).status == "FAIL"


def test_invalid_policy_json(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text("{invalid", encoding="utf-8")
    with pytest.raises(PolicyError, match="algorithm policy"):
        load_policy(path)


def test_missing_policy_file(tmp_path: Path) -> None:
    with pytest.raises(PolicyError):
        load_policy(tmp_path / "missing.json")


def test_non_object_policy(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(PolicyError, match="JSON object"):
        load_policy(path)
