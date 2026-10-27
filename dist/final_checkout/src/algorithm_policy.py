"""Đánh giá public key và signature hash bằng policy JSON bên ngoài."""

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from src.crypto_info import CryptoInfo


class PolicyError(ValueError):
    """Không thể đọc hoặc hiểu file policy."""


@dataclass(frozen=True)
class PolicyRule:
    """Kết quả một rule độc lập."""

    status: str
    message: str


@dataclass(frozen=True)
class AlgorithmResult:
    """Ba rule và kết luận policy, không bỏ qua field thiếu."""

    info: CryptoInfo
    public_key: PolicyRule
    key_size: PolicyRule
    signature_hash: PolicyRule

    @property
    def status(self) -> str:
        """FAIL ưu tiên WARNING và PASS."""
        states = (self.public_key.status, self.key_size.status, self.signature_hash.status)
        return "FAIL" if "FAIL" in states else "WARNING" if "WARNING" in states else "PASS"

    @property
    def reasons(self) -> tuple[str, ...]:
        """Thông báo cho các rule không PASS."""
        return tuple(rule.message for rule in (self.public_key, self.key_size, self.signature_hash) if rule.status != "PASS")


def load_policy(path: Path) -> dict[str, Any]:
    """Đọc JSON UTF-8, báo lỗi rõ; schema thiếu được đánh giá fail closed."""
    try:
        with Path(path).open(encoding="utf-8-sig") as stream:
            policy = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PolicyError(f"Không thể đọc algorithm policy {path}: {exc}") from exc
    if not isinstance(policy, dict):
        raise PolicyError("Algorithm policy phải là JSON object.")
    return policy


def _names(section: dict[str, Any], field: str) -> list[str] | None:
    """Đọc danh sách tên hợp lệ, từ chối cả list sai kiểu lẫn field thiếu."""
    value = section.get(field)
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        return None
    return [item.casefold() for item in value]


def _allow_rule(name: str | None, section: object, label: str) -> PolicyRule:
    """Blocked luôn ưu tiên allowed; policy thiếu/sai không trở thành PASS."""
    if not isinstance(section, dict):
        return PolicyRule("FAIL", f"Missing/invalid policy field: {label}")
    allowed, blocked = _names(section, "allowed"), _names(section, "blocked")
    if allowed is None or blocked is None:
        return PolicyRule("FAIL", f"Missing/invalid allowed or blocked list: {label}")
    normalized = name.casefold() if name is not None else ""
    if normalized in blocked:
        return PolicyRule("FAIL", f"Blocked {label}: {name}")
    if not normalized or normalized not in allowed:
        return PolicyRule("FAIL", f"Unknown/not allowed {label}: {name or 'N/A'}")
    return PolicyRule("PASS", f"Allowed {label}: {name}")


def evaluate_algorithm(info: CryptoInfo, policy: dict[str, Any]) -> AlgorithmResult:
    """Kiểm tra key algorithm, minimum size và signature hash theo policy."""
    public_key = _allow_rule(info.public_key_algorithm, policy.get("public_key_algorithms"), "public key algorithm")
    algorithm = info.public_key_algorithm.casefold()
    if algorithm in ("rsa", "ec", "dsa"):
        section = policy.get(algorithm)
        minimum = section.get("minimum_key_size") if isinstance(section, dict) else None
        if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum <= 0:
            key_size = PolicyRule("FAIL", f"Missing/invalid policy field: {algorithm}.minimum_key_size")
        elif info.public_key_size is None or info.public_key_size < minimum:
            key_size = PolicyRule("FAIL", f"{info.public_key_algorithm} key size below policy minimum ({minimum} bits)")
        else:
            key_size = PolicyRule("PASS", f"Key size meets policy minimum ({minimum} bits)")
    elif public_key.status == "PASS" and algorithm in ("ed25519", "ed448"):
        key_size = PolicyRule("PASS", "Key size rule is not applicable to this fixed-size key algorithm")
    else:
        key_size = PolicyRule("FAIL", "Cannot evaluate key size for unknown/blocked key algorithm")
    hash_section = policy.get("hash")
    if info.signature_hash_algorithm is None:
        allowed = _names(hash_section, "allowed_without_external_hash") if isinstance(hash_section, dict) else None
        if allowed is not None and info.signature_algorithm_name.casefold() in allowed:
            hash_rule = PolicyRule("PASS", "Signature algorithm is allowed without a separate hash parameter")
        else:
            hash_rule = PolicyRule("FAIL", "Signature without external hash is not explicitly allowed by policy")
    else:
        hash_rule = _allow_rule(info.signature_hash_algorithm, hash_section, "signature hash")
    return AlgorithmResult(info, public_key, key_size, hash_rule)
