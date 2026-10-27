"""Tổng hợp các kiểm tra và module errors thành PASS/WARNING/FAIL."""

from dataclasses import dataclass
from typing import Mapping

from src.algorithm_policy import AlgorithmResult
from src.chain_validator import ChainResult
from src.ct_validator import CTResult
from src.hostname_validator import HostnameResult
from src.validity_checker import ValidityResult


@dataclass(frozen=True)
class SecurityResult:
    """Kết quả tổng, trạng thái thành phần và reasons không trùng lặp."""

    status: str
    checks: dict[str, str]
    reasons: tuple[str, ...]


def evaluate_security(
    validity: ValidityResult | None,
    hostname: HostnameResult | None,
    chain: ChainResult | None,
    algorithm: AlgorithmResult | None,
    ct: CTResult | None,
    errors: Mapping[str, str] | None = None,
    *, include_ct: bool = True,
) -> SecurityResult:
    """Bất kỳ kiểm tra thiết yếu thiếu/FAIL -> FAIL; CT thiếu -> WARNING."""
    checks = {
        "Validity": "PASS" if validity is not None and validity.status == "VALID" else "FAIL",
        "Hostname": hostname.status if hostname is not None else "FAIL",
        "Certificate Chain": chain.status if chain is not None else "FAIL",
        "Algorithm Policy": algorithm.status if algorithm is not None else "FAIL",
        "Certificate Transparency": ct.status if ct is not None else "WARNING",
    }
    reasons: list[str] = []
    if not include_ct:
        del checks['Certificate Transparency']
    if validity is None:
        reasons.append("Validity check unavailable")
    elif validity.status != "VALID":
        reasons.append(f"Certificate validity: {validity.status}; {validity.message}")
    if hostname is None:
        reasons.append("Hostname check unavailable")
    elif hostname.status != "PASS":
        reasons.append(f"Hostname mismatch: {hostname.message}")
    for name, result in (("Certificate Chain", chain), ("Algorithm Policy", algorithm), ("Certificate Transparency", ct)):
        if name == 'Certificate Transparency' and not include_ct:
            continue
        if result is None:
            reasons.append(f"{name} check unavailable")
        elif result.status != "PASS":
            reasons.extend(result.reasons or (f"{name}: {result.status}",))
    for name, message in (errors or {}).items():
        reasons.append(f"{name}: {message}")
        # CT dataset/parsing unavailable is a declared warning, other modules fail closed.
        checks[name] = "WARNING" if name == "Certificate Transparency" else "FAIL"
    for name, status in tuple(checks.items()):
        if status not in ("PASS", "WARNING", "FAIL"):
            checks[name] = "FAIL"
            reasons.append(f"Invalid status from {name}: {status}")
    status = "FAIL" if "FAIL" in checks.values() else "WARNING" if "WARNING" in checks.values() else "PASS"
    return SecurityResult(status, checks, tuple(dict.fromkeys(reasons)))
