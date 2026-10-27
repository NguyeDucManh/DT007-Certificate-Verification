"""Kiểm tra tổng hợp critical failures, warnings và module errors."""

from collections.abc import Callable
from dataclasses import replace
from datetime import datetime
from pathlib import Path

import pytest

from src.algorithm_policy import evaluate_algorithm, load_policy, PolicyRule
from src.chain_validator import validate_chain
from src.crypto_info import get_crypto_info
from src.ct_validator import CTResult
from src.hostname_validator import validate_hostname
from src.security_evaluator import evaluate_security
from src.validity_checker import check_validity


@pytest.fixture
def results(chain_factory: Callable, reference_time: datetime) -> dict:
    chain = chain_factory()
    policy = load_policy(Path(__file__).resolve().parents[1] / "config" / "algorithm_policy.json")
    return dict(validity=check_validity(chain[0], reference_time), hostname=validate_hostname(chain[0], "example.com"),
                chain=validate_chain(chain, [chain[-1]], reference_time),
                algorithm=evaluate_algorithm(get_crypto_info(chain[0]), policy),
                ct=CTResult((), "PASS", (), signature_validation="VERIFIED"))


def test_all_pass(results: dict) -> None:
    result = evaluate_security(**results)
    assert result.status == "PASS" and not result.reasons


def test_warning_only(results: dict) -> None:
    results["ct"] = CTResult((), "WARNING", ("NO_SCT",))
    assert evaluate_security(**results).status == "WARNING"


@pytest.mark.parametrize("component", ["validity", "hostname", "chain", "algorithm", "ct"])
def test_critical_fail(results: dict, component: str) -> None:
    if component == "validity":
        results[component] = replace(results[component], status="EXPIRED")
    elif component == "algorithm":
        results[component] = replace(results[component], key_size=PolicyRule("FAIL", "RSA key size below policy minimum"))
    else:
        results[component] = replace(results[component], status="FAIL")
    assert evaluate_security(**results).status == "FAIL"


def test_not_yet_valid_is_fail(results: dict) -> None:
    results["validity"] = replace(results["validity"], status="NOT_YET_VALID")
    assert evaluate_security(**results).status == "FAIL"


def test_multiple_reasons(results: dict) -> None:
    results["hostname"] = replace(results["hostname"], status="FAIL", message="wrong SAN")
    results["algorithm"] = replace(results["algorithm"], key_size=PolicyRule("FAIL", "RSA key size below policy minimum"))
    results["ct"] = CTResult((), "WARNING", ("CT log is retired", "CT log is retired"))
    result = evaluate_security(**results)
    assert result.status == "FAIL"
    assert any("Hostname mismatch" in reason for reason in result.reasons)
    assert "RSA key size below policy minimum" in result.reasons
    assert result.reasons.count("CT log is retired") == 1


@pytest.mark.parametrize("component", ["validity", "hostname", "chain", "algorithm"])
def test_missing_critical_check(results: dict, component: str) -> None:
    results[component] = None
    assert evaluate_security(**results).status == "FAIL"


def test_missing_ct_is_warning(results: dict) -> None:
    results["ct"] = None
    assert evaluate_security(**results).status == "WARNING"


def test_module_error_overrides_pass(results: dict) -> None:
    result = evaluate_security(**results, errors={"Algorithm Policy": "invalid JSON"})
    assert result.status == "FAIL"
    assert "Algorithm Policy: invalid JSON" in result.reasons


def test_ct_dataset_error_warning(results: dict) -> None:
    result = evaluate_security(**results, errors={"Certificate Transparency": "dataset missing"})
    assert result.status == "WARNING"


def test_unknown_status_fail_closed(results: dict) -> None:
    results["ct"] = CTResult((), "UNKNOWN", ())
    assert evaluate_security(**results).status == "FAIL"
