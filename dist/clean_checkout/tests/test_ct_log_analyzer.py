"""Fixture tổng hợp chỉ dùng để kiểm thử, không thay thế dataset Google."""

import json
from pathlib import Path

import pytest

from main import main, print_summary
from src.ct_log_analyzer import DatasetError, analyze_dataset, analyze_file, read_json


@pytest.fixture
def sample() -> dict:
    """Dataset giả lập nhỏ để kiểm tra độc lập với dữ liệu bên ngoài."""
    return {
        "version": "test-1", "log_list_timestamp": "2026-01-01T00:00:00Z",
        "operators": [
            {"name": "Test Operator", "logs": [{
                "description": "Test RFC log", "log_id": "test-id", "key": "test-key",
                "url": "https://example.test/log/", "mmd": 86400,
                "state": {"usable": {"timestamp": "2025-01-01T00:00:00Z"}},
                "temporal_interval": {"start_inclusive": "2026-01-01T00:00:00Z",
                                      "end_exclusive": "2027-01-01T00:00:00Z"},
            }], "tiled_logs": [{
                "description": "Test tiled log", "log_id": "tiled-id", "key": "tiled-key",
                "submission_url": "https://example.test/submit/",
                "monitoring_url": "https://example.test/monitor/", "mmd": 60,
                "state": {"qualified": {"timestamp": "2025-02-01T00:00:00Z"}},
            }]},
            {"name": "Empty Operator", "logs": [], "tiled_logs": []},
        ],
    }


def test_read_json(tmp_path: Path, sample: dict) -> None:
    path = tmp_path / "dataset.json"
    path.write_text(json.dumps(sample), encoding="utf-8")
    assert read_json(path) == sample
    assert analyze_file(path).total_logs == 2


def test_version(sample: dict) -> None:
    assert analyze_dataset(sample).version == "test-1"


def test_timestamp(sample: dict) -> None:
    assert analyze_dataset(sample).log_list_timestamp == "2026-01-01T00:00:00Z"


def test_operators(sample: dict) -> None:
    result = analyze_dataset(sample)
    assert result.total_operators == 2
    assert result.operators == sample["operators"]
    assert result.logs_by_operator == {"Test Operator": 2, "Empty Operator": 0}


def test_logs_count(sample: dict) -> None:
    assert analyze_dataset(sample).total_logs == 2


@pytest.mark.parametrize("state", ["usable", "qualified", "readonly", "retired", "pending", "rejected", "future_state"])
def test_states(state: str) -> None:
    result = analyze_dataset({"operators": [{"logs": [{"state": {state: {}}}]}]})
    assert result.logs_by_state[state] == 1
    assert sum(result.logs_by_state.values()) == 1


def test_standard_log(sample: dict) -> None:
    log = analyze_dataset(sample).logs[0]
    assert (log.operator, log.source, log.description) == ("Test Operator", "logs", "Test RFC log")
    assert (log.log_id, log.key, log.url, log.mmd) == (
        "test-id", "test-key", "https://example.test/log/", 86400)
    assert (log.state, log.state_timestamp) == ("usable", "2025-01-01T00:00:00Z")
    assert (log.start_inclusive, log.end_exclusive) == (
        "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")


def test_tiled_log(sample: dict) -> None:
    log = analyze_dataset(sample).logs[1]
    assert (log.source, log.log_id, log.key, log.mmd) == ("tiled_logs", "tiled-id", "tiled-key", 60)
    assert log.url is None
    assert log.submission_url == "https://example.test/submit/"
    assert log.monitoring_url == "https://example.test/monitor/"
    assert (log.state, log.state_timestamp) == ("qualified", "2025-02-01T00:00:00Z")


def test_missing_fields() -> None:
    result = analyze_dataset({"operators": [{"logs": [{}]}]})
    log = result.logs[0]
    assert result.version is None and result.log_list_timestamp is None
    assert log.operator == "(unknown operator)" and log.state == "unknown"
    assert all(getattr(log, field) is None for field in (
        "description", "log_id", "key", "url", "submission_url", "monitoring_url",
        "mmd", "state_timestamp", "start_inclusive", "end_exclusive"))
    assert result.logs_by_state["unknown"] == 1
    assert analyze_dataset({}).total_logs == 0


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="data/log_list.json"):
        read_json(tmp_path / "missing.json")


def test_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text('{"operators":', encoding="utf-8")
    with pytest.raises(DatasetError, match="JSON không hợp lệ"):
        read_json(path)


def test_invalid_root(tmp_path: Path) -> None:
    path = tmp_path / "list.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(DatasetError, match="JSON object"):
        read_json(path)


@pytest.mark.parametrize("data", [
    {"operators": "wrong"}, {"operators": [1]},
    {"operators": [{"logs": {}}]}, {"operators": [{"tiled_logs": [None]}]},
])
def test_invalid_collections(data: dict) -> None:
    with pytest.raises(DatasetError, match="danh sách"):
        analyze_dataset(data)


def test_utf8_bom(tmp_path: Path) -> None:
    path = tmp_path / "bom.json"
    path.write_text('{"version": "kiểm thử"}', encoding="utf-8-sig")
    assert read_json(path)["version"] == "kiểm thử"


def test_print_limit(capsys: pytest.CaptureFixture) -> None:
    result = analyze_dataset({"operators": [{"name": "Test", "logs": [{} for _ in range(7)]}]})
    print_summary(result)
    output = capsys.readouterr().out
    assert "Total logs          : 7" in output
    assert output.count("CT log #") == 5
    assert "N/A" in output


def test_main_missing_dataset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
    monkeypatch.setattr("main.DATASET_PATH", tmp_path / "missing.json")
    assert main() == 1
    assert "Không tìm thấy dataset" in capsys.readouterr().err
