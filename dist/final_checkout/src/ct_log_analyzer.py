"""Đọc và thống kê Google CT Log List v3, không xác minh chứng thư."""

from collections import Counter
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

KNOWN_STATES = ("usable", "qualified", "readonly", "retired", "pending", "rejected")


class DatasetError(ValueError):
    """Lỗi nội dung hoặc thao tác đọc dataset."""


@dataclass(frozen=True)
class CTLog:
    """Các trường của một log; None biểu thị trường bị thiếu."""

    operator: str
    source: str
    description: str | None = None
    log_id: str | None = None
    key: str | None = None
    url: str | None = None
    submission_url: str | None = None
    monitoring_url: str | None = None
    mmd: int | float | None = None
    state: str = "unknown"
    state_timestamp: str | None = None
    start_inclusive: str | None = None
    end_exclusive: str | None = None


@dataclass(frozen=True)
class DatasetSummary:
    """Kết quả thống kê từ dữ liệu thực tế trong file."""

    version: str | None
    log_list_timestamp: str | None
    operators: list[dict[str, Any]]
    logs: list[CTLog]
    logs_by_operator: dict[str, int]
    logs_by_state: dict[str, int]

    @property
    def total_operators(self) -> int:
        """Số bản ghi operator, kể cả operator không có log."""
        return len(self.operators)

    @property
    def total_logs(self) -> int:
        """Tổng bản ghi trong cả logs và tiled_logs."""
        return len(self.logs)


def read_json(path: Path) -> dict[str, Any]:
    """Đọc JSON UTF-8; báo rõ file thiếu hoặc nội dung không hợp lệ."""
    path = Path(path)
    try:
        with path.open(encoding="utf-8-sig") as stream:
            data = json.load(stream)
    except FileNotFoundError as exc:
        raise FileNotFoundError(
            f"Không tìm thấy dataset: {path.resolve()}. "
            "Hãy đặt Google CT Log List v3 vào data/log_list.json."
        ) from exc
    except json.JSONDecodeError as exc:
        raise DatasetError(
            f"JSON không hợp lệ trong {path}: dòng {exc.lineno}, cột {exc.colno}."
        ) from exc
    except (OSError, UnicodeError) as exc:
        raise DatasetError(f"Không thể đọc dataset UTF-8 {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise DatasetError("Dataset phải là một JSON object.")
    return data


def optional_text(value: Any) -> str | None:
    """Giữ trường chuỗi hợp lệ, trả None nếu thiếu hoặc sai kiểu."""
    return value if isinstance(value, str) else None


def object_list(value: Any, field: str) -> list[dict[str, Any]]:
    """Cho phép danh sách thiếu/null; từ chối cấu trúc sai để tránh đếm sai."""
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise DatasetError(f"Trường {field} phải là danh sách JSON objects.")
    return value


def parse_log(raw: dict[str, Any], operator: str, source: str) -> CTLog:
    """Chuẩn hóa một RFC6962 log hoặc Static CT log, giữ các trường tùy chọn."""
    state_data = raw.get("state")
    state, timestamp = "unknown", None
    if isinstance(state_data, dict) and state_data:
        if len(state_data) != 1:
            raise DatasetError("Trường state phải chứa đúng một trạng thái.")
        state, details = next(iter(state_data.items()))
        if isinstance(details, dict):
            timestamp = optional_text(details.get("timestamp"))
    interval = raw.get("temporal_interval")
    interval = interval if isinstance(interval, dict) else {}
    mmd = raw.get("mmd")
    return CTLog(
        operator=operator, source=source,
        description=optional_text(raw.get("description")),
        log_id=optional_text(raw.get("log_id")),
        key=optional_text(raw.get("key")),
        url=optional_text(raw.get("url")),
        submission_url=optional_text(raw.get("submission_url")),
        monitoring_url=optional_text(raw.get("monitoring_url")),
        mmd=mmd if isinstance(mmd, (int, float)) and not isinstance(mmd, bool) else None,
        state=state, state_timestamp=timestamp,
        start_inclusive=optional_text(interval.get("start_inclusive")),
        end_exclusive=optional_text(interval.get("end_exclusive")),
    )


def analyze_dataset(data: dict[str, Any]) -> DatasetSummary:
    """Thống kê operator, hai loại log và mọi state xuất hiện trong dataset."""
    operators = object_list(data.get("operators"), "operators")
    logs: list[CTLog] = []
    by_operator: Counter[str] = Counter()
    by_state: Counter[str] = Counter({state: 0 for state in KNOWN_STATES})
    for operator in operators:
        name = optional_text(operator.get("name")) or "(unknown operator)"
        by_operator.setdefault(name, 0)
        for source in ("logs", "tiled_logs"):
            for raw in object_list(operator.get(source), f"{name}.{source}"):
                log = parse_log(raw, name, source)
                logs.append(log)
                by_operator[name] += 1
                by_state[log.state] += 1
    return DatasetSummary(
        version=optional_text(data.get("version")),
        log_list_timestamp=optional_text(data.get("log_list_timestamp")),
        operators=operators, logs=logs,
        logs_by_operator=dict(by_operator), logs_by_state=dict(by_state),
    )


def analyze_file(path: Path) -> DatasetSummary:
    """Đọc file và trả kết quả phân tích."""
    return analyze_dataset(read_json(path))
