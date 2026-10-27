"""Capture full-suite/import evidence in a new directory without overwriting logs."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def run(output: Path) -> int:
    """Run the requested full pytest command and record exact imports/environment."""
    if output.exists() and any(output.iterdir()):
        raise ValueError("Thư mục kiểm chứng phải trống; không ghi đè bằng chứng")
    output.mkdir(parents=True, exist_ok=True)
    modules, errors = [], []
    for folder in ("src", "experiments"):
        for path in sorted((ROOT / folder).glob("*.py")):
            name = folder if path.stem == "__init__" else f"{folder}.{path.stem}"
            try:
                importlib.import_module(name)
                modules.append(name)
            except Exception as exc:
                errors.append({"module": name, "error": f"{type(exc).__name__}: {exc}"})
    for name in ("main", "app"):
        try:
            importlib.import_module(name)
            modules.append(name)
        except Exception as exc:
            errors.append({"module": name, "error": f"{type(exc).__name__}: {exc}"})
    environment = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    command = [sys.executable, "-m", "pytest", "-v", f"--basetemp={output / 'tmp'}", "-p", "no:cacheprovider", f"--junitxml={output / 'pytest.xml'}"]
    with (output / "pytest.log").open("w", encoding="utf-8") as stream:
        completed = subprocess.run(command, cwd=ROOT, env=environment, stdout=stream, stderr=subprocess.STDOUT)
    evidence = {"created_utc": datetime.now(timezone.utc).isoformat(), "command": command, "pytest_exit_code": completed.returncode, "imports": modules, "import_errors": errors}
    (output / "validation.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    print("pytest exit:", completed.returncode, "imports:", len(modules), "import errors:", len(errors))
    return completed.returncode or (1 if errors else 0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(run(args.output_dir.resolve()))
