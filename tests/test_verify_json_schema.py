from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


def _schema_path() -> Path:
    return Path(__file__).resolve().parents[1] / "schemas" / "verify_output_v1.json"


def test_verify_json_validates_against_schema_on_env_failure(tmp_path: Path) -> None:
    schema_p = _schema_path()
    if not schema_p.exists():
        pytest.skip(f"missing schema: {schema_p}")

    missing = tmp_path / "nope.zip"
    p = subprocess.run(
        [sys.executable, "-m", "oord_verify.cli", "verify", str(missing), "--json"],
        capture_output=True,
        text=True,
    )
    assert p.returncode == 2
    obj = json.loads(p.stdout)

    try:
        import jsonschema  # type: ignore
    except Exception:
        pytest.skip("jsonschema not installed")

    schema = json.loads(schema_p.read_text(encoding="utf-8"))
    jsonschema.validate(instance=obj, schema=schema)
