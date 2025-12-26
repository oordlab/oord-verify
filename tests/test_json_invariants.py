# oord-verify/tests/test_json_invariants.py
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.util import run_cli_json, vector_bundle


def _schema_path() -> Path:
    return Path(__file__).resolve().parents[1] / "schemas" / "verify_output_v1.json"


def test_verify_json_is_json_only_and_schema_valid_on_env_failure(tmp_path: Path) -> None:
    schema_p = _schema_path()
    if not schema_p.exists():
        pytest.skip(f"missing schema: {schema_p}")

    missing = tmp_path / "nope.zip"
    code, obj, stdout, stderr = run_cli_json(["verify", str(missing), "--json"])

    assert code == 2
    assert stdout.strip()
    assert stderr == ""

    try:
        import jsonschema  # type: ignore
    except Exception:
        pytest.skip("jsonschema not installed")

    schema = json.loads(schema_p.read_text(encoding="utf-8"))
    jsonschema.validate(instance=obj, schema=schema)


def test_verify_json_is_json_only_and_schema_valid_on_content_failure_vector_missing_tl() -> None:
    schema_p = _schema_path()
    if not schema_p.exists():
        pytest.skip(f"missing schema: {schema_p}")

    b = vector_bundle("missing_tl_001.zip")
    if b is None:
        pytest.skip("missing protocol vectors (set OORD_PROTOCOL_DIR or ensure ../oord-protocol exists)")

    code, obj, stdout, stderr = run_cli_json(["verify", str(b), "--json"])

    assert code == 1
    assert stdout.strip()
    assert stderr == ""

    try:
        import jsonschema  # type: ignore
    except Exception:
        pytest.skip("jsonschema not installed")

    schema = json.loads(schema_p.read_text(encoding="utf-8"))
    jsonschema.validate(instance=obj, schema=schema)
