import json
import subprocess
import sys
from pathlib import Path


def test_cli_help() -> None:
    p = subprocess.run([sys.executable, "-m", "oord_verify.cli", "--help"], capture_output=True, text=True)
    assert p.returncode == 0
    assert "Oord verifier" in p.stdout


def test_cli_verify_json_on_missing_path(tmp_path: Path) -> None:
    missing = tmp_path / "nope.zip"
    p = subprocess.run([sys.executable, "-m", "oord_verify.cli", "verify", str(missing), "--json"], capture_output=True, text=True)
    assert p.returncode == 2
    obj = json.loads(p.stdout)
    assert obj["reason_ids"] == ["ENV_PATH_MISSING"]
    assert obj["exit_code"] == 2
    assert isinstance(obj.get("checks"), dict)
    assert obj["checks"]["hashes_ok"] is None
    assert obj["checks"]["merkle_ok"] is None
