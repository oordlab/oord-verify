from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Tuple

import pytest


def _protocol_root() -> Path | None:
    env = os.environ.get("OORD_PROTOCOL_DIR")
    if env:
        p = Path(env).expanduser().resolve()
        return p if p.is_dir() else None
    here = Path(__file__).resolve()
    p = (here.parents[1] / ".." / "oord-protocol").resolve()
    return p if p.is_dir() else None


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_sha256sums(p: Path) -> Dict[str, str]:
    m: Dict[str, str] = {}
    for line in p.read_text("utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        sha = parts[0].strip()
        rel = parts[-1].strip()
        m[rel] = sha
    return m


def _run_verify_json(bundle_zip: Path) -> Tuple[int, Dict[str, Any], str]:
    p = subprocess.run(
        [
            sys.executable,
            "-m",
            "oord_verify.cli",
            "verify",
            str(bundle_zip),
            "--json",
            "--offline",
        ],
        capture_output=True,
        text=True,
    )
    obj = json.loads(p.stdout)
    return p.returncode, obj, p.stderr


def _assert_subset(expected: Any, actual: Any, *, path: str) -> None:
    if isinstance(expected, dict):
        assert isinstance(actual, dict), f"{path}: expected object, got {type(actual).__name__}"
        for k, v in expected.items():
            assert k in actual, f"{path}: missing key {k!r}"
            _assert_subset(v, actual[k], path=f"{path}.{k}")
        return

    if isinstance(expected, list):
        assert isinstance(actual, list), f"{path}: expected array, got {type(actual).__name__}"
        assert actual == expected, f"{path}: array mismatch"
        return

    assert actual == expected, f"{path}: value mismatch (expected {expected!r}, got {actual!r})"


def test_protocol_vectors_v1_replay_subset_contract() -> None:
    pr = _protocol_root()
    if pr is None:
        pytest.skip("missing protocol vectors (set OORD_PROTOCOL_DIR or ensure ../oord-protocol exists)")

    v1 = pr / "test-vectors" / "v1"
    bundles_dir = v1 / "bundles"
    expected_dir = v1 / "expected"
    sha_file = v1 / "SHA256SUMS"

    assert bundles_dir.is_dir(), f"missing bundles dir: {bundles_dir}"
    assert expected_dir.is_dir(), f"missing expected dir: {expected_dir}"
    assert sha_file.is_file(), f"missing SHA256SUMS: {sha_file}"

    sha_map = _parse_sha256sums(sha_file)
    expected_files = sorted(expected_dir.glob("*.json"))
    assert expected_files, f"no expected vectors found under {expected_dir}"

    for exp_path in expected_files:
        exp = json.loads(exp_path.read_text("utf-8"))
        name = exp_path.stem
        bundle = bundles_dir / f"{name}.zip"
        assert bundle.is_file(), f"missing bundle for expected vector: {bundle}"

        rel = f"bundles/{bundle.name}"
        assert rel in sha_map, f"{bundle.name}: missing from SHA256SUMS"
        bundle_sha = _sha256_file(bundle)
        assert bundle_sha == sha_map[rel], f"{bundle.name}: sha256 mismatch vs SHA256SUMS"

        rc, out, err = _run_verify_json(bundle)
        assert err == "", f"{bundle.name}: stderr not empty under --json\n{err}"

        exp_reason_ids = set(exp.get("reason_ids") or [])
        out_reason_ids = set(out.get("reason_ids") or [])
        assert out_reason_ids == exp_reason_ids, f"{bundle.name}: reason_ids mismatch"

        assert out.get("hashes_ok") == exp.get("hashes_ok"), f"{bundle.name}: hashes_ok mismatch"

        exp_copy = dict(exp)
        exp_copy.pop("reason_ids", None)
        exp_copy.pop("hashes_ok", None)
        _assert_subset(exp_copy, out, path=bundle.name)

        expected_exit = 0 if len(exp_reason_ids) == 0 else 1
        assert rc == expected_exit, f"{bundle.name}: exit code mismatch (expected {expected_exit}, got {rc})"
