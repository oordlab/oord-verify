from __future__ import annotations

import os
import subprocess
import sys
from typing import Optional
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]

def _vectors_dir() -> Path:
    env = os.environ.get("OORD_PROTOCOL_DIR")
    if env:
        p = Path(env).expanduser().resolve()
        if p.is_dir():
            return p / "test-vectors" / "v1" / "bundles"
    return (ROOT / ".." / "oord-protocol" / "test-vectors" / "v1" / "bundles").resolve()

def _vector_bundle(name: str) -> Path:
    p = (_vectors_dir() / name).resolve()
    if not p.exists():
        pytest.skip(f"missing protocol vectors: {p}")
    return p

def _run_verify(bundle: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "oord_verify.cli",
            "verify",
            str(bundle),
            "--offline",
        ],
        capture_output=True,
        text=True,
    )

def test_vectors_v1_good_001_smoke() -> None:
    b = _vector_bundle("good_001.zip")
    p = _run_verify(b)
    assert p.returncode == 0, f"stdout=\n{p.stdout}\nstderr=\n{p.stderr}"

def test_vectors_v1_missing_tl_001_smoke() -> None:
    b = _vector_bundle("missing_tl_001.zip")
    p = _run_verify(b)
    assert p.returncode == 1, f"stdout=\n{p.stdout}\nstderr=\n{p.stderr}"

def test_vectors_v1_tampered_001_smoke() -> None:
    b = _vector_bundle("tampered_001.zip")
    p = _run_verify(b)
    assert p.returncode == 1, f"stdout=\n{p.stdout}\nstderr=\n{p.stderr}"
