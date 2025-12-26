# oord-verify/tests/util.py
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple


def run_cli(args: List[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "oord_verify.cli", *args],
        capture_output=True,
        text=True,
    )


def run_cli_json(args: List[str]) -> Tuple[int, Dict[str, Any], str, str]:
    p = run_cli(args)
    out = p.stdout
    err = p.stderr
    if not out.strip():
        raise AssertionError(
            "expected JSON on stdout, got empty stdout\n"
            f"exit={p.returncode}\n"
            f"stderr=\n{err}"
        )
    try:
        obj = json.loads(out)
    except Exception as e:
        raise AssertionError(
            "stdout was not valid JSON\n"
            f"err={e}\n"
            f"exit={p.returncode}\n"
            f"stdout=\n{out}\n"
            f"stderr=\n{err}"
        )
    return p.returncode, obj, out, err

def protocol_root() -> Path | None:
    env = os.environ.get("OORD_PROTOCOL_DIR")
    if env:
        p = Path(env).expanduser().resolve()
        return p if p.is_dir() else None
    root = Path(__file__).resolve().parents[1]
    p = (root / ".." / "oord-protocol").resolve()
    return p if p.is_dir() else None


def vector_bundle(name: str) -> Path | None:
    pr = protocol_root()
    if pr is None:
        return None
    p = (pr / "test-vectors" / "v1" / "bundles" / name).resolve()
    return p if p.is_file() else None
