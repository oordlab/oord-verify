from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from typing import Any, Dict

import pytest

from tests.util import vector_bundle


def _run_cli_json_inproc(argv: list[str]) -> tuple[int, Dict[str, Any], str, str]:
    from oord_verify.cli import build_parser

    parser = build_parser()
    args = parser.parse_args(argv)

    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = int(args.func(args))

    stdout = out.getvalue()
    stderr = err.getvalue()
    if not stdout.strip():
        raise AssertionError(
            "expected JSON on stdout, got empty stdout\n"
            f"exit={rc}\n"
            f"stderr=\n{stderr}"
        )
    try:
        obj = json.loads(stdout)
    except Exception as e:
        raise AssertionError(
            "stdout was not valid JSON\n"
            f"err={e}\n"
            f"exit={rc}\n"
            f"stdout=\n{stdout}\n"
            f"stderr=\n{stderr}"
        )
    return rc, obj, stdout, stderr

def _good_vector() -> str:
    p = vector_bundle("good_001.zip")
    if p is None:
        pytest.skip("missing protocol vectors")
    return str(p)


def test_online_unreachable_is_exit_2(monkeypatch: pytest.MonkeyPatch) -> None:
    from oord_verify.notary_client import client as nc
    from oord_verify.notary_client.errors import NotaryUnreachable

    def boom(self: nc.NotaryClient, seq: int) -> Dict[str, Any]:
        raise NotaryUnreachable("no route")

    monkeypatch.setattr(nc.NotaryClient, "get_tl_entry_by_seq", boom)

    rc, obj, _, _ = _run_cli_json_inproc(
        ["verify", _good_vector(), "--json", "--online", "--tl-url", "http://127.0.0.1:8000"]
    )
    assert rc == 2
    assert obj.get("reason_ids") == ["TL_ONLINE_UNREACHABLE"]
    assert obj.get("error_kind") is None
    assert obj.get("checks", {}).get("tl_online_enabled") is True
    assert obj.get("checks", {}).get("tl_online_ok") is False


def test_online_contradiction_is_exit_1(monkeypatch: pytest.MonkeyPatch) -> None:
    from oord_verify.notary_client import client as nc

    def fake(self: nc.NotaryClient, seq: int) -> Dict[str, Any]:
        return {"seq": seq, "merkle_root": "cid:sha256:" + ("0" * 64), "sth_sig": "x", "t_ms": 0, "signer_key_id": "k"}

    monkeypatch.setattr(nc.NotaryClient, "get_tl_entry_by_seq", fake)

    rc, obj, _, _ = _run_cli_json_inproc(
        ["verify", _good_vector(), "--json", "--online", "--tl-url", "http://127.0.0.1:8000"]
    )
    assert rc == 1
    assert obj.get("reason_ids") == ["TL_ONLINE_CONTRADICTION"]
    assert obj.get("error_kind") is None
    assert obj.get("checks", {}).get("tl_online_enabled") is True
    assert obj.get("checks", {}).get("tl_online_ok") is False
