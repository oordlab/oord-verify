from __future__ import annotations

from typing import Any, Dict


def build_checks(summary: Dict[str, Any]) -> Dict[str, Any]:
    if summary.get("error_kind") == "env":
        return {
            "hashes_ok": None,
            "merkle_ok": None,
            "jwks_present": None,
            "jwks_ok": None,
            "manifest_sig_ok": None,
            "tl_present": None,
            "tl_required": None,
            "tl_ok": None,
            "tl_sig_verified": None,
            "tl_online_enabled": None,
            "tl_online_ok": None,
        }

    merkle = summary.get("merkle") if isinstance(summary.get("merkle"), dict) else {}
    jwks = summary.get("jwks") if isinstance(summary.get("jwks"), dict) else {}
    ms = summary.get("manifest_sig") if isinstance(summary.get("manifest_sig"), dict) else {}
    tl = summary.get("tl") if isinstance(summary.get("tl"), dict) else {}
    tlo = summary.get("tl_online") if isinstance(summary.get("tl_online"), dict) else {}

    def _b(v: Any) -> Any:
        return v if isinstance(v, bool) else None

    return {
        "hashes_ok": _b(summary.get("hashes_ok")),
        "merkle_ok": _b(merkle.get("ok")),
        "jwks_present": _b(jwks.get("present")),
        "jwks_ok": _b(jwks.get("ok")),
        "manifest_sig_ok": _b(ms.get("ok")),
        "tl_present": _b(tl.get("present")),
        "tl_required": _b(tl.get("required")),
        "tl_ok": _b(tl.get("ok")),
        "tl_sig_verified": _b(tl.get("sig_verified")),
        "tl_online_enabled": _b(tlo.get("enabled")),
        "tl_online_ok": _b(tlo.get("ok")),
    }


def wrap_json(summary: Dict[str, Any], exit_code: int) -> Dict[str, Any]:
    rids = summary.get("reason_ids")
    if not isinstance(rids, list):
        rids = []
    summary["reason_ids"] = rids
    summary["exit_code"] = exit_code
    summary["checks"] = build_checks(summary)
    return summary
