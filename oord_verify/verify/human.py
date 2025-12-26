from typing import Any, Dict


def _short_hex(s: Any, n: int = 12) -> str:
    if not isinstance(s, str) or not s:
        return "-"
    return s[:n]


def _first_failure_kind(summary: Dict[str, Any]) -> str:
    if summary.get("hashes_ok") is False:
        return "hashes"
    merkle = summary.get("merkle", {})
    if isinstance(merkle, dict) and merkle.get("ok") is False:
        return "merkle"
    jwks = summary.get("jwks", {})
    if isinstance(jwks, dict) and jwks.get("ok") is False:
        return "jwks"
    ms = summary.get("manifest_sig", {})
    if isinstance(ms, dict) and ms.get("ok") is False:
        return "manifest_sig"
    tl = summary.get("tl", {})
    if isinstance(tl, dict) and tl.get("present") and tl.get("ok") is False:
        return "tl"
    if isinstance(tl, dict) and tl.get("required") and tl.get("ok") is False:
        return "tl"
    if isinstance(tl, dict) and tl.get("error"):
        return "tl"
    tlo = summary.get("tl_online", {})
    if isinstance(tlo, dict) and tlo.get("enabled") and tlo.get("ok") is False:
        return "tl_online"
    return "unknown"


def print_human(summary: Dict[str, Any], ok: bool, verbose: bool) -> None:
    b = summary.get("batch", {}) if isinstance(summary.get("batch"), dict) else {}
    org_id = b.get("org_id") or "-"
    batch_id = b.get("batch_id") or "-"
    root = b.get("merkle_root") or summary.get("merkle", {}).get("manifest_root") or "-"
    file_count = b.get("file_count")
    total_bytes = b.get("total_bytes")

    tl = summary.get("tl", {}) if isinstance(summary.get("tl"), dict) else {}
    tl_part = "tl=missing"
    if tl.get("present"):
        tl_part = f"tl=seq:{tl.get('seq')}"

    if ok:
        print(
            f"PASS org={org_id} batch={batch_id} root={root} "
            f"files={file_count if file_count is not None else '-'} "
            f"bytes={total_bytes if total_bytes is not None else '-'} {tl_part}"
        )
    else:
        kind = _first_failure_kind(summary)
        msg = summary.get("error") or kind
        rids = summary.get("reason_ids") or []
        if isinstance(rids, list) and rids:
            rid_s = ",".join(str(x) for x in rids)
            msg = f"{msg} reason_ids={rid_s}"
        print(f"FAIL org={org_id} batch={batch_id} root={root} reason={kind} msg={msg}")

    if not verbose:
        return

    print(f"bundle={summary.get('bundle_path')}")
    print(f"hashes_ok={summary.get('hashes_ok')}")
    if summary.get("hashes_ok") is False:
        for m in summary.get("hash_mismatches", []):
            print(f"  mismatch={m}")

    merkle = summary.get("merkle", {})
    if isinstance(merkle, dict):
        print(
            f"merkle_ok={merkle.get('ok')} "
            f"manifest_root={merkle.get('manifest_root') or '-'} "
            f"recomputed_root={merkle.get('recomputed_root') or '-'}"
        )
        if merkle.get("error"):
            print(f"  merkle_error={merkle.get('error')}")

    jwks = summary.get("jwks", {})
    if isinstance(jwks, dict):
        kids = jwks.get("kids") or []
        if isinstance(kids, list):
            kids_s = ",".join(str(x) for x in kids if x)
        else:
            kids_s = "-"
        print(
            f"jwks_ok={jwks.get('ok')} kids={kids_s or '-'} fp={_short_hex(jwks.get('fingerprint'))}"
        )
        if jwks.get("error"):
            print(f"  jwks_error={jwks.get('error')}")

    ms = summary.get("manifest_sig", {})
    if isinstance(ms, dict):
        print(
            f"manifest_sig_ok={ms.get('ok')} key_id={ms.get('key_id') or '-'} sig_verified={ms.get('sig_verified')}"
        )
        if ms.get("error"):
            print(f"  manifest_sig_error={ms.get('error')}")

    if isinstance(tl, dict):
        if tl.get("present"):
            print(
                f"tl_ok={tl.get('ok')} seq={tl.get('seq')} sig_verified={tl.get('sig_verified')} "
                f"signer_kid={tl.get('signer_kid') or '-'}"
            )
            if tl.get("error"):
                print(f"  tl_error={tl.get('error')}")
        else:
            print("tl_present=false")

    tlo = summary.get("tl_online", {})
    if isinstance(tlo, dict):
        print(f"tl_online_enabled={tlo.get('enabled')} ok={tlo.get('ok')}")
        if tlo.get("error"):
            print(f"  tl_online_error={tlo.get('error')}")
