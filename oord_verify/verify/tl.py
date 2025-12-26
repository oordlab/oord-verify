import json
from typing import Any, Dict, Optional, Tuple
from urllib import error as urlerror
from urllib import request


def _http_json(url: str, timeout_s: float = 5.0) -> Dict[str, Any]:
    req = request.Request(url, headers={"Content-Type": "application/json"}, method="GET")
    with request.urlopen(req, timeout=timeout_s) as resp:
        raw = resp.read().decode("utf-8")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise RuntimeError(f"{url} did not return a JSON object")
    return obj


def normalize_tl_fields(tl_obj: Dict[str, Any]) -> Tuple[Optional[str], Optional[int], Optional[str], Optional[str]]:
    entry = tl_obj.get("entry") or {}
    sth = tl_obj.get("sth") or {}

    merkle_root = entry.get("merkle_root")
    seq = entry.get("seq")
    sth_sig = sth.get("sth_sig")
    signer_kid = entry.get("signer_key_id") or entry.get("signer_kid")

    if merkle_root is None:
        merkle_root = tl_obj.get("merkle_root")
    if seq is None:
        seq = tl_obj.get("tl_seq") or tl_obj.get("seq")
    if sth_sig is None:
        sth_sig = tl_obj.get("sth_sig")
    if signer_kid is None:
        signer_kid = tl_obj.get("signer_key_id") or tl_obj.get("signer_kid")

    if isinstance(seq, str) and seq.isdigit():
        seq_int: Optional[int] = int(seq)
    elif isinstance(seq, (int, float)):
        seq_int = int(seq)
    else:
        seq_int = None

    return merkle_root, seq_int, sth_sig, signer_kid


def online_tl_check(tl_url_base: str, seq: int, merkle_root: str, sth_sig: Optional[str]) -> Tuple[bool, Optional[str]]:
    base = tl_url_base.rstrip("/")
    url = f"{base}/v1/tl/entries/{seq}"
    try:
        obj = _http_json(url, timeout_s=5.0)
    except (urlerror.URLError, TimeoutError, RuntimeError, json.JSONDecodeError, ValueError) as e:
        return False, f"TL online lookup failed: {e}"

    entry = obj.get("entry") or obj
    live_root, live_seq, live_sth, _ = normalize_tl_fields(entry)

    if live_seq is None or live_root is None:
        return False, "TL entry missing seq/merkle_root"
    if live_seq != seq or live_root != merkle_root:
        return False, f"TL mismatch (live seq={live_seq}, root={live_root})"
    if sth_sig and live_sth and live_sth != sth_sig:
        return False, "TL STH signature mismatch"
    return True, None
