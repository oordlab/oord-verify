import json
from typing import Any, Dict, Optional, Tuple

from oord_verify.notary_client.client import NotaryClient
from oord_verify.notary_client.errors import (
    NotaryBadResponse,
    NotaryNotFound,
    NotaryUnauthorized,
    NotaryUnreachable,
)

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

def online_tl_check(client: NotaryClient, seq: int, merkle_root: str, sth_sig: Optional[str]) -> Tuple[bool, Optional[str], Optional[str]]:
    try:
        obj = client.get_tl_entry_by_seq(int(seq))
    except NotaryUnauthorized as e:
        return False, "TL_ONLINE_UNAUTHORIZED", f"TL online unauthorized: {e}"
    except NotaryNotFound as e:
        return False, "TL_ONLINE_NOT_FOUND", f"TL online not found: {e}"
    except NotaryUnreachable as e:
        return False, "TL_ONLINE_UNREACHABLE", f"TL online unreachable: {e}"
    except NotaryBadResponse as e:
        return False, "TL_ONLINE_BAD_RESPONSE", f"TL online bad response: {e}"

    entry = obj.get("entry") or obj
    live_root, live_seq, live_sth, _ = normalize_tl_fields(entry)

    if live_seq is None or live_root is None:
        return False, "TL_ONLINE_BAD_RESPONSE", "TL entry missing seq/merkle_root"
    if live_seq != seq or live_root != merkle_root:
        return False, "TL_ONLINE_CONTRADICTION", f"TL mismatch (live seq={live_seq}, root={live_root})"
    return True, None, None
