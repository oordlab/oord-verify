import hashlib
import json
from base64 import urlsafe_b64decode
from typing import Any, Dict, Optional, Tuple

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except Exception:  # pragma: no cover
    Ed25519PublicKey = None  # type: ignore[assignment]


def jwks_fingerprint(jwks: Dict[str, Any]) -> str:
    raw = json.dumps(jwks, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def manifest_unsigned_bytes(manifest: Dict[str, Any]) -> bytes:
    unsigned = dict(manifest)
    unsigned["signature"] = ""
    return canonical_json_bytes(unsigned)


def verify_manifest_signature(manifest: Dict[str, Any], jwks: Dict[str, Any]) -> Tuple[Optional[bool], Optional[str]]:
    if Ed25519PublicKey is None:
        return None, None

    key_id = manifest.get("key_id")
    sig = manifest.get("signature")
    if not isinstance(key_id, str) or not isinstance(sig, str):
        return False, "manifest missing 'key_id' or 'signature'"

    if key_id == "stub-kid":
        return None, None

    key = next((k for k in jwks.get("keys", []) if k.get("kid") == key_id), None)
    if not key:
        return False, f"manifest key_id {key_id!r} not found in JWKS"
    if key.get("kty") != "OKP" or key.get("crv") != "Ed25519":
        return False, "JWKS key for manifest is not an Ed25519 OKP key"

    x_b64 = key.get("x")
    if not x_b64:
        return False, "JWKS key for manifest missing 'x' field"

    try:
        pub_bytes = urlsafe_b64decode(x_b64 + "===")
    except Exception as e:  # pragma: no cover
        return False, f"invalid JWKS x encoding for manifest key: {e!s}"

    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
    except Exception as e:  # pragma: no cover
        return False, f"invalid Ed25519 public key bytes for manifest key: {e!s}"

    unsigned = manifest_unsigned_bytes(manifest)
    try:
        sig_bytes = urlsafe_b64decode(sig + "===")
    except Exception as e:  # pragma: no cover
        return False, f"invalid manifest signature encoding: {e!s}"

    try:
        pub.verify(sig_bytes, unsigned)
    except Exception:
        return False, "manifest signature verification failed"

    return True, None


def verify_tl_signature(
    merkle_root: Optional[str],
    seq: Optional[int],
    sth_sig: Optional[str],
    jwks: Dict[str, Any],
    signer_kid: Optional[str],
) -> Tuple[Optional[bool], Optional[str]]:
    if merkle_root is None or seq is None or not sth_sig or not signer_kid or Ed25519PublicKey is None:
        return None, None
    if signer_kid == "stub-kid":
        return None, None

    key = next((k for k in jwks.get("keys", []) if k.get("kid") == signer_kid), None)
    if not key:
        return False, f"signer_kid {signer_kid!r} not found in JWKS"
    if key.get("kty") != "OKP" or key.get("crv") != "Ed25519":
        return False, "JWKS key is not an Ed25519 OKP key"

    x_b64 = key.get("x")
    if not x_b64:
        return False, "JWKS key missing 'x' field"

    try:
        pub_bytes = urlsafe_b64decode(x_b64 + "===")
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        sig_bytes = urlsafe_b64decode(sth_sig + "===")
    except Exception as e:  # pragma: no cover
        return False, f"invalid JWKS/sig encoding: {e!s}"

    msg = f"seq={seq}|merkle_root={merkle_root}".encode("utf-8")
    try:
        pub.verify(sig_bytes, msg)
    except Exception:
        return False, "TL signature verification failed"

    return True, None
