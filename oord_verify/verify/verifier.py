import hashlib
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from oord_verify.verify.crypto import jwks_fingerprint, verify_manifest_signature, verify_tl_signature
from oord_verify.verify.merkle import compute_merkle_root_from_manifest_files
from oord_verify.verify.tl import normalize_tl_fields, online_tl_check
from oord_verify.notary_client.client import NotaryClient
from oord_verify.verify.zipio import load_jwks, load_manifest, load_tl_proof


def _safe_int(v: Any) -> Optional[int]:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        return int(v)
    if isinstance(v, str) and v.isdigit():
        return int(v)
    return None


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _manifest_meta(manifest: Dict[str, Any]) -> Dict[str, Any]:
    org_id = manifest.get("org_id") if isinstance(manifest.get("org_id"), str) else None
    batch_id = manifest.get("batch_id") if isinstance(manifest.get("batch_id"), str) else None
    created_at_ms = _safe_int(manifest.get("created_at_ms"))
    key_id = manifest.get("key_id") if isinstance(manifest.get("key_id"), str) else None
    merkle_root = None
    merkle = manifest.get("merkle")
    if isinstance(merkle, dict) and isinstance(merkle.get("root_cid"), str):
        merkle_root = merkle.get("root_cid")

    files = manifest.get("files")
    file_count = 0
    total_bytes = 0
    if isinstance(files, list):
        for fe in files:
            if not isinstance(fe, dict):
                continue
            file_count += 1
            sb = _safe_int(fe.get("size_bytes"))
            if sb is not None and sb >= 0:
                total_bytes += sb

    return {
        "org_id": org_id,
        "batch_id": batch_id,
        "created_at_ms": created_at_ms,
        "key_id": key_id,
        "merkle_root": merkle_root,
        "file_count": file_count,
        "total_bytes": total_bytes,
    }


def _check_hashes_from_manifest(z: zipfile.ZipFile, manifest: Dict[str, Any]) -> Tuple[bool, List[Dict[str, str]]]:
    mismatches: List[Dict[str, str]] = []
    files = manifest.get("files") or []
    if not isinstance(files, list):
        mismatches.append({"file": "<manifest>", "reason": "files_not_array"})
        return False, mismatches

    expected_paths: List[str] = []
    for fe in files:
        if not isinstance(fe, dict):
            mismatches.append({"file": "<?>", "reason": "invalid_manifest_entry"})
            continue
        path = fe.get("path")
        sha_expected = fe.get("sha256")
        size_expected = fe.get("size_bytes")
        if not isinstance(path, str) or not isinstance(sha_expected, str) or not isinstance(size_expected, int):
            mismatches.append({"file": str(path), "reason": "invalid_manifest_entry"})
            continue
        expected_paths.append(path)
        try:
            data = z.read(path)
        except KeyError:
            mismatches.append({"file": path, "reason": "missing_from_zip", "expected": sha_expected})
            continue
        sha_actual = _sha256_bytes(data)
        if sha_actual != sha_expected:
            mismatches.append({"file": path, "reason": "hash_mismatch", "actual": sha_actual, "expected": sha_expected})
        if len(data) != size_expected:
            mismatches.append(
                {"file": path, "reason": "size_mismatch", "actual": str(len(data)), "expected": str(size_expected)}
            )

    names = set(z.namelist())
    for name in sorted(n for n in names if n.startswith("files/")):
        if name not in expected_paths:
            data = z.read(name)
            mismatches.append({"file": name, "reason": "missing_from_manifest", "actual": _sha256_bytes(data)})

    return len(mismatches) == 0, mismatches


def verify_bundle(
    path: Path,
    tl_url: Optional[str] = None,
    online: bool = False,
    tl_api_key: Optional[str] = None,
    tl_timeout_s: float = 5.0,
) -> Tuple[bool, Dict[str, Any]]:
    summary: Dict[str, Any] = {
        "reason_ids": [],
        "bundle_path": str(path),
        "error": None,
        "error_kind": None,
        "batch": {
            "org_id": None,
            "batch_id": None,
            "created_at_ms": None,
            "file_count": None,
            "total_bytes": None,
            "merkle_root": None,
        },
        "hashes_ok": None,
        "hash_mismatches": [],
        "tl": {
            "present": None,
            "ok": None,
            "seq": None,
            "merkle_root": None,
            "sth_sig": None,
            "signer_kid": None,
            "sig_verified": None,
            "error": None,
        },
        "jwks": {"present": None, "ok": None, "kids": [], "fingerprint": None, "error": None},
        "manifest_sig": {"ok": None, "key_id": None, "sig_verified": None, "error": None},
        "tl_online": {"enabled": bool(online), "ok": None, "error": None, "reason_id": None},
        "merkle": {"ok": None, "manifest_root": None, "recomputed_root": None, "error": None},
    }

    if not path.is_file():
        summary["error"] = "bundle path does not exist or is not a file"
        summary["error_kind"] = "env"
        summary["reason_ids"] = ["ENV_PATH_MISSING"]
        return False, summary

    try:
        with zipfile.ZipFile(path, "r") as z:
            try:
                manifest = load_manifest(z)
            except RuntimeError as e:
                msg = str(e)
                summary["error"] = msg
                if "manifest.json missing from bundle" in msg:
                    summary["reason_ids"] = ["BUNDLE_MANIFEST_MISSING"]
                elif "manifest.json is not valid JSON" in msg:
                    summary["reason_ids"] = ["BUNDLE_MANIFEST_INVALID_JSON"]
                elif "manifest.json must be a JSON object" in msg:
                    summary["reason_ids"] = ["BUNDLE_MANIFEST_INVALID_SHAPE"]
                else:
                    summary["reason_ids"] = ["BUNDLE_MANIFEST_INVALID_SHAPE"]
                return False, summary

            m = _manifest_meta(manifest)
            if isinstance(summary.get("batch"), dict):
                summary["batch"].update(m)
            summary["manifest_sig"]["key_id"] = m.get("key_id")

            hashes_ok, mismatches = _check_hashes_from_manifest(z, manifest)
            summary["hashes_ok"] = hashes_ok
            summary["hash_mismatches"] = mismatches
            if not hashes_ok:
                summary["reason_ids"] = ["HASH_MISMATCH"]
                summary["error"] = "hash mismatch (bundle payload does not match manifest)"
                return False, summary

            merkle_info = manifest.get("merkle")
            if not isinstance(merkle_info, dict):
                summary["merkle"]["ok"] = False
                summary["merkle"]["error"] = "manifest.merkle is missing or not an object"
                summary["error"] = summary["merkle"]["error"]
                summary["reason_ids"] = ["MERKLE_SCHEMA_INVALID"]
                return False, summary

            manifest_root = merkle_info.get("root_cid")
            if not isinstance(manifest_root, str):
                summary["merkle"]["ok"] = False
                summary["merkle"]["error"] = "manifest.merkle.root_cid is missing or not a string"
                summary["error"] = summary["merkle"]["error"]
                summary["reason_ids"] = ["MERKLE_SCHEMA_INVALID"]
                return False, summary

            summary["merkle"]["manifest_root"] = manifest_root
            try:
                recomputed_root = compute_merkle_root_from_manifest_files(manifest.get("files") or [])
            except ValueError as e:
                summary["merkle"]["ok"] = False
                summary["merkle"]["error"] = f"failed to recompute Merkle root from manifest.files: {e}"
                summary["error"] = summary["merkle"]["error"]
                summary["reason_ids"] = ["MERKLE_COMPUTE_ERROR"]
                return False, summary

            summary["merkle"]["recomputed_root"] = recomputed_root
            if recomputed_root != manifest_root:
                summary["merkle"]["ok"] = False
                summary["merkle"]["error"] = "recomputed Merkle root does not match manifest.merkle.root_cid"
                summary["error"] = summary["merkle"]["error"]
                summary["reason_ids"] = ["MERKLE_MISMATCH"]
                return False, summary
            summary["merkle"]["ok"] = True

            try:
                jwks = load_jwks(z)
            except RuntimeError as e:
                msg = str(e)
                summary["jwks"]["present"] = False
                summary["jwks"]["ok"] = False
                summary["jwks"]["error"] = msg
                summary["error"] = msg
                if "jwks_snapshot.json missing from bundle" in msg:
                    summary["reason_ids"] = ["JWKS_MISSING"]
                elif "jwks_snapshot.json is not valid JSON" in msg:
                    summary["reason_ids"] = ["JWKS_INVALID_JSON"]
                else:
                    summary["reason_ids"] = ["JWKS_INVALID_SHAPE"]
                return False, summary

            kids: List[str] = []
            for k in jwks.get("keys", []):
                kid = k.get("kid")
                if kid:
                    kids.append(kid)
            summary["jwks"].update(
                {"present": True, "ok": True, "kids": kids, "fingerprint": jwks_fingerprint(jwks), "error": None}
            )

            ok_manifest_sig, ms_err = verify_manifest_signature(manifest, jwks)
            summary["manifest_sig"]["sig_verified"] = ok_manifest_sig
            summary["manifest_sig"]["error"] = ms_err
            if ok_manifest_sig is False:
                summary["manifest_sig"]["ok"] = False
                summary["error"] = ms_err or "manifest signature verification failed"
                summary["reason_ids"] = ["MANIFEST_SIG_INVALID"]
                return False, summary
            summary["manifest_sig"]["ok"] = ok_manifest_sig

            m_tl_mode = manifest.get("tl_mode")
            if not isinstance(m_tl_mode, str):
                summary["tl"]["present"] = False
                summary["tl"]["ok"] = False
                summary["tl"]["error"] = "manifest.tl_mode missing or not a string"
                summary["error"] = summary["tl"]["error"]
                summary["reason_ids"] = ["TL_MODE_MISSING"]
                return False, summary
            if m_tl_mode not in ("included", "none"):
                summary["tl"]["present"] = False
                summary["tl"]["ok"] = False
                summary["tl"]["error"] = f"invalid manifest.tl_mode={m_tl_mode!r} (expected 'included'|'none')"
                summary["error"] = summary["tl"]["error"]
                summary["reason_ids"] = ["TL_MODE_INVALID"]
                return False, summary

            tl_required = m_tl_mode == "included"
            summary["tl"]["required"] = tl_required

            names = set(z.namelist())
            tl_file_present = "tl_proof.json" in names
            if m_tl_mode == "none" and tl_file_present:
                summary["tl"]["present"] = True
                summary["tl"]["ok"] = False
                summary["tl"]["error"] = "tl_proof.json present but manifest.tl_mode=none"
                summary["error"] = summary["tl"]["error"]
                summary["reason_ids"] = ["TL_PROOF_UNEXPECTED"]
                return False, summary

            tl_obj: Optional[Dict[str, Any]] = None
            try:
                tl_obj = load_tl_proof(z)
            except RuntimeError as e:
                msg = str(e)
                if "tl_proof.json missing from bundle" in msg:
                    if tl_required:
                        summary["tl"]["present"] = False
                        summary["tl"]["ok"] = False
                        summary["tl"]["error"] = "tl_proof.json missing but manifest.tl_mode=included"
                        summary["error"] = summary["tl"]["error"]
                        summary["reason_ids"] = ["TL_PROOF_MISSING"]
                        return False, summary
                    summary["tl"]["present"] = False
                    summary["tl"]["ok"] = True
                    summary["tl"]["error"] = None
                    tl_obj = None
                else:
                    summary["tl"]["present"] = False
                    summary["tl"]["ok"] = False
                    summary["tl"]["error"] = msg
                    summary["error"] = msg
                    summary["reason_ids"] = ["TL_PROOF_JSON_INVALID"]
                    return False, summary

            merkle_root: Optional[str] = None
            seq: Optional[int] = None
            sth_sig: Optional[str] = None
            signer_kid: Optional[str] = None

            if tl_obj is not None:
                merkle_root, seq, sth_sig, signer_kid = normalize_tl_fields(tl_obj)
                if merkle_root is None or seq is None:
                    summary["tl"]["present"] = True
                    summary["tl"]["ok"] = False
                    summary["tl"]["error"] = "tl_proof.json missing merkle_root or seq"
                    summary["error"] = summary["tl"]["error"]
                    summary["reason_ids"] = ["TL_PROOF_SCHEMA_INVALID"]
                    return False, summary

                manifest_root_for_tl = summary["merkle"]["manifest_root"]
                if isinstance(manifest_root_for_tl, str) and merkle_root != manifest_root_for_tl:
                    summary["tl"]["present"] = True
                    summary["tl"]["ok"] = False
                    summary["tl"]["error"] = "tl_proof merkle_root does not match manifest.merkle.root_cid"
                    summary["error"] = summary["tl"]["error"]
                    summary["reason_ids"] = ["TL_ROOT_MISMATCH"]
                    return False, summary

                summary["tl"].update(
                    {
                        "present": True,
                        "ok": True,
                        "seq": seq,
                        "merkle_root": merkle_root,
                        "sth_sig": sth_sig,
                        "signer_kid": signer_kid,
                        "sig_verified": None,
                        "error": None,
                    }
                )

            if tl_obj is not None and merkle_root is not None and seq is not None:
                ok_sig, sig_err = verify_tl_signature(
                    merkle_root=merkle_root, seq=int(seq), sth_sig=sth_sig, jwks=jwks, signer_kid=signer_kid
                )
                summary["tl"]["sig_verified"] = ok_sig
                if ok_sig is False:
                    summary["tl"]["ok"] = False
                    summary["tl"]["error"] = sig_err or "TL signature verification failed"
                    summary["error"] = summary["tl"]["error"]
                    if sig_err and "not found in JWKS" in sig_err:
                        summary["reason_ids"] = ["TL_KEY_MISSING"]
                    else:
                        summary["reason_ids"] = ["TL_PROOF_SIG_INVALID"]
                    return False, summary

            online_enabled = bool(online or tl_url)
            summary["tl_online"]["enabled"] = online_enabled

            if online_enabled:
                if not tl_url:
                    summary["tl_online"]["ok"] = False
                    summary["tl_online"]["reason_id"] = "ENV_NOTARY_URL_MISSING"
                    summary["tl_online"]["error"] = "online enabled but no --tl-url/--notary-url provided"
                    summary["error"] = summary["tl_online"]["error"]
                    summary["reason_ids"] = ["ENV_NOTARY_URL_MISSING"]
                    return False, summary

                if tl_obj is None or seq is None or merkle_root is None:
                    summary["tl_online"]["ok"] = None
                    summary["tl_online"]["reason_id"] = None
                    summary["tl_online"]["error"] = None
                else:
                    client = NotaryClient(base_url=tl_url, api_key=tl_api_key, timeout_s=float(tl_timeout_s))
                    ok_online, rid, err = online_tl_check(client, int(seq), merkle_root, sth_sig)
                    summary["tl_online"]["ok"] = ok_online
                    summary["tl_online"]["reason_id"] = rid
                    summary["tl_online"]["error"] = err
                    if not ok_online and rid:
                        summary["error"] = err or "online TL check failed"
                        summary["reason_ids"] = [rid]
                        return False, summary
            else:
                summary["tl_online"]["ok"] = None
                summary["tl_online"]["reason_id"] = None
                summary["tl_online"]["error"] = None

    except zipfile.BadZipFile as e:
        summary["error"] = f"bad zip file: {e}"
        summary["error_kind"] = "env"
        summary["reason_ids"] = ["ZIP_BAD"]
        return False, summary
    except RuntimeError as e:
        summary["error"] = str(e)
        if not summary.get("reason_ids"):
            summary["reason_ids"] = ["RUNTIME_ERROR"]
        return False, summary

    return True, summary
