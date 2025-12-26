import json
import zipfile
from typing import Any, Dict


def load_json_member(z: zipfile.ZipFile, name: str) -> Dict[str, Any]:
    try:
        raw = z.read(name).decode("utf-8")
    except KeyError:
        raise RuntimeError(f"{name} missing from bundle")
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"{name} is not valid JSON: {e}")
    if not isinstance(obj, dict):
        raise RuntimeError(f"{name} must be a JSON object")
    return obj


def load_manifest(z: zipfile.ZipFile) -> Dict[str, Any]:
    return load_json_member(z, "manifest.json")


def load_tl_proof(z: zipfile.ZipFile) -> Dict[str, Any]:
    return load_json_member(z, "tl_proof.json")


def load_jwks(z: zipfile.ZipFile) -> Dict[str, Any]:
    obj = load_json_member(z, "jwks_snapshot.json")
    keys = obj.get("keys")
    if not isinstance(keys, list) or not keys:
        raise RuntimeError("jwks_snapshot.json keys[] missing or empty")
    return obj
