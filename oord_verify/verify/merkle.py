import hashlib
from typing import Dict, List, Tuple


def compute_merkle_root_from_manifest_files(files: List[Dict[str, object]]) -> str:
    entries: List[Tuple[str, bytes]] = []

    for fe in files:
        if not isinstance(fe, dict):
            raise ValueError("files entries must be objects")
        path = fe.get("path")
        h = fe.get("sha256")
        if not isinstance(path, str) or not isinstance(h, str):
            raise ValueError("files entries must provide 'path' and 'sha256' strings")
        if not path.startswith("files/"):
            raise ValueError("manifest file path must start with 'files/'")
        if ".." in path or "\\" in path:
            raise ValueError("manifest file path must not contain '..' or backslashes")
        if len(h) != 64:
            raise ValueError("sha256 must be 64 hex characters")
        try:
            digest = bytes.fromhex(h)
        except ValueError:
            raise ValueError("sha256 must be valid hex")
        entries.append((path, digest))

    if not entries:
        raise ValueError("cannot compute Merkle root for empty file list")

    entries.sort(key=lambda item: item[0])

    level: List[bytes] = []
    for _, digest in entries:
        level.append(hashlib.sha256(b"leaf:" + digest).digest())

    while len(level) > 1:
        next_level: List[bytes] = []
        i = 0
        n = len(level)
        while i < n:
            left = level[i]
            if i + 1 < n:
                right = level[i + 1]
                i += 2
                node = hashlib.sha256(b"node:" + left + right).digest()
            else:
                i += 1
                node = left
            next_level.append(node)
        level = next_level

    return "cid:sha256:" + level[0].hex()
