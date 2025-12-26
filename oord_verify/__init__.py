from __future__ import annotations

try:
    from importlib.metadata import version as _version
    __version__ = _version("oord-verify")
except Exception:
    __version__ = "0.0.0"

__all__ = ["__version__"]
