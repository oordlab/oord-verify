from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib import error as urlerror
from urllib import request

from oord_verify.notary_client.errors import (
    NotaryBadResponse,
    NotaryNotFound,
    NotaryUnauthorized,
    NotaryUnreachable,
)


@dataclass(frozen=True)
class NotaryClient:
    base_url: str
    api_key: Optional[str] = None
    timeout_s: float = 5.0

    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def get_tl_entry_by_seq(self, seq: int) -> Dict[str, Any]:
        base = self.base_url.rstrip("/")
        url = f"{base}/v1/tl/entries/{int(seq)}"
        req = request.Request(url, headers=self._headers(), method="GET")

        try:
            with request.urlopen(req, timeout=self.timeout_s) as resp:
                status = getattr(resp, "status", 200)
                raw = resp.read().decode("utf-8")
        except urlerror.HTTPError as e:
            if e.code in (401, 403):
                raise NotaryUnauthorized(f"http {e.code}") from e
            if e.code == 404:
                raise NotaryNotFound("not found") from e
            raise NotaryUnreachable(f"http {e.code}") from e
        except (urlerror.URLError, TimeoutError, ValueError) as e:
            raise NotaryUnreachable(str(e)) from e

        if status in (401, 403):
            raise NotaryUnauthorized(f"http {status}")
        if status == 404:
            raise NotaryNotFound("not found")

        try:
            obj = json.loads(raw)
        except Exception as e:
            raise NotaryBadResponse(f"invalid json: {e}") from e

        if not isinstance(obj, dict):
            raise NotaryBadResponse("response was not a JSON object")
        return obj
