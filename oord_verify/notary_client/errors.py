from __future__ import annotations


class NotaryError(Exception):
    pass


class NotaryUnreachable(NotaryError):
    pass


class NotaryUnauthorized(NotaryError):
    pass


class NotaryNotFound(NotaryError):
    pass


class NotaryBadResponse(NotaryError):
    pass
