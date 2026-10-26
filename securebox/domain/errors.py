from __future__ import annotations


class DomainError(Exception):
    """An application error identified by a stable, non-HTTP error code."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)
