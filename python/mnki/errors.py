"""Error taxonomy shared by the Python SDK, the guard and the adapters."""
from __future__ import annotations
from typing import Any


class AgentTrustError(Exception):
    """An error returned by the control plane (HTTP status + machine code + detail)."""
    def __init__(self, status: int, code: str, detail: Any = None):
        super().__init__(f"{code} ({status})"); self.status, self.code, self.detail = status, code, detail


MnkiError = AgentTrustError
