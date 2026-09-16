"""Deprecated import path. `agent_trust` is now `mnki` (pip install mnki); this shim will be removed in 0.2."""
import warnings as _w
_w.warn("`agent_trust` has been renamed to `mnki` — `from mnki import AgentTrustClient`", DeprecationWarning, stacklevel=2)
from mnki import AgentTrustClient, AgentTrustError, AgentIdentity, b64url, body_hash  # noqa: E402,F401

__all__ = ["AgentTrustClient", "AgentTrustError", "AgentIdentity", "b64url", "body_hash"]
