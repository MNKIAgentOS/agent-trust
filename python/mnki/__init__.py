"""
mnki — give every AI agent an identity, authority and proof of action.

    from mnki import AgentTrustClient, AgentIdentity
    c = AgentTrustClient("https://mnki.com", api_key="at_verify_…")
    d = c.verify({"agent": "invoice-agent", "action": "refund.create", "amount": 420, "currency": "EUR"})
    d["decision"]      # "ALLOW" | "DENY" | "REQUIRE_APPROVAL"; d["evidence"] is the ✓/⚠/✕ list

Local mode (no account): `Guard(world=demo_world(), agent="invoice-agent", action_prefix="")` — the same pipeline as the
control plane, in-process. Framework adapters: `mnki.adapters.openai_agents`, `.langchain`, `.crewai`, `.pydantic_ai`.
Zero dependencies for verify / attest / delegate; `pip install mnki[signing]` for Agent-Proof signing.
"""
from .client import AgentTrustClient, Client
from .errors import AgentTrustError, MnkiError
from .identity import AgentIdentity, b64url, b64url_decode, body_hash
from . import offline
from .guard import Guard, Denied, ApprovalRequired, wrap
from .local import demo_world, local_verify, load_world
from . import pipeline, policy, adapters

__version__ = "0.1.0"
__all__ = ["AgentTrustClient", "Client", "AgentTrustError", "MnkiError", "AgentIdentity", "b64url", "b64url_decode", "body_hash", "offline", "Guard", "Denied", "ApprovalRequired", "wrap", "demo_world", "local_verify", "load_world", "pipeline", "policy", "adapters"]
