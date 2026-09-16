# mnki (Python)

```bash
pip install mnki            # verify, delegate, attest — no dependencies
pip install "mnki[signing]" # Agent-Proof signing with a local key
```

```python
from mnki import AgentTrustClient, AgentIdentity

c = AgentTrustClient("https://mnki.com", api_key="at_verify_…")
d = c.verify({"agent": "invoice-agent", "action": "refund.create", "amount": 420, "currency": "EUR"})
print(d["decision"], [e["title"] for e in d["evidence"]])
```

Local mode (no account) runs the same pipeline as the control plane, in-process, validated against the conformance vectors:

```python
from mnki import Guard, Denied, demo_world
g = Guard(world=demo_world(), agent="invoice-agent", action_prefix="", mode="observe")   # observe → warn → require_approval → enforce

@g.wrap("refund.create")
def refund(customer_id: str, amount: float, currency: str = "EUR"): ...
```

Framework adapters (the framework is imported lazily, never required): `mnki.adapters.openai_agents`, `.langchain`,
`.crewai`, `.pydantic_ai` — each exposes `guard_tools(guard, tools)`; refusals come back to the model as
`{"error": "denied", "reasons": [...], "evidence": [...]}` or raise with `on_refused="throw"`. Extras:
`pip install "mnki[openai-agents]"`, `[langchain]`, `[crewai]`, `[pydantic-ai]`, `[httpx]`.

`agent_trust` remains importable as a deprecated alias for one minor version. Apache-2.0.
