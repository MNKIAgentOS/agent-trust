# agent-trust (Python)

Zero-dependency client for the Agent Trust API; `pip install cryptography` for request signing.

```python
from agent_trust import AgentTrustClient
c = AgentTrustClient("https://staging.mnki.com", api_key="at_verify_…")
d = c.verify({"agent": "procurement-7821", "action": "purchase.create", "resource": "supplier:4711", "amount": 2450, "currency": "EUR", "context": {"region": "EU"}})
print(d["decision"]); print(*(f'{e["status"]:8} {e["title"]}' for e in d["evidence"]), sep="\n")
```

Run the tests: `cd python && python3 -m unittest discover -s tests`.
