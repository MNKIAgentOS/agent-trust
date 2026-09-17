# langchain-mnki

LangChain / LangGraph tools guarded by [mnki](https://mnki.com) (Agent Trust): every tool call is verified against
the agent's delegated authority, with an evidence list, before it runs.

```bash
pip install langchain-mnki
```

```python
import os
from mnki import AgentTrustClient, Guard
from langchain_mnki import guard_tools
from langgraph.prebuilt import create_react_agent

g = Guard(AgentTrustClient("https://mnki.com", api_key=os.environ["MNKI_API_KEY"]), agent="invoice-agent")
graph = create_react_agent(model, guard_tools(g, [refund, lookup]))
```

- Tools stay `BaseTool` instances (a `GuardedTool` subclass), so `ToolNode`, `bind_tools` and isinstance checks work.
- A refused call returns `{"error": "denied", "reasons": [...], "evidence": [...]}` to the model; `on_refused="throw"` raises.
- Calls that policy escalates wait for a human approval (phone app) and continue when approved.
- No account needed to try it: `Guard(world=demo_world(), agent="invoice-agent")` runs the same verifier offline.

Pinned versions and the support level are in the [compatibility matrix](https://mnki.com/docs/compatibility); every
integration path is on one page at <https://mnki.com/docs/integrations>. The implementation is
`mnki.adapters.langchain` in the [`mnki`](https://pypi.org/project/mnki/) package; this distribution is its
LangChain-facing name. Apache-2.0.
