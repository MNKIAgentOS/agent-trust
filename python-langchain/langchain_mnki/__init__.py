"""
langchain-mnki — LangChain / LangGraph tools guarded by mnki (Agent Trust).

    pip install langchain-mnki

    from mnki import AgentTrustClient, Guard
    from langchain_mnki import guard_tools

    g = Guard(AgentTrustClient("https://mnki.com", api_key=os.environ["MNKI_API_KEY"]), agent="invoice-agent")
    graph = create_react_agent(model, guard_tools(g, [refund, lookup]))

Every `BaseTool` becomes a `GuardedTool` subclass (so `ToolNode`, `bind_tools` and isinstance checks keep working)
whose `_run` / `_arun` verify the call against the agent's delegated authority first. A refused call returns
`{"error": "denied", "reasons": [...], "evidence": [...]}` to the model so it can explain itself; pass
`on_refused="throw"` to raise instead. Local mode (no account) works the same way with `Guard(world=demo_world(), ...)`.

This distribution is the LangChain-facing name of `mnki.adapters.langchain`; the implementation lives in the
`mnki` package so the two can never drift.
"""
from mnki.adapters.langchain import guard_tool, guard_tools

__all__ = ["guard_tool", "guard_tools", "__version__"]
__version__ = "0.3.0"
