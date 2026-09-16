"""
Framework adapters — thin, framework-free wrappers over `Guard.check`. Each module imports its framework lazily
(only when a real framework object is handed in), so `mnki` stays dependency-free.

    from mnki.adapters.openai_agents import guard_tools     # openai-agents  (FunctionTool.on_invoke_tool)
    from mnki.adapters.langchain import guard_tools         # langchain-core BaseTool (invoke / ainvoke)
    from mnki.adapters.crewai import guard_tools            # crewai BaseTool (_run)
    from mnki.adapters.pydantic_ai import guard_tool        # pydantic-ai tool functions (decorator)

Refusals are returned to the model as a JSON result by default (`on_refused="result"`), or raised
(`on_refused="throw"`).
"""
from . import shared
from .shared import refusal, refusal_json, wanted

__all__ = ["shared", "refusal", "refusal_json", "wanted"]
