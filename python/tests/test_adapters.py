"""Every adapter against the local demo world — no framework installed, no network; the real-framework paths run when the framework is importable."""
import asyncio, json, unittest

from mnki import Guard, Denied, demo_world
from mnki.adapters import openai_agents, langchain, crewai, pydantic_ai, refusal

OK = {"customer_id": "customer:1", "amount": 420, "currency": "EUR"}; BIG = {"customer_id": "customer:1", "amount": 47000, "currency": "EUR"}
guard = lambda: Guard(world=demo_world(), agent="invoice-agent", action_prefix="")


class FunctionTool:
    def __init__(self, name): self.name, self.params_json_schema = name, {"type": "object"}
    async def on_invoke_tool(self, ctx, input_json): return f"ran {self.name} {input_json}"


class Adapters(unittest.TestCase):
    def test_openai_agents(self):
        t = openai_agents.guard_tools(guard(), [FunctionTool("refund.create")])[0]
        self.assertEqual(t.params_json_schema, {"type": "object"}); self.assertIsInstance(t, FunctionTool)
        self.assertEqual(asyncio.run(t.on_invoke_tool(None, json.dumps(OK))), f"ran refund.create {json.dumps(OK)}")
        r = json.loads(asyncio.run(t.on_invoke_tool(None, json.dumps(BIG)))); self.assertEqual(r["error"], "denied"); self.assertIn("constraint_violated", r["reasons"]); self.assertEqual(r["evidence"][0]["status"], "fail")
        strict = openai_agents.guard_tool(guard(), FunctionTool("refund.create"), on_refused="throw")
        with self.assertRaises(Denied): asyncio.run(strict.on_invoke_tool(None, json.dumps(BIG)))
        untouched = openai_agents.guard_tool(guard(), FunctionTool("database.write"), skip=["database.write"]); self.assertTrue(asyncio.run(untouched.on_invoke_tool(None, "{}")).startswith("ran"))

    def test_langchain_proxy_and_subclass(self):
        class Tool:
            name, description = "refund.create", "refund"
            def invoke(self, inp, config=None): return {"done": inp}
            async def ainvoke(self, inp, config=None): return {"adone": inp}
        t = langchain.guard_tools(guard(), [Tool()])[0]
        self.assertEqual(t.description, "refund"); self.assertEqual(t.invoke(OK), {"done": OK})
        self.assertEqual(t.invoke({"name": "refund.create", "args": OK, "id": "c1", "type": "tool_call"}), {"done": {"name": "refund.create", "args": OK, "id": "c1", "type": "tool_call"}})
        self.assertEqual(json.loads(t.invoke(BIG))["error"], "denied"); self.assertEqual(asyncio.run(t.ainvoke(OK)), {"adone": OK})
        try:
            from langchain_core.tools import BaseTool, StructuredTool  # type: ignore
        except ImportError:
            self.skipTest("langchain-core not installed"); return
        real = StructuredTool.from_function(lambda customer_id, amount, currency="EUR": f"refunded {amount}", name="refund.create", description="refund")
        g = langchain.guard_tools(guard(), [real])[0]; self.assertIsInstance(g, BaseTool); self.assertEqual(g.name, "refund.create")
        self.assertEqual(g.invoke(OK), "refunded 420"); self.assertEqual(json.loads(g.invoke(BIG))["error"], "denied")

    def test_crewai_proxy_and_subclass(self):
        class Tool:
            name, description = "refund.create", "refund"
            def _run(self, **kw): return f"ran {kw['amount']}"
        t = crewai.guard_tools(guard(), [Tool()])[0]
        self.assertEqual(t._run(**OK), "ran 420"); self.assertEqual(json.loads(t._run(**BIG))["error"], "denied")
        try:
            from crewai.tools import BaseTool  # type: ignore
        except ImportError:
            self.skipTest("crewai not installed"); return
        class Refund(BaseTool):
            name: str = "refund.create"; description: str = "refund"
            def _run(self, customer_id: str, amount: float, currency: str = "EUR") -> str: return f"refunded {amount}"
        g = crewai.guard_tools(guard(), [Refund()])[0]; self.assertIsInstance(g, BaseTool)
        self.assertEqual(g._run(**OK), "refunded 420"); self.assertEqual(json.loads(g._run(**BIG))["error"], "denied")

    def test_pydantic_ai(self):
        class RunContext: pass
        @pydantic_ai.guard_tool(guard(), name="refund.create")
        def refund(ctx, customer_id: str, amount: float, currency: str = "EUR") -> str: return f"refunded {amount}"
        self.assertEqual(refund(RunContext(), "customer:1", 420), "refunded 420"); self.assertEqual(refund.__name__, "refund")
        self.assertEqual(json.loads(refund(RunContext(), "customer:1", 47000, currency="EUR"))["error"], "denied")
        @pydantic_ai.guard_tool(guard(), name="refund.create")
        async def arefund(customer_id: str, amount: float, currency: str = "EUR") -> str: return "ok"
        self.assertEqual(asyncio.run(arefund("customer:1", 420)), "ok"); self.assertEqual(json.loads(asyncio.run(arefund("customer:1", 47000)))["error"], "denied")
        class ToolObj:
            def __init__(self): self.name, self.function = "refund.create", (lambda customer_id, amount, currency="EUR": "done")
        obj = pydantic_ai.guard_tools(guard(), [ToolObj()])[0]; self.assertEqual(json.loads(obj.function("customer:1", 47000))["error"], "denied")

    def test_refusal_reraises_unknown(self):
        with self.assertRaises(TypeError): refusal(TypeError("boom"))
