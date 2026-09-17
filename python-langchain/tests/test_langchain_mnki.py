import sys, unittest, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python")); sys.path.insert(0, str(ROOT / "python-langchain"))


class LangchainMnkiTests(unittest.TestCase):
    def test_reexports_the_mnki_adapter(self):
        import langchain_mnki
        from mnki.adapters import langchain as impl
        self.assertIs(langchain_mnki.guard_tools, impl.guard_tools)
        self.assertIs(langchain_mnki.guard_tool, impl.guard_tool)
        self.assertEqual(sorted(langchain_mnki.__all__), ["__version__", "guard_tool", "guard_tools"])

    def test_guards_a_duck_typed_tool_in_local_mode(self):
        from mnki import Guard
        from mnki.local import demo_world
        from langchain_mnki import guard_tools

        class Refund:
            name = "refund.create"
            def invoke(self, args, config=None, **kw): return {"refunded": args["amount"]}

        g = Guard(world=demo_world(), agent="invoice-agent", action_prefix="", mode="enforce")
        [tool] = guard_tools(g, [Refund()])
        self.assertEqual(tool.invoke({"customer_id": "customer:4711", "amount": 420, "currency": "EUR"}), {"refunded": 420})
        import json
        refused = json.loads(tool.invoke({"customer_id": "customer:4711", "amount": 47000, "currency": "EUR"}))
        self.assertEqual(refused.get("error"), "denied")
        self.assertTrue(refused.get("evidence"))


if __name__ == "__main__":
    unittest.main()
