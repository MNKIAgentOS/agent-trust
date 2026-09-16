"""Level-1 conformance vectors through the Python pipeline — the cross-language contract with the TypeScript verifier."""
import glob, json, os, unittest
from datetime import datetime, timezone

from mnki import Guard, Denied, ApprovalRequired, demo_world, local_verify, load_world
from mnki.policy import evaluate, parse_policy_doc
from mnki.pipeline import parse_verify_request, resolve_chain

HERE = os.path.dirname(__file__)
DIRS = [os.path.join(HERE, "..", "..", "conformance", "vectors"), os.path.join(HERE, "..", "conformance", "vectors")]


def vectors():
    for d in DIRS:
        files = sorted(glob.glob(os.path.join(d, "V*.json")))
        if files: return [json.load(open(f)) for f in files]
    return []


class Pipeline(unittest.TestCase):
    def test_every_level_1_vector(self):
        vs = vectors(); self.assertGreaterEqual(len(vs), 14)
        for v in vs:
            with self.subTest(v["id"]):
                now = datetime.fromisoformat(v["now"].replace("Z", "+00:00")).astimezone(timezone.utc)
                r = local_verify(v["world"], v["request"], now); self.assertTrue(r["ok"], v["id"]); res = r["result"]; e = v["expect"]
                self.assertEqual(res["decision"], e["decision"])
                for reason in e.get("reasons_include", []): self.assertIn(reason, res["reasons"])
                if "reasons_exact" in e: self.assertEqual(res["reasons"], e["reasons_exact"])
                for step, status in (e.get("evidence") or {}).items():
                    self.assertEqual(next((x["status"] for x in res["evidence"] if x["step"] == step), None), status, f"{v['id']} {step}")

    def test_demo_story_through_the_local_guard(self):
        seen = []
        g = Guard(world=demo_world(), agent="invoice-agent", action_prefix="", on_decision=lambda r: seen.append(f"{r['tool']}:{r['decision']}"))
        with self.assertRaises(Denied) as cm: g.check("refund.create", {"customer_id": "customer:1", "amount": 47000, "currency": "EUR"})
        self.assertIn("constraint_violated", cm.exception.reasons); self.assertEqual(cm.exception.evidence[0]["status"], "fail")
        ok = g.check("refund.create", {"customer_id": "customer:1", "amount": 420, "currency": "EUR"}); self.assertTrue(ok["allowed"])
        with self.assertRaises(ApprovalRequired): g.check("refund.create", {"customer_id": "customer:1", "amount": 3200, "currency": "EUR"})
        with self.assertRaises(Denied) as cm2: g.check("database.write", {"table": "users"})
        self.assertIn("policy:no-database-writes:deny", cm2.exception.reasons)
        self.assertEqual(seen, ["refund.create:DENY", "refund.create:ALLOW", "refund.create:REQUIRE_APPROVAL", "database.write:DENY"])
        observe = Guard(world=demo_world(), agent="agt_invoice", action_prefix="", mode="observe", on_decision=lambda r: seen.append(r["tags"]))
        self.assertTrue(observe.check("refund.create", {"amount": 47000, "currency": "EUR", "customer_id": "customer:1"})["allowed"]); self.assertIn("would_deny", seen[-1])
        with self.assertRaises(ValueError): Guard(agent="x")

    def test_helpers(self):
        self.assertEqual(parse_verify_request({"agent": " a ", "action": "b", "amount": 1, "currency": "EUR"}), {"ok": True, "request": {"agent": "a", "action": "b", "amount": 1, "currency": "EUR"}})
        self.assertEqual(parse_verify_request({"agent": "a", "action": "b", "currency": "eur"})["code"], "currency"); self.assertEqual(parse_verify_request([])["code"], "not_object")
        self.assertEqual(resolve_chain("c", {"c": {"id": "c", "parent_id": "b"}, "b": {"id": "b", "parent_id": "c"}}.get), {"ok": False, "reason": "cycle", "at": "c"})
        self.assertEqual(resolve_chain("c", {"c": {"id": "c", "parent_id": "x"}}.get), {"ok": False, "reason": "missing", "at": "x"})
        doc = {"version": 1, "rules": [{"id": "night", "match": {"action": "pay*"}, "conditions": [{"kind": "time_window", "start": "22:00", "end": "06:00"}], "effect": "deny"}]}
        self.assertTrue(parse_policy_doc(doc)["ok"]); self.assertEqual(parse_policy_doc({"version": 2})["error"], "version")
        late = datetime(2026, 9, 16, 23, 30, tzinfo=timezone.utc); day = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)
        inp = lambda t: {"action": "pay.create", "risk_tier": "low", "agent_labels": {}, "delegation_depth": 0, "attestations": [], "time": t}
        self.assertEqual(evaluate(doc, inp(late))["effect"], "deny"); self.assertEqual(evaluate(doc, inp(day)), {"effect": "allow", "fired": [], "reasons": ["policy:default:allow"]})
        self.assertEqual(load_world({"world": {"agent": None}, "id": "V"}), {"agent": None}); self.assertEqual(load_world('{"agent": null}'), {"agent": None})
