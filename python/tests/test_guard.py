import json, unittest
from mnki import Guard, Denied, ApprovalRequired, wrap


class FakeClient:
    def __init__(self, decision, statuses=None):
        self.decision, self.statuses, self.calls = decision, list(statuses or []), []
    def verify(self, request, identity=None, credential=None):
        self.calls.append(("verify", request)); d = dict(self.decision); return d
    def approval_status(self, approval_id):
        self.calls.append(("status", approval_id)); return {"id": approval_id, "decision_id": "dec_1", "status": self.statuses.pop(0) if self.statuses else "pending"}
    def issue_attestation(self, decision_id, ttl_seconds=None, audience=None):
        self.calls.append(("attest", decision_id)); return {"ok": True, "token": "eyJ.a.b"}


def dec(kind, **extra):
    d = {"decision": kind, "reasons": ["identity_verified", "authority_valid"] if kind == "ALLOW" else ["policy:big:require_approval"], "evidence": [{"step": "policy", "status": "pass" if kind == "ALLOW" else "warn", "title": "Policy"}], "request_id": "req_1", "decision_id": "dec_1", "approval_id": "apr_1" if kind == "REQUIRE_APPROVAL" else None, "latency_ms": 2}
    d.update(extra); return d


class GuardTest(unittest.TestCase):
    def test_allow_deny_and_argument_mapping(self):
        c = FakeClient(dec("ALLOW")); g = Guard(c, "invoice-agent")
        r = g.check("refund.create", {"customer_id": "customer:1", "amount": 420, "currency": "EUR", "region": "EU"})
        self.assertTrue(r["allowed"])
        req = c.calls[0][1]
        self.assertEqual((req["agent"], req["action"], req["resource"], req["amount"], req["currency"], req["context"]["region"], req["context"]["tool"]), ("invoice-agent", "tool:refund.create", "customer:1", 420, "EUR", "EU", "refund.create"))
        self.assertEqual(len(req["context"]["arguments_hash"]), 43)
        d = FakeClient(dec("DENY", reasons=["constraint_violated"], evidence=[{"step": "identity", "status": "pass", "title": "ok"}, {"step": "constraints", "status": "fail", "title": "Request exceeds capability constraints"}]))
        with self.assertRaises(Denied) as ctx: Guard(d, "a").check("refund.create", {"amount": 99999})
        self.assertEqual(ctx.exception.evidence[0]["status"], "fail"); self.assertIn("constraint_violated", str(ctx.exception))

    def test_modes(self):
        seen = []
        d = FakeClient(dec("DENY", reasons=["capability_missing"]))
        self.assertTrue(Guard(d, "a", mode="observe", on_decision=seen.append).check("x", {})["allowed"])
        self.assertEqual(seen[0]["enforced"], False); self.assertIn("would_deny", seen[0]["tags"]); self.assertIn("excess_capability", seen[0]["tags"])
        self.assertTrue(Guard(d, "a", mode="warn").check("x", {})["allowed"])
        self.assertTrue(Guard(d, "a", mode="require_approval").check("x", {})["allowed"])
        with self.assertRaises(ApprovalRequired): Guard(FakeClient(dec("REQUIRE_APPROVAL")), "a", mode="require_approval", on_approval="throw").check("x", {})

    def test_approval_wait_then_attestation_and_failures(self):
        c = FakeClient(dec("REQUIRE_APPROVAL"), statuses=["pending", "pending", "approved"])
        r = Guard(c, "a", sleep=lambda s: None).check("refund.create", {"amount": 3200})
        self.assertTrue(r["allowed"]); self.assertEqual(r["attestation"], "eyJ.a.b"); self.assertEqual([x[0] for x in c.calls].count("status"), 3)
        with self.assertRaises(ApprovalRequired) as ctx: Guard(FakeClient(dec("REQUIRE_APPROVAL"), ["rejected"]), "a", sleep=lambda s: None).check("x", {})
        self.assertEqual((ctx.exception.status, ctx.exception.code), ("rejected", "approval_rejected"))
        with self.assertRaises(ApprovalRequired) as ctx: Guard(FakeClient(dec("REQUIRE_APPROVAL")), "a", approval_timeout=0, sleep=lambda s: None).check("x", {})
        self.assertEqual(ctx.exception.status, "timeout")

    def test_wrap_decorator_sync_and_async(self):
        c = FakeClient(dec("ALLOW")); g = Guard(c, "a", action_prefix="")
        @g.wrap("refund.create")
        def refund(customer_id, amount, currency="EUR"): return f"refunded {amount}"
        self.assertEqual(refund(customer_id="customer:1", amount=100), "refunded 100")
        self.assertEqual(c.calls[-1][1]["action"], "refund.create"); self.assertEqual(c.calls[-1][1]["amount"], 100)
        import asyncio
        @wrap(FakeClient(dec("DENY")), "a", "delete_db")
        async def delete_db(table): return "gone"
        with self.assertRaises(Denied): asyncio.run(delete_db(table="users"))
