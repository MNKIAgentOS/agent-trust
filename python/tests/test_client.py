import io, json, unittest, urllib.error
from agent_trust import AgentTrustClient, AgentTrustError, body_hash

class FakeResp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False

class ClientTest(unittest.TestCase):
    def test_verify_and_errors(self):
        seen = []
        def opener(req):
            seen.append((req.full_url, req.get_method(), dict(req.header_items()), req.data))
            if req.full_url.endswith("/api/v1/verify"):
                return FakeResp(json.dumps({"decision": "ALLOW", "reasons": ["request_unsigned"], "evidence": []}).encode())
            if "/status/" in req.full_url:
                raise urllib.error.HTTPError(req.full_url, 404, "nf", {}, io.BytesIO(b'{"error":"not_found"}'))
            return FakeResp(b"{}")
        c = AgentTrustClient("https://staging.mnki.com/", "at_verify_x", opener=opener)
        d = c.verify({"agent": "procurement-7821", "action": "purchase.create", "amount": 10, "currency": "EUR"}, credential="eyJ.x.y")
        self.assertEqual(d["decision"], "ALLOW")
        url, method, headers, data = seen[0]
        self.assertEqual((url, method), ("https://staging.mnki.com/api/v1/verify", "POST"))
        self.assertEqual(headers["Authorization"], "Bearer at_verify_x"); self.assertEqual(headers["Agent-credential"], "eyJ.x.y")
        self.assertEqual(json.loads(data)["agent"], "procurement-7821")
        with self.assertRaises(AgentTrustError) as ctx: c.status("agt_x")
        self.assertEqual((ctx.exception.status, ctx.exception.code), (404, "not_found"))
        self.assertEqual(body_hash("{}"), "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o")

    def test_signing_when_cryptography_available(self):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("cryptography not installed")
        from agent_trust import AgentIdentity
        ident = AgentIdentity.create("agt_1")
        proof = ident.sign_proof("post", "https://X.example/v1/verify?q=1", "{}")
        self.assertEqual(proof.count("."), 2)
        header = json.loads(__import__("base64").urlsafe_b64decode(proof.split(".")[0] + "=="))
        self.assertEqual(header["typ"], "agent-trust-proof+jwt")

if __name__ == "__main__":
    unittest.main()
