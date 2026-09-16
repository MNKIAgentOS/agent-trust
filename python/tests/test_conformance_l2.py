"""Level-2 conformance vectors (signed objects) through the Python offline verifier — the cross-language contract."""
import glob, json, os, unittest
from datetime import datetime, timezone

HERE = os.path.dirname(__file__)
DIRS = [os.path.join(HERE, "..", "..", "conformance", "crypto"), os.path.join(HERE, "..", "conformance", "crypto")]


def vectors():
    for d in DIRS:
        files = sorted(glob.glob(os.path.join(d, "L2-*.json")))
        if files: return [json.load(open(f)) for f in files]
    return []


class ConformanceL2(unittest.TestCase):
    def setUp(self):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("cryptography not installed")
        from mnki import offline
        self.o = offline
        self.vs = vectors()
        self.assertGreaterEqual(len(self.vs), 12)

    def test_all_level_2_vectors(self):
        for v in self.vs:
            now = datetime.fromisoformat(v["now"].replace("Z", "+00:00")).astimezone(timezone.utc)
            keys = v.get("keys", {}); e = v["expect"]; c = v["case"]
            resolve = lambda kid, iss, keys=keys: (keys.get(iss) or {}).get(kid)
            with self.subTest(v["id"]):
                if c["kind"] == "delegation_chain":
                    r = self.o.verify_delegation_chain(c["tokens"], resolve, now)
                    self.assertEqual(r["ok"], e["ok"])
                    if r["ok"]: self.assertEqual((r["chain"], r["subject"], r["effective"]), (e["chain"], e["subject"], e["effective"]))
                    else: self.assertEqual((r["at"], r["reason"]), (e["at"], e["reason"]))
                elif c["kind"] == "request_proof":
                    r = self.o.verify_request_proof(c["proof"], lambda kid, c=c: (c["agent_keys"].get(kid) if kid else None), c["htm"], c["htu"], c["body_hash"], now)
                    self.assertEqual(r["ok"], e["ok"])
                    if r["ok"]: self.assertEqual((r["claims"]["iss"], r["alg"]), (e["iss"], e["alg"]))
                    else: self.assertEqual(r["reason"], e["reason"])
                elif c["kind"] == "attestation":
                    r = self.o.verify_attestation(c["token"], resolve, now)
                    self.assertEqual(r["ok"], e["ok"])
                    if r["ok"]: self.assertEqual((r["payload"]["sub"], r["payload"]["atp"]["action"], r["expires_in"]), (e["sub"], e["action"], e["expires_in"]))
                    else: self.assertEqual(r["reason"], e["reason"])
                elif c["kind"] == "approval":
                    r = self.o.verify_approval(c["token"], resolve, now)
                    self.assertEqual(r["ok"], e["ok"])
                    if r["ok"]:
                        self.assertEqual((r["header"]["kid"], r["payload"]["jti"], r["payload"]["atp"]["status"]), (e["kid"], e["jti"], e["status"]))
                        self.assertEqual(r["payload"]["atp"].get("device_proof_hash"), e.get("device_proof_hash"))
                    else: self.assertEqual(r["reason"], e["reason"])
                else:
                    self.fail(f"unknown case kind {c['kind']}")

    def test_attenuation_rules(self):
        o = self.o
        self.assertTrue(o.resource_contains("supplier:*", "supplier:1*")); self.assertFalse(o.resource_contains("supplier:1", "supplier:2"))
        self.assertTrue(o.constraints_tighter({"max_value": 5000, "currency": "EUR", "region": ["EU"]}, {"max_value": 1200, "currency": "EUR", "region": ["EU"]}))
        self.assertFalse(o.constraints_tighter({"max_value": 5000}, {}))
        self.assertFalse(o.constraints_tighter({"region": ["EU"]}, {"region": ["EU", "US"]}))
        self.assertEqual(o.attenuate([{"action": "a", "resource": "x:*"}], [{"action": "a", "resource": "x:1"}, {"action": "b", "resource": "x:1"}]), [{"action": "a", "resource": "x:1"}])
