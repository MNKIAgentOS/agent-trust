"""
Offline verification of the signed objects in the Agent Trust profile — no control plane involved:
delegation credential chains (`agent-trust-delegation+jwt`), authorization attestations
(`agent-trust-attestation+jwt`), approval objects (`agent-trust-approval+jwt`) and request proofs
(`agent-trust-proof+jwt`). Mirrors packages/verifier/src/{credential,proof,delegation/attenuate}.ts and
passes the level-2 conformance vectors. Needs `cryptography` (pip install mnki[signing]).

    from mnki.offline import verify_delegation_chain, jwks_resolver
    r = verify_delegation_chain(tokens, jwks_resolver({"org_acme": jwks}), now=datetime.now(timezone.utc))
"""
from __future__ import annotations
import base64, hashlib, json, time
from datetime import datetime, timezone
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

from .identity import b64url, b64url_decode, body_hash

KeyResolver = Callable[[str, str], Optional[dict]]   # (kid, iss) -> JWK | None
MAX_CHAIN = 8
DELEGATION_TYP = "agent-trust-delegation+jwt"
ATTESTATION_TYP = "agent-trust-attestation+jwt"
APPROVAL_TYP = "agent-trust-approval+jwt"
PROOF_TYP = "agent-trust-proof+jwt"


def _ts(now: datetime | float | int | None) -> int:
    if now is None: return int(time.time())
    if isinstance(now, datetime): return int(now.timestamp())
    return int(now)


def decode_jwt(token: str) -> Optional[tuple[dict, dict]]:
    parts = token.split(".")
    if len(parts) != 3: return None
    try:
        return json.loads(b64url_decode(parts[0])), json.loads(b64url_decode(parts[1]))
    except Exception:
        return None


def alg_for_jwk(jwk: dict) -> Optional[str]:
    if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256": return "ES256"
    if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519": return "EdDSA"
    return None


def _verify_signature(alg: str, jwk: dict, signing_input: bytes, sig: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    try:
        if alg == "ES256":
            x = int.from_bytes(b64url_decode(jwk["x"]), "big"); y = int.from_bytes(b64url_decode(jwk["y"]), "big")
            pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
            if len(sig) != 64: return False
            der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
            pub.verify(der, signing_input, ec.ECDSA(hashes.SHA256())); return True
        if alg == "EdDSA":
            ed25519.Ed25519PublicKey.from_public_bytes(b64url_decode(jwk["x"])).verify(sig, signing_input); return True
    except (InvalidSignature, ValueError, KeyError):
        return False
    return False


def verify_jwt(token: str, typ: str, resolve_key: KeyResolver, now: datetime | float | int | None = None, max_skew: int = 300) -> dict:
    """Signature, typ and time claims. Returns {"ok": True, "header", "payload"} or {"ok": False, "reason"}. Never raises."""
    d = decode_jwt(token)
    if not d: return {"ok": False, "reason": "malformed"}
    header, payload = d
    if header.get("typ") != typ: return {"ok": False, "reason": "typ"}
    if header.get("alg") not in ("ES256", "EdDSA"): return {"ok": False, "reason": "alg"}
    if not isinstance(header.get("kid"), str) or not isinstance(payload.get("iss"), str): return {"ok": False, "reason": "claims"}
    jwk = resolve_key(header["kid"], payload["iss"])
    if not jwk: return {"ok": False, "reason": "unknown_key"}
    if alg_for_jwk(jwk) != header["alg"]: return {"ok": False, "reason": "alg_mismatch"}
    parts = token.split(".")
    if not _verify_signature(header["alg"], jwk, f"{parts[0]}.{parts[1]}".encode(), b64url_decode(parts[2])): return {"ok": False, "reason": "signature"}
    t = _ts(now)
    if isinstance(payload.get("exp"), (int, float)) and payload["exp"] <= t: return {"ok": False, "reason": "expired"}
    if isinstance(payload.get("nbf"), (int, float)) and payload["nbf"] > t + max_skew: return {"ok": False, "reason": "not_yet_valid"}
    if isinstance(payload.get("iat"), (int, float)) and payload["iat"] > t + max_skew: return {"ok": False, "reason": "iat_future"}
    return {"ok": True, "header": header, "payload": payload}


# --- capability attenuation (port of delegation/attenuate.ts) ---
def _glob_prefix(resource: str) -> Optional[str]:
    return resource[:-1] if resource.endswith("*") else None

def resource_contains(parent: str, child: str) -> bool:
    if parent == child: return True
    pp = _glob_prefix(parent)
    if pp is None: return False
    cp = _glob_prefix(child)
    return (cp if cp is not None else child).startswith(pp)

def constraints_tighter(parent: Optional[dict], child: Optional[dict]) -> bool:
    if not parent: return True
    c = child or {}
    for key, p in parent.items():
        if p is None: continue
        if key in ("max_value", "max_total"):
            cv = c.get(key)
            if not isinstance(cv, (int, float)) or isinstance(cv, bool) or not cv <= p: return False
        elif key == "region":
            cr = c.get("region")
            if not isinstance(cr, list) or not cr or not all(r in set(p) for r in cr): return False
        elif json.dumps(c.get(key), sort_keys=True) != json.dumps(p, sort_keys=True):
            return False
    return True

def capability_covered(parent: dict, child: dict) -> bool:
    return parent.get("action") == child.get("action") and resource_contains(parent["resource"], child["resource"]) and constraints_tighter(parent.get("constraints"), child.get("constraints"))

def is_subset(child: list, parent: list) -> bool:
    return all(any(capability_covered(p, c) for p in parent) for c in child)

def attenuate(parent: list, requested: list) -> list:
    return [c for c in requested if any(capability_covered(p, c) for p in parent)]


def _sha256_b64url(s: str) -> str:
    return b64url(hashlib.sha256(s.encode()).digest())


def verify_delegation_chain(tokens: list[str], resolve_key: KeyResolver, now: datetime | float | int | None = None) -> dict:
    """Root → leaf, offline: each link's parent_hash commits to the parent token and capabilities attenuate."""
    if not tokens: return {"ok": False, "at": 0, "reason": "empty"}
    if len(tokens) > MAX_CHAIN: return {"ok": False, "at": len(tokens), "reason": "too_long"}
    prev: Optional[tuple[str, dict]] = None; chain: list[str] = []; effective: list = []; root_issuer = None
    for i, tok in enumerate(tokens):
        r = verify_jwt(tok, DELEGATION_TYP, resolve_key, now)
        if not r["ok"]: return {"ok": False, "at": i, "reason": r["reason"]}
        p = r["payload"]; a = p.get("atp") or {}
        if a.get("v") != 1 or not isinstance(a.get("capabilities"), list) or not isinstance(a.get("effective"), list) or not isinstance(p.get("sub"), str) or not isinstance(p.get("jti"), str):
            return {"ok": False, "at": i, "reason": "claims"}
        if i == 0:
            if a.get("parent") is not None or a.get("depth") != 0: return {"ok": False, "at": i, "reason": "root_expected"}
            if (a.get("issuer") or {}).get("type") != "principal": return {"ok": False, "at": i, "reason": "root_requires_principal"}
            effective = a["capabilities"]; root_issuer = a["issuer"]
            if json.dumps(a["effective"]) != json.dumps(effective): return {"ok": False, "at": i, "reason": "effective_mismatch"}
        else:
            pp = prev[1]
            if a.get("parent") != pp["jti"]: return {"ok": False, "at": i, "reason": "parent_link"}
            if a.get("parent_hash") != _sha256_b64url(prev[0]): return {"ok": False, "at": i, "reason": "parent_hash"}
            if a.get("depth") != pp["atp"]["depth"] + 1: return {"ok": False, "at": i, "reason": "depth"}
            iss = a.get("issuer") or {}
            if iss.get("type") != "agent" or iss.get("id") != pp["sub"]: return {"ok": False, "at": i, "reason": "issuer_must_be_parent_subject"}
            if not is_subset(a["capabilities"], effective): return {"ok": False, "at": i, "reason": "exceeds_parent"}
            effective = attenuate(effective, a["capabilities"])
            if json.dumps(a["effective"]) != json.dumps(effective): return {"ok": False, "at": i, "reason": "effective_mismatch"}
        chain.append(p["jti"]); prev = (tok, p)
    return {"ok": True, "effective": effective, "chain": chain, "subject": prev[1]["sub"], "root_issuer": root_issuer}


def verify_attestation(token: str, resolve_key: KeyResolver, now: datetime | float | int | None = None) -> dict:
    r = verify_jwt(token, ATTESTATION_TYP, resolve_key, now)
    if not r["ok"]: return r
    p = r["payload"]; a = p.get("atp") or {}
    if a.get("v") != 1 or not isinstance(p.get("sub"), str) or not isinstance(p.get("jti"), str) or not isinstance(p.get("exp"), (int, float)) or not isinstance(a.get("action"), str):
        return {"ok": False, "reason": "claims"}
    return {"ok": True, "payload": p, "expires_in": int(p["exp"]) - _ts(now)}


def verify_approval(token: str, resolve_key: KeyResolver, now: datetime | float | int | None = None) -> dict:
    r = verify_jwt(token, APPROVAL_TYP, resolve_key, now)
    if not r["ok"]: return r
    p = r["payload"]; a = p.get("atp") or {}
    if a.get("v") != 1 or not all(isinstance(p.get(k), str) for k in ("sub", "jti")) or not all(isinstance(p.get(k), (int, float)) for k in ("iat", "exp")): return {"ok": False, "reason": "claims"}
    if not all(isinstance(a.get(k), str) for k in ("decision_id", "action", "approver", "reason")) or a.get("status") not in ("approved", "rejected"): return {"ok": False, "reason": "claims"}
    if a.get("request_hash") is not None and not isinstance(a.get("request_hash"), str): return {"ok": False, "reason": "claims"}
    return r


def normalize_htu(u: str) -> str:
    s = urlsplit(u); return f"{s.scheme.lower()}://{s.netloc.lower()}{s.path}"


def verify_request_proof(proof: str, resolve_key: Callable[[Optional[str]], Optional[dict]], htm: str, htu: str, body_hash_value: str, now: datetime | float | int | None = None, max_skew: int = 300, max_age: int = 300, seen_jti: Optional[Callable[[str, int], bool]] = None) -> dict:
    """DPoP-style request proof: method, normalised URL, body hash, freshness and replay."""
    d = decode_jwt(proof)
    if not d: return {"ok": False, "reason": "malformed"}
    header, c = d
    if header.get("typ") != PROOF_TYP: return {"ok": False, "reason": "typ"}
    if header.get("alg") not in ("ES256", "EdDSA"): return {"ok": False, "reason": "alg"}
    kid = header.get("kid") if isinstance(header.get("kid"), str) else None
    jwk = resolve_key(kid)
    if not jwk: return {"ok": False, "reason": "unknown_key", "kid": kid}
    if alg_for_jwk(jwk) != header["alg"]: return {"ok": False, "reason": "alg_mismatch", "kid": kid}
    parts = proof.split(".")
    if not _verify_signature(header["alg"], jwk, f"{parts[0]}.{parts[1]}".encode(), b64url_decode(parts[2])): return {"ok": False, "reason": "signature", "kid": kid}
    for k, t in (("iss", str), ("htm", str), ("htu", str), ("jti", str), ("rh", str)):
        if not isinstance(c.get(k), t): return {"ok": False, "reason": "claims", "kid": kid}
    if not isinstance(c.get("iat"), (int, float)) or not isinstance(c.get("exp"), (int, float)): return {"ok": False, "reason": "claims", "kid": kid}
    if c["htm"].upper() != htm.upper(): return {"ok": False, "reason": "htm", "kid": kid}
    if normalize_htu(c["htu"]) != normalize_htu(htu): return {"ok": False, "reason": "htu", "kid": kid}
    if c["rh"] != body_hash_value: return {"ok": False, "reason": "body_hash", "kid": kid}
    t = _ts(now)
    if c["iat"] > t + max_skew: return {"ok": False, "reason": "iat_future", "kid": kid}
    if c["exp"] <= t: return {"ok": False, "reason": "expired", "kid": kid}
    if t - c["iat"] > max_age: return {"ok": False, "reason": "too_old", "kid": kid}
    if seen_jti and seen_jti(c["jti"], int(c["exp"])): return {"ok": False, "reason": "replay", "kid": kid}
    return {"ok": True, "kid": kid, "alg": header["alg"], "claims": c}


def jwks_resolver(jwks_by_issuer: dict[str, Any]) -> KeyResolver:
    """{ iss: { "keys": [jwk...] } | { kid: jwk } } → resolver."""
    def resolve(kid: str, iss: str) -> Optional[dict]:
        entry = jwks_by_issuer.get(iss)
        if not entry: return None
        if isinstance(entry, dict) and "keys" in entry: return next((k for k in entry["keys"] if k.get("kid") == kid), None)
        return entry.get(kid) if isinstance(entry, dict) else None
    return resolve
