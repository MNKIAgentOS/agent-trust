"""
Agent identity: a P-256 (ES256) or Ed25519 (EdDSA) key whose private half never leaves the process, and the
`ExportedIdentity` JSON shared with the TypeScript SDK ({ v: 1, agentId, kid, alg, publicJwk, privateJwk }).
Needs `pip install cryptography` (extra: mnki[signing]).
"""
from __future__ import annotations
import base64, hashlib, json, os, stat, time
from pathlib import Path
from typing import Any, Optional


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def body_hash(body: bytes | str) -> str:
    return b64url(hashlib.sha256(body.encode() if isinstance(body, str) else body).digest())


def _crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519
        from cryptography.hazmat.primitives import hashes, serialization
        return ec, ed25519, hashes, serialization
    except ImportError as e:  # pragma: no cover
        raise ImportError("Signing needs `pip install cryptography` (or `pip install mnki[signing]`)") from e


class AgentIdentity:
    """A local agent key (ES256 or EdDSA). The private key never leaves the process."""
    def __init__(self, agent_id: str, kid: str, private_key: Any, public_jwk: dict, alg: str = "ES256"):
        self.agent_id, self.kid, self._key, self.public_jwk, self.alg = agent_id, kid, private_key, public_jwk, alg

    @staticmethod
    def create(agent_id: str, kid: Optional[str] = None, alg: str = "ES256") -> "AgentIdentity":
        ec, ed25519, _h, _s = _crypto()
        if alg == "EdDSA":
            key = ed25519.Ed25519PrivateKey.generate()
            from cryptography.hazmat.primitives import serialization
            raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64url(raw)}
        elif alg == "ES256":
            key = ec.generate_private_key(ec.SECP256R1())
            nums = key.public_key().public_numbers()
            jwk = {"kty": "EC", "crv": "P-256", "x": b64url(nums.x.to_bytes(32, "big")), "y": b64url(nums.y.to_bytes(32, "big"))}
        else:
            raise ValueError("alg must be ES256 or EdDSA")
        return AgentIdentity(agent_id, kid or f"kid-{int(time.time()):x}", key, jwk, alg)

    # --- JWS ---
    def sign(self, signing_input: str) -> str:
        """Raw JWS signature (base64url r||s for ES256, raw for EdDSA) over the signing input."""
        ec, _e, hashes, _s = _crypto()
        if self.alg == "EdDSA":
            return b64url(self._key.sign(signing_input.encode()))
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        der = self._key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    def sign_jwt(self, typ: str, payload: dict) -> str:
        header = {"alg": self.alg, "typ": typ, "kid": self.kid}
        signing_input = f"{b64url(json.dumps(header, separators=(',', ':')).encode())}.{b64url(json.dumps(payload, separators=(',', ':')).encode())}"
        return f"{signing_input}.{self.sign(signing_input)}"

    def sign_proof(self, method: str, url: str, body: bytes | str, ttl: int = 60) -> str:
        """Agent-Proof (DPoP-style): binds method, URL (no query), body hash, a fresh jti and a short lifetime."""
        from urllib.parse import urlsplit
        u = urlsplit(url); htu = f"{u.scheme.lower()}://{u.netloc.lower()}{u.path}"
        now = int(time.time())
        payload = {"iss": self.agent_id, "htm": method.upper(), "htu": htu, "iat": now, "exp": now + ttl, "jti": b64url(os.urandom(16)), "rh": body_hash(body)}
        return self.sign_jwt("agent-trust-proof+jwt", payload)

    # --- persistence (same file format as the TypeScript SDK) ---
    def export(self) -> dict:
        _ec, _e, _h, serialization = _crypto()
        if self.alg == "EdDSA":
            d = self._key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            private_jwk = {**self.public_jwk, "d": b64url(d)}
        else:
            d = self._key.private_numbers().private_value.to_bytes(32, "big")
            private_jwk = {**self.public_jwk, "d": b64url(d)}
        return {"v": 1, "agentId": self.agent_id, "kid": self.kid, "alg": self.alg, "publicJwk": self.public_jwk, "privateJwk": private_jwk}

    @staticmethod
    def import_(e: dict) -> "AgentIdentity":
        ec, ed25519, _h, _s = _crypto()
        priv = e["privateJwk"]; alg = e.get("alg", "ES256")
        if alg == "EdDSA":
            key = ed25519.Ed25519PrivateKey.from_private_bytes(b64url_decode(priv["d"]))
        else:
            d = int.from_bytes(b64url_decode(priv["d"]), "big")
            x = int.from_bytes(b64url_decode(priv["x"]), "big"); y = int.from_bytes(b64url_decode(priv["y"]), "big")
            key = ec.EllipticCurvePrivateNumbers(d, ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())).private_key()
        return AgentIdentity(e["agentId"], e["kid"], key, e["publicJwk"], alg)

    def save(self, path: str | os.PathLike | None = None) -> Path:
        p = Path(path or default_identity_path()); p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.export(), indent=2))
        try: p.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError: pass
        return p

    @staticmethod
    def load(path: str | os.PathLike | None = None) -> Optional["AgentIdentity"]:
        """From MNKI_IDENTITY (base64 or JSON), else the file (default ~/.mnki/identity.json)."""
        env = os.environ.get("MNKI_IDENTITY")
        if env:
            raw = env if env.lstrip().startswith("{") else base64.b64decode(env).decode()
            return AgentIdentity.import_(json.loads(raw))
        p = Path(path or default_identity_path())
        return AgentIdentity.import_(json.loads(p.read_text())) if p.exists() else None


def default_identity_path() -> Path:
    home = os.environ.get("MNKI_HOME") or os.path.join(os.path.expanduser("~"), ".mnki")
    return Path(home) / "identity.json"

