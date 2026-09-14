# Security policy

Report vulnerabilities to **security@mnki.com**. We acknowledge within 2 business days, keep you informed,
and credit reporters who wish it. Please do not test against production systems you do not own; a staging
environment is available to design partners on request.

Scope: the Agent Trust console and API (`mnki.com`), the open-source verifier, SDKs, CLI and conformance
suite (`MNKIHealth/agent-trust`). Out of scope: denial of service, social engineering, findings on
third-party services.

Cryptography: the profile defines no new primitives — JWS with ES256/EdDSA, SHA-256, JCS canonicalization,
AES-GCM at rest for stored credentials and organization private keys. Keys never leave the process that
generated them (SDK) or the encrypted store (console).
