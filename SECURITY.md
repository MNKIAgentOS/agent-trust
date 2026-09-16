# Security policy

Report vulnerabilities to **security@mnki.com**. We acknowledge within 2 business days, keep you informed,
and credit reporters who wish it. Please do not test against production systems you do not own; a staging
environment is available to design partners on request.

Scope: the Agent Trust console and API (`mnki.com`), the open-source verifier, SDKs, CLI and conformance
suite (`MNKIAgentOS/agent-trust`). Out of scope: denial of service, social engineering, findings on
third-party services.

Cryptography: the profile defines no new primitives — JWS with ES256/EdDSA, SHA-256, JCS canonicalization,
AES-GCM at rest for stored credentials and organization private keys. Keys never leave the process that
generated them (SDK) or the encrypted store (console).

## Disclosure process

1. Email security@mnki.com (PGP on request). Include the package or endpoint, a reproduction and the impact.
2. We acknowledge within 2 business days and share a fix or mitigation timeline within 10; critical issues
   in the hosted service are patched before disclosure, package fixes ship as a patch release.
3. Coordinated disclosure after the fix is available; we credit reporters in the release notes unless asked not to.

## Supply chain

Because these packages sit in the action path of agents, every release is verifiable:

- npm packages are published through **trusted publishing** (OIDC): the workflow proves its identity to npm,
  which mints a short-lived token and attaches a **provenance** attestation linked to the tag and workflow — no
  long-lived npm token exists;
- PyPI `mnki` is published through **trusted publishing** with attestations, never a long-lived token;
- each release attaches a **CycloneDX SBOM** per package and a `SHA256SUMS` file signed keyless with
  **cosign** (`SHA256SUMS.sig` + certificate) — verify with
  `cosign verify-blob --certificate SHA256SUMS.pem --signature SHA256SUMS.sig --certificate-identity-regexp github.com/MNKIAgentOS --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS`;
- the container image `ghcr.io/mnkiagentos/mnki-mcp` is built with provenance and SBOM and signed with cosign;
- releases run in a protected `release` environment restricted to `v*` tags and gated on a maintainer's approval;
  publishing identity comes from that environment, not from a credential anyone can copy;
- dependency review, `npm audit`, `pip-audit` and `govulncheck` run on every change and weekly; GitHub secret
  scanning with push protection is enabled;
- builds are reproducible from the tag with pinned toolchains (`npm ci`, `tsc`); the CLI, SDK and proxy have
  no runtime dependencies beyond WebCrypto and the platform.

Telemetry in the CLI, SDK and proxy is opt-in, anonymous and allow-listed (`MNKI_TELEMETRY=0` disables it);
it never carries tool arguments, agent names or URLs.
