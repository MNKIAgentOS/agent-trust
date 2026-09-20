# Access broker

Agents request capabilities, not credentials. A **connection** is an external system your organisation holds a
credential for: a Stripe account, a GitHub organisation, a Slack workspace, a Google or Microsoft 365 account, an
AWS role, or any HTTP API. An **agent permission** is a delegation that says which agent may run which operations on
which connection, within what limits. A **grant** is the single-use permit the broker mints when an agent asks to
run one operation: the request is verified with the connection as its audience, the permit is consumed before the
effect, the broker performs the call with the stored credential, and the grant records what happened. The agent never
sees the credential. Profile §17 defines the objects; this page is how you use them.

| You want to… | Do this |
| --- | --- |
| Let an agent refund on Stripe without giving it a key | Console → **Access** → Connect Stripe with a restricted key → Grant access → `POST /v1/grants/execute` |
| Use any connection from an MCP client | Point the client at `/api/gateway/access/<connection id>/mcp` |
| Let an agent ask for access it lacks | `POST /v1/access-requests`; approve in the console; the agent retries |
| Hand an agent short-lived AWS credentials | Connect AWS with an IAM key pair; `sts.assume_role` returns them as a `native_token` grant |

## Connect a system

Console → **Access** → **Connect a system**. Pick the provider, name the connection, then either sign in with the
provider (OAuth: GitHub, Google, Slack, Microsoft) or paste an API key (Stripe, GitHub, any HTTP API) or an IAM
access-key pair (AWS). The secret is encrypted at rest with the deployment's `TOOL_ENC_KEY` and read only by the
broker at execution time; no endpoint, event or log ever carries it.

Every provider ships an **operation catalogue**: the operations agents may ask for, each with a parameter schema
(allow-listed keys, types, patterns, bounds), an HTTP method and a risk level. Enable only what you need; disabled
operations cannot be granted. **Restrictions** cap every grant on the connection whatever the agent's delegation
says: an amount cap shows up in the evidence as a policy rule (`connection:<id>:<op>:max_value`), currency and
region are refused before verification.

| Provider | Auth | Operations (release one) |
| --- | --- | --- |
| Stripe | API key | `refund.create`, `charge.get`, `payment_intent.get`, `customer.get`, `invoice.list`, `balance.get` (probe) |
| GitHub | OAuth or token | `issue.create`, `issue.comment.create`, `pull.list`, `repo.get`, `user.get` (probe); owner allow-list |
| Slack | OAuth | `chat.postMessage`, `conversations.list`, `auth.test` (probe) |
| Google | OAuth | `gmail.send`, `calendar.event.create`, `userinfo.get` (probe) |
| Microsoft 365 | OAuth | `mail.send`, `calendar.event.create`, `me.get` (probe) |
| AWS | IAM key pair | `sts.assume_role` (short-lived credentials, 15-minute minimum, recorded as `native_token`), `request` (SigV4-signed call to an allow-listed service) |
| HTTP API | API key | Operations you declare per connection (id, method, path with `{param}` placeholders, parameter schema, risk); public https only, no IP literals, redirects refused |

`POST /v1/connections/{id}/test` runs the provider's read probe with the stored credential and marks the connection
`active` or `needs_reconnect`. Disconnecting destroys the credential, disables the connection and revokes every
unexecuted grant; the ledger keeps the history.

## Grant access

Agents get access the way they get any authority: a delegation. Console → Access → **Grant access** issues one from
the agent's owner principal with capabilities in the broker vocabulary, action `<provider>:<operation>` on resource
`<provider>:<connection id>/*`, and constraints clamped to the connection's restrictions. From the CLI:

```bash
mnki delegate --issuer principal:<id> --to <agent> --cap "stripe:refund.create=stripe:con_…/*;max_value=500;currency=EUR" --expires 30d
```

A time-boxed delegation sits **beside** the agent's existing chain, not on top of it: the verifier selects, among the
agent's active delegations, the one whose authority covers the action and resource (§17.3), so granting a week of
Stripe access does not shadow the agent's other permissions and the grant expiring does not break them.

## Execute

```bash
curl -X POST https://mnki.com/api/v1/grants/execute \
  -H "authorization: Bearer $MNKI_API_KEY" -H "content-type: application/json" \
  -d '{ "agent": "invoice-agent", "connection": "con_…", "operation": "refund.create",
        "params": { "charge": "ch_1…", "amount": 42000, "currency": "EUR" } }'
```

```ts
import { AgentTrustClient } from "mnki-sdk";
const client = new AgentTrustClient({ baseUrl: "https://mnki.com", apiKey: process.env.MNKI_API_KEY! });
const r = await client.grants.run({ agent: "invoice-agent", connection: "con_…", operation: "refund.create", params: { charge: "ch_1…", amount: 42000, currency: "EUR" } });
// r.grant.status === "executed"; r.result.body is the projected, redacted Stripe response; r.decision carries the evidence
```

```python
from mnki import AgentTrustClient, Guard
g = Guard(AgentTrustClient("https://mnki.com", api_key=os.environ["MNKI_API_KEY"]), agent="invoice-agent")
r = g.access("con_…", "refund.create", {"charge": "ch_1…", "amount": 42000, "currency": "EUR"})
```

What happens, in order: platform switch and configuration → plan and quota → rate limits → operation resolved and
parameters validated → connection restrictions → verification with the connection as audience (`aud`) and the
restriction rules as policy → a single-use permit minted and consumed → the call, with an idempotency key where the
provider supports one → the grant marked `executed` or `failed` → `grant.issued` and `grant.executed` in the
ledger. Responses:

| Status | Body | Meaning |
| --- | --- | --- |
| 200 | `{ grant, decision, result }` | Done. `result.body` is projected to the fields an agent needs and redacted of anything secret-shaped; the grant keeps its hash. |
| 202 | `{ decision, approval_id, poll_url, resume }` | A person must approve. Poll `poll_url`, then resend with `approval_id`; the approval executes exactly once and only for the same parameters. |
| 403 | `{ error: "denied", decision, access_request_hint? }` | Denied with reasons and the failing evidence. `capability_missing` comes with a hint to ask for access. |
| 409 | `approval_already_used`, `grant_already_executed`, `approval_mismatch`, `permit_already_used` | Replays and bent approvals. |
| 402 | `plan_feature_required`, `plan_limit_reached` | Plan or verification quota. |
| 502 | `{ grant: { status: "failed" }, result: { error } }` | The upstream call failed (timeout, redirect, oversized body, provider error); nothing is retried without a new grant. |
| 503 | `feature_disabled`, `broker_unconfigured` | Broker switched off by the operator, or `TOOL_ENC_KEY` not set. |

Headers `agent-trust-decision`, `agent-trust-request` and `agent-trust-grant` name the decision, the request and the
grant. Send `Agent-Proof` to sign the request and `Agent-Attestation` to present a permit you minted earlier.

**Mint without executing.** `POST /v1/grants` with the same body returns the permit (a single-use attestation with
`aud` = the connection and `atp.grant` = the operation and a hash of the parameters) instead of running the call;
present it later as `attestation`. A permit for connection A is refused at connection B
(`attestation_invalid:audience`); a permit for other parameters is refused (`attestation_invalid:request_hash`);
a permit presented twice is refused (`attestation_invalid:consumed`). For `sts.assume_role` the exchange happens at
mint time and the short-lived credential is the result.

## A connection as an MCP server

Every connection is also a Streamable-HTTP MCP server at `https://mnki.com/api/gateway/access/<connection id>/mcp`:
`tools/list` is the enabled operations with their parameter schemas, every `tools/call` runs the execution path above.

```json
{ "mcpServers": { "stripe": { "url": "https://mnki.com/api/gateway/access/con_…/mcp",
  "headers": { "Authorization": "Bearer at_verify_…", "Agent-Id": "invoice-agent" } } } }
```

JSON-RPC errors: `-32001` approval required (resend with `params.approval_id`), `-32003` denied, `-32004`
unavailable, `-32005` quota. No upstream MCP server is involved: the broker answers itself.

## Ask for access

When an agent is denied for a missing capability it can ask a person:

```bash
curl -X POST https://mnki.com/api/v1/access-requests -H "authorization: Bearer $MNKI_API_KEY" -H "content-type: application/json" \
  -d '{ "agent": "invoice-agent", "connection": "con_…", "operations": ["customer.get"], "duration_seconds": 3600, "reason": "Refund investigation for ticket 4711" }'
```

Owners and admins get a push and an email; Console → Access → **Requests** approves for a limited time (shorter or
narrower than asked, if they like) or denies with a reason. Approval issues a time-boxed delegation from the agent's
owner; the agent polls `GET /v1/access-requests/{id}` and then requests grants normally. Pending requests expire
after 72 hours; the delegation is swept when its window closes (`delegation.expired`).

## What the ledger holds

`connection.created|updated|credential.set|connected|tested|disconnected`, `grant.issued|executed|failed|refused|revoked`,
`access_request.created|approved|denied|cancelled`, `access.permission_granted`, `delegation.expired`. Grants keep the
decision, the approval, the permit's `jti`, the upstream status and request id, a hash of the body handed to the agent
and the latency. Bodies and credentials are never stored.

## Plans

Every plan includes connections (Free 1, Individual 3, Team 25, Enterprise unlimited with vault credential providers
and signing); above the included count you buy connections one at a time as an add-on, next to SSO. Kill switch
`broker` in the admin portal stops every grant platform-wide; `/api/health` reports `access_broker: ready` when
`TOOL_ENC_KEY` is set.
