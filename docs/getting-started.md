# mnki in five minutes

mnki gives an AI agent an identity, bounded authority and proof of every consequential action. Start
with no account; connect a console when you want approvals, a ledger and a fleet view.

## 0. See it (15 seconds, no account)

```bash
npx mnki-cli demo
```

An invoice agent may refund up to €5,000: **€47,000 is denied** with the evidence list, **€420 is
allowed**, **€3,200 needs a human**. That is the whole product.

## 1. Guard a tool call (local mode)

```bash
npm install mnki-sdk        # or: pip install mnki
npm install -g mnki-cli     # optional: the `mnki` command on your PATH
npx mnki-cli init           # identity + a local world + a starter policy in ~/.mnki, nothing leaves the machine
```

```ts
import { createGuard, demoWorld } from "mnki-sdk";

const guard = createGuard({ world: demoWorld(), agent: "invoice-agent", actionPrefix: "", mode: "observe" });
const refund = guard.wrap("refund.create", async (a: { customer_id: string; amount: number; currency: string }) => pay(a));

await refund({ customer_id: "customer:4711", amount: 420, currency: "EUR" });    // runs
await refund({ customer_id: "customer:4711", amount: 47000, currency: "EUR" });  // observe: runs, records "would_deny"; enforce: throws Denied with evidence
```

Modes: `observe` (log only) → `warn` → `require_approval` → `enforce`. Start in observe, read the
shadow log, then enforce. `mnki verify --local --agent invoice-agent --action refund.create --amount 47000 --currency EUR`
prints the evidence; `mnki policy explain --last` answers which rule, which delegation, which condition,
and what would change the outcome. `mnki policy test policy.json --cases cases.json` checks a policy.

## 2. Protect the MCP servers you already run

```bash
npx mnki-cli scan                                   # every MCP server and credential an agent can use on this machine
npx mnki-cli protect --client cursor --server github --agent my-agent            # dry run: shows the config diff
npx mnki-cli protect --client cursor --server github --agent my-agent --apply    # observe mode by default
```

`mnki-mcp` sits between the client and the server and verifies every `tools/call`. `mnki protect report`
summarises what would have been denied; `--mode enforce` when you are ready; `mnki protect rollback` undoes it.

## 3. Connect a console (free organisation)

```bash
npx mnki-cli init --url https://mnki.com --key at_verify_…    # Settings → API keys in the console
npx mnki-cli identity create --name invoice-agent --risk medium
npx mnki-cli delegate --issuer principal:<your principal id> --to <agent id> \
  --cap "refund.create=customer:*;max_value=5000;currency=EUR" --expires 30d
```

```ts
import { createGuard } from "mnki-sdk";
import { loadIdentity } from "mnki-sdk/identity-store";

const guard = createGuard({ client: { baseUrl: "https://mnki.com", apiKey: process.env.MNKI_API_KEY! }, agent: "invoice-agent", identity: await loadIdentity() });
await guard.check("refund.create", { customer_id: "customer:4711", amount: 3200, currency: "EUR" });
// REQUIRE_APPROVAL → the guard waits; the approver gets a push, confirms with Face ID, the decision is signed and recorded
```

```python
from mnki import AgentTrustClient, Guard
g = Guard(AgentTrustClient("https://mnki.com", api_key=os.environ["MNKI_API_KEY"]), agent="invoice-agent")

@g.wrap("refund.create")
def refund(customer_id: str, amount: float, currency: str = "EUR"): ...
```

## 4. Your framework

Adapters are subpaths of the same packages; the framework itself is never imported by mnki.

```ts
import { guardTools } from "mnki-sdk/openai-agents";      // new Agent({ tools: guardTools(guard, [refund]) })
import { guardTools } from "mnki-sdk/langchain";           // new ToolNode(guardTools(guard, [refund]))
import { preToolUse } from "mnki-sdk/claude-agent-sdk";    // hooks: { PreToolUse: [{ hooks: [preToolUse(guard)] }] }
import { guardTools } from "mnki-sdk/ai";                  // generateText({ tools: guardTools(guard, { refund }) })
```

```python
from mnki.adapters.openai_agents import guard_tools   # Agent(tools=guard_tools(g, [refund]))
from mnki.adapters.langchain import guard_tools       # create_react_agent(model, guard_tools(g, [refund]))
from mnki.adapters.crewai import guard_tools          # Agent(tools=guard_tools(g, [refund_tool]))
from mnki.adapters.pydantic_ai import guard_tool      # @agent.tool_plain  @guard_tool(g)  def refund(...): ...
```

A refused call comes back to the model as `{ "error": "denied", "reasons": [...], "evidence": [...] }` so it
can explain itself; pass `onRefused: "throw"` / `on_refused="throw"` to abort instead. Python has the same
local mode: `Guard(world=demo_world(), agent="invoice-agent", action_prefix="")`.

Every decision carries the ✓/⚠/✕ evidence list, lands in a tamper-evident ledger, and can be presented to
other services as a signed attestation. Which frameworks and versions are covered, and how far each claim
goes, is in `docs/compatibility.md` (`/docs/compatibility`).

Read the profile (`/docs/profile`), the API (`/docs/api`) and the conformance levels (`/docs/conformance`).
