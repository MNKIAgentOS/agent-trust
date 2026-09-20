# mnki en cinco minutos

mnki da a un agente de IA una identidad, una autoridad acotada y prueba de cada acción relevante. Empiece
sin cuenta; conecte una consola cuando quiera aprobaciones, un libro de registro y una vista de la flota.

## 0. Véalo (15 segundos, sin cuenta)

```bash
npx mnki-cli demo
```

Un agente de facturación puede reembolsar hasta €5,000: **€47,000 se deniegan** con la lista de evidencia, **€420 se
permiten**, **€3,200 necesitan a una persona**. Ese es todo el producto.

## 1. Proteja una llamada a una herramienta (modo local)

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

Modos: `observe` (solo registra) → `warn` → `require_approval` → `enforce`. Empiece en modo observación, lea el
registro sombra y después aplique. `mnki verify --local --agent invoice-agent --action refund.create --amount 47000 --currency EUR`
imprime la evidencia; `mnki policy explain --last` responde qué regla, qué delegación, qué condición,
y qué cambiaría el resultado. `mnki policy test policy.json --cases cases.json` comprueba una política.

## 2. Proteja los servidores MCP que ya ejecuta

```bash
npx mnki-cli scan                                   # every MCP server and credential an agent can use on this machine
npx mnki-cli protect --client cursor --server github --agent my-agent            # dry run: shows the config diff
npx mnki-cli protect --client cursor --server github --agent my-agent --apply    # observe mode by default
```

`mnki-mcp` se sitúa entre el cliente y el servidor y verifica cada `tools/call`. `mnki protect report`
resume lo que se habría denegado; `--mode enforce` cuando esté listo; `mnki protect rollback` lo deshace.

## 3. Conecte una consola (organización gratuita)

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

### Deje que el agente actúe sin clave

Conecte Stripe en Consola → **Acceso** con una clave restringida, conceda al agente `refund.create` hasta 500 € y deje
que el bróker haga la llamada: el agente pide una operación, recibe una concesión de un solo uso y nunca ve la
credencial.

```ts
const r = await client.grants.run({ agent: "invoice-agent", connection: "con_…", operation: "refund.create", params: { charge: "ch_1…", amount: 42000, currency: "EUR" } });
```

¿Denegado por falta de capacidad? `mnki access request --agent invoice-agent --connection con_… --op customer.get --for 1h --reason "…"`
se lo pide a una persona, que lo aprueba por una hora desde la consola. Guía completa: [Bróker de acceso](/es/docs/access-broker).

## 4. Su framework

Los adaptadores son subrutas de los mismos paquetes; mnki nunca importa el framework en sí.

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

Una llamada rechazada vuelve al modelo como `{ "error": "denied", "reasons": [...], "evidence": [...] }` para que
pueda explicarse; pase `onRefused: "throw"` / `on_refused="throw"` para abortar en su lugar. Python tiene el mismo
modo local: `Guard(world=demo_world(), agent="invoice-agent", action_prefix="")`.

Cada decisión lleva la lista de evidencia ✓/⚠/✕, queda en un libro de registro a prueba de manipulaciones y puede presentarse a
otros servicios como una atestación firmada. Qué frameworks y versiones están cubiertos, y hasta dónde llega cada
afirmación, está en `docs/compatibility.md` (`/es/docs/compatibility`).

Lea el perfil (`/es/docs/profile`), la API (`/es/docs/api`) y los niveles de conformidad (`/es/docs/conformance`).
