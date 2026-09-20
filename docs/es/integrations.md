# Integraciones

Cada vía de entrada a Agent Trust en tres líneas o menos. Elija la fila que corresponda a lo que ya ejecuta; cada
sección es completa por sí sola. `mnki` es la marca para desarrolladores: en npm `mnki-cli`, `mnki-sdk`, `mnki-mcp`,
`mnki-verifier`; en PyPI `mnki`; contenedor `ghcr.io/mnkiagentos/mnki-mcp`.

| Usted tiene… | Empiece aquí | Qué obtiene |
| --- | --- | --- |
| Nada todavía | `npx mnki-cli demo` | La historia del reembolso de €47,000: DENY con evidencia, ALLOW, REQUIRE_APPROVAL. Sin cuenta. |
| Servidores MCP en Claude Desktop, Claude Code, Cursor, Windsurf o VS Code | `npx mnki-cli scan` y después `mnki protect` | Cada `tools/call` verificado; primero en modo observación, aplique cuando esté listo. |
| Un agente escrito en TypeScript o Python | `npm i mnki-sdk` / `pip install mnki` | `guard.wrap(tool)` en modo local y, después, una consola para aprobaciones y el libro de registro. |
| OpenAI Agents, LangChain, Claude Agent SDK, Vercel AI, CrewAI, Pydantic AI | la subruta del adaptador | Una línea por framework; mnki nunca importa el framework. |
| Un servidor MCP remoto (HTTP) | Consola → Integraciones → Pasarela MCP | URL de proxy alojado, sin instalar nada. |
| Cualquier otra cosa que hable HTTP | `POST /v1/verify` | La misma decisión, evidencia y libro de registro desde cualquier lenguaje. |
| Un requisito de "no depender de un proveedor" | `mnki-verifier` / `at-verify` (Go) | Verificación sin conexión de cadenas y atestaciones contra los vectores públicos. |

## Clientes MCP

`mnki-mcp` es un proxy local: habla stdio con el cliente, lanza o se conecta al servidor real que hay detrás
y verifica cada `tools/call` con la lista de evidencia. `mnki protect` edita la configuración del cliente por usted
(primero el diff, `--apply` para escribir, se conserva una copia de seguridad, `mnki protect rollback` para deshacer). Los bloques siguientes son lo que
escribe, por si prefiere pegarlos usted mismo. Cada ejemplo necesita una clave de API de la consola con el ámbito `verify`
(Configuración → Claves de API), colocada en `MNKI_API_KEY`; el id del agente es la identidad bajo la que se ejecutan las llamadas.

### Claude Desktop

Con un clic: descargue `mnki-mcp.mcpb` desde la [última versión publicada](https://github.com/MNKIAgentOS/agent-trust/releases/latest),
haga doble clic en el archivo y rellene en el diálogo el comando del servidor de origen, el id del agente y la clave de API.
Claude Desktop guarda la clave en su llavero.

O edite `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) / `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "mnki-mcp", "--agent", "desktop-assistant", "--server", "github", "--mode", "observe",
               "--upstream", "--", "npx", "-y", "@modelcontextprotocol/server-github"],
      "env": { "MNKI_API_KEY": "at_verify_…", "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_…" }
    }
  }
}
```

```bash
npx mnki-cli protect --client claude-desktop --server github --agent desktop-assistant --apply
```

### Claude Code

```bash
claude mcp add github -e MNKI_API_KEY=at_verify_… -- npx -y mnki-mcp --agent claude-code --server github --upstream -- npx -y @modelcontextprotocol/server-github
```

o `npx mnki-cli protect --client claude-code --server github --agent claude-code --apply`, que reescribe
la entrada en `~/.claude.json` o en el `.mcp.json` del proyecto. El Claude Agent SDK (Claude Code programático)
usa en su lugar el adaptador de hooks; véase más abajo.

### Cursor

`~/.cursor/mcp.json` (global) o `<project>/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "mnki-mcp", "--agent", "cursor", "--server", "github", "--upstream", "--", "npx", "-y", "@modelcontextprotocol/server-github"],
      "env": { "MNKI_API_KEY": "at_verify_…" }
    }
  }
}
```

`npx mnki-cli protect --client cursor --server github --agent cursor --apply` hace lo mismo. Los enlaces profundos
"Add to Cursor" de Cursor (`cursor://anysphere.cursor-deeplink/mcp/install?name=…&config=<base64 JSON>`)
llevan exactamente este JSON, de modo que un equipo puede distribuir un único enlace.

### Windsurf

`~/.codeium/windsurf/mcp_config.json`, con la misma forma `mcpServers` que Cursor; `--client windsurf` en `mnki protect`.

### VS Code (modo agente de Copilot)

`<project>/.vscode/mcp.json`:

```json
{
  "servers": {
    "github": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "mnki-mcp", "--agent", "vscode", "--server", "github", "--upstream", "--", "npx", "-y", "@modelcontextprotocol/server-github"],
      "env": { "MNKI_API_KEY": "${input:mnki-key}" }
    }
  },
  "inputs": [{ "id": "mnki-key", "type": "promptString", "password": true, "description": "Agent Trust API key" }]
}
```

`npx mnki-cli protect --client vscode --server github --agent vscode --apply`.

### Cualquier otro cliente MCP, o un servidor remoto

Origen por stdio: `npx -y mnki-mcp --agent <id> --server <name> --upstream -- <command> [args…]`.
Origen por HTTP (Streamable HTTP): `npx -y mnki-mcp --agent <id> --server <name> --upstream-url https://… --upstream-header "Authorization=Bearer …"`.
Contenedor: `docker run -i ghcr.io/mnkiagentos/mnki-mcp --agent <id> --upstream-url https://…` con `MNKI_API_KEY` en el entorno.

Modos: `observe` (predeterminado: todo se ejecuta, lo que se denegaría se registra en `~/.mnki/shadow/<server>.ndjson`), `warn`,
`require_approval` (solo lo que la política escala espera a una persona), `enforce`. `mnki protect report` lee el
registro sombra y enumera las delegaciones y capacidades que conviene conceder antes de pasar un servidor a `enforce`.
Las denegaciones llegan al cliente como el error JSON-RPC `-32003` con la evidencia; una aprobación que expiró es `-32001`;
`-32005` es la cuota de verificación del plan.

### Pasarela MCP alojada (sin proxy local)

Consola → Integraciones → **Pasarela MCP** → la URL de origen y su encabezado de autenticación. La consola responde con una
URL de pasarela; el cliente la llama con una clave de API de Agent Trust en el encabezado `Authorization`. La misma verificación,
el mismo libro de registro, sin instalar nada. Cualquier cliente que pueda enviar un encabezado funciona hoy, por ejemplo la
herramienta `mcp` alojada de la Responses API de OpenAI:

```python
from openai import OpenAI
client = OpenAI()
resp = client.responses.create(
    model="gpt-5",
    tools=[{ "type": "mcp", "server_label": "github-via-agent-trust",
             "server_url": "https://mnki.com/api/gateway/mcp/<integration id>",
             "headers": { "Authorization": f"Bearer {os.environ['MNKI_API_KEY']}" },
             "require_approval": "never" }],
    input="Open a pull request that bumps the dependency.",
)
```

Como la pasarela custodia la credencial del servidor y el agente nunca la tiene, sus decisiones registran la
ruta del efecto como **custodia** (perfil §15): la evidencia muestra que no se pudo llamar al servidor
esquivando la comprobación. El proxy local declara `none`, con honestidad, porque comparte máquina con el
proceso del agente.

El directorio de conectores de ChatGPT, los conectores de Claude y Smithery exigen inicio de sesión OAuth en el servidor en lugar de
un encabezado; está previsto para la pasarela y se anunciará aquí.

## Bróker de acceso: una conexión como servidor MCP

Consola → **Acceso** → conecte Stripe, GitHub, Google, Slack, Microsoft, AWS o cualquier API HTTP una sola vez. Cada
conexión es entonces un servidor MCP en `https://mnki.com/api/gateway/access/<id de conexión>/mcp`: `tools/list` son
las operaciones que activó y cada `tools/call` se verifica con la conexión como audiencia, se concede una vez y lo
ejecuta el bróker con la credencial guardada. El agente nunca tiene una clave. La misma ruta es
`POST /v1/grants/execute` para cualquier cosa que hable HTTP, `client.grants.run(...)` en los SDK y
`mnki access run …` en la CLI. Guía completa: [Bróker de acceso](/es/docs/access-broker).

```json
{ "mcpServers": { "stripe": { "url": "https://mnki.com/api/gateway/access/con_…/mcp",
  "headers": { "Authorization": "Bearer at_verify_…", "Agent-Id": "invoice-agent" } } } }
```

## Frameworks

Los adaptadores son subrutas de `mnki-sdk` y módulos de `mnki`; el adaptador nunca importa el framework en sí,
de modo que sus actualizaciones no pueden romper el guard. Una llamada rechazada devuelve
`{ "error": "denied", "reasons": [...], "evidence": [...] }` al modelo, salvo que pase `onRefused: "throw"`.
Versiones fijadas y niveles de compatibilidad: [compatibilidad](/es/docs/compatibility).

```ts
import { createGuard } from "mnki-sdk";
const guard = createGuard({ client: { baseUrl: "https://mnki.com", apiKey: process.env.MNKI_API_KEY! }, agent: "invoice-agent" });

import { guardTools } from "mnki-sdk/openai-agents";      // new Agent({ tools: guardTools(guard, [refund]) })
import { guardTools } from "mnki-sdk/langchain";           // new ToolNode(guardTools(guard, [refund]))
import { preToolUse } from "mnki-sdk/claude-agent-sdk";    // query({ hooks: { PreToolUse: [{ hooks: [preToolUse(guard)] }] } })
import { guardTools } from "mnki-sdk/ai";                  // generateText({ tools: guardTools(guard, { refund }) })
import { signTaskRequest, verifyBeforeAccept } from "mnki-sdk/a2a";   // agent-to-agent: sign outgoing tasks, verify incoming ones
```

```python
from mnki import AgentTrustClient, Guard
g = Guard(AgentTrustClient("https://mnki.com", api_key=os.environ["MNKI_API_KEY"]), agent="invoice-agent")

from mnki.adapters.openai_agents import guard_tools   # Agent(tools=guard_tools(g, [refund]))
from mnki.adapters.langchain import guard_tools       # create_react_agent(model, guard_tools(g, [refund]))
from langchain_mnki import guard_tools                # the same, as the `pip install langchain-mnki` partner package
from mnki.adapters.crewai import guard_tools          # Agent(tools=guard_tools(g, [refund_tool]))
from mnki.adapters.pydantic_ai import guard_tool      # @agent.tool_plain  @guard_tool(g)  def refund(...): ...
```

El modo local (sin cuenta) es la misma llamada con un mundo en lugar de un cliente:
`createGuard({ world: demoWorld(), agent: "invoice-agent" })` / `Guard(world=demo_world(), agent="invoice-agent")`.

## API

```bash
curl https://mnki.com/api/v1/verify -H "Authorization: Bearer at_verify_…" -H "content-type: application/json" \
  -d '{"agent":"invoice-agent","action":"refund.create","resource":"customer:4711","amount":47000,"currency":"EUR"}'
```

La respuesta lleva `decision` (`ALLOW` / `DENY` / `REQUIRE_APPROVAL`), `reasons`, la lista de evidencia y
el id del evento del libro de registro; un `REQUIRE_APPROVAL` incluye un `approval_id` que se consulta en `/v1/approvals/{id}/status`.
Los motores de políticas que hablan [AuthZEN](/es/docs/standards) llaman a `/api/access/v1/evaluation` con la misma clave.
Referencia completa: [API](/es/docs/api) y el documento OpenAPI en `/api/v1/openapi`.


**Permisos.** `POST /v1/attestations { decision_id }` convierte una decisión permitida o aprobada en un
permiso firmado de corta duración, que el agente presenta como `attestation` en llamadas posteriores. Un
permiso derivado de una aprobación humana es de un solo uso (perfil §9.2): el primer `ALLOW` que lo presenta
lo consume, una repetición se rechaza con `attestation_invalid:consumed`, y solo sirve para la solicitud que
se aprobó. `GET /v1/orgs/{id}/status/attestation/{jti}` es público y responde `active`, `revoked`, `expired`
o `unknown`, de modo que quien aceptó una de sus atestaciones puede comprobarla antes de actuar (§12.1).
## Verificación sin conexión

`mnki-verifier` (TypeScript) y `at-verify` (Go, `go/cmd/at-verify`) validan cadenas de delegación, decisiones firmadas
y atestaciones sin contactar con la consola, contra las claves publicadas por la organización. Superan
los mismos [vectores de conformidad](/es/docs/conformance) que el verificador alojado, de modo que un socio puede comprobar una
atestación firmada de sus agentes en su propio proceso.

## Dónde están los paquetes

| Canal | Nombre |
| --- | --- |
| npm | [`mnki-cli`](https://www.npmjs.com/package/mnki-cli) · [`mnki-sdk`](https://www.npmjs.com/package/mnki-sdk) · [`mnki-mcp`](https://www.npmjs.com/package/mnki-mcp) · [`mnki-verifier`](https://www.npmjs.com/package/mnki-verifier) |
| PyPI | [`mnki`](https://pypi.org/project/mnki/) |
| Contenedor | `ghcr.io/mnkiagentos/mnki-mcp` (firmado con cosign) |
| Registro MCP | `io.github.MNKIAgentOS/mnki-mcp` (también lo que indexan las galerías de GitHub y VS Code y PulseMCP) |
| Extensión de Claude Desktop | `mnki-mcp.mcpb` en cada [versión publicada en GitHub](https://github.com/MNKIAgentOS/agent-trust/releases) |
| Cursor, Smithery, Glama, mcp.so | listados desde el repositorio (`.mcp.json`, `smithery.yaml`, `glama.json` en su raíz) |
| Código fuente | [github.com/MNKIAgentOS/agent-trust](https://github.com/MNKIAgentOS/agent-trust) (Apache-2.0) |
