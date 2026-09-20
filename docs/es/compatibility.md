# Matriz de compatibilidad

Con qué se ha ejecutado mnki, en qué versión y cuánto vale esa afirmación. Los niveles son deliberadamente
estrictos: **Verificado** significa que un socio de diseño lo ejecuta contra agentes reales en staging y está en CI;
**Compatible** significa que la integración se ejercita con una prueba automatizada contra la versión fijada;
**Experimental** significa que el adaptador existe, sigue el contrato público de herramientas del framework y se prueba
solo contra un sustituto de ese contrato; **No compatible** se documenta para que nadie tenga dudas.

Cada adaptador es una envoltura fina sobre `guard.check(tool, args)`; el paquete nunca importa el framework
(solo tipos en TypeScript, carga diferida en Python), de modo que un adaptador carga sin el framework instalado.
Los rechazos se devuelven al modelo como un resultado estructurado de forma predeterminada (`{ error, reasons, evidence }`) o
se lanzan como excepción (`onRefused: "throw"` / `on_refused="throw"`). Los modos `observe → warn → require_approval → enforce`
se aplican en todas partes.

## Frameworks

| Framework | Lenguaje | Versión fijada | Punto de entrada | Integración | Espera de aprobación | Nivel |
| --- | --- | --- | --- | --- | --- | --- |
| OpenAI Agents SDK | TypeScript | `@openai/agents` 0.1.x | `mnki-sdk/openai-agents` → `guardTools(guard, tools)` | envuelve `FunctionTool.invoke` | sí (el guard espera, o resultado `ask`) | Experimental |
| OpenAI Agents SDK | Python | `openai-agents` 0.22.x | `mnki.adapters.openai_agents.guard_tools` | envuelve `FunctionTool.on_invoke_tool` | sí | Compatible |
| LangChain / LangGraph | TypeScript | `@langchain/core` 0.3.x | `mnki-sdk/langchain` → `guardTools` | envuelve `invoke` (args o ToolCall), se conserva el prototipo para `ToolNode` | sí | Experimental |
| LangChain / LangGraph | Python | `langchain-core` 1.6.x | `mnki.adapters.langchain.guard_tools` | subclase `GuardedTool(BaseTool)`, `_run`/`_arun` → `invoke` | sí | Compatible |
| Claude Agent SDK | TypeScript | `@anthropic-ai/claude-agent-sdk` 0.1.x | `mnki-sdk/claude-agent-sdk` → `preToolUse(guard)` | hook `PreToolUse` → `allow` / `deny` (evidencia como motivo) / `ask` | `ask` (una persona decide en el cliente) o el guard espera | Experimental |
| Vercel AI SDK | TypeScript | `ai` 5.x | `mnki-sdk/ai` → `guardTools(guard, { … })` | envuelve `execute`; las herramientas del lado del cliente no se tocan | sí | Experimental |
| CrewAI | Python | `crewai` 0.80+ | `mnki.adapters.crewai.guard_tools` | subclase `GuardedTool(BaseTool)`, `_run` | sí | Experimental |
| Pydantic AI | Python | `pydantic-ai` 0.1+ | `mnki.adapters.pydantic_ai.guard_tool` | decorador sobre funciones de herramienta (síncronas/asíncronas, compatible con `RunContext`) | sí | Experimental |
| Funciones simples | ambos | — | `guard.wrap(tool, fn)` / `@g.wrap("tool")` | — | sí | Verificado |

## Clientes MCP (`mnki protect`)

| Cliente | Configuración | Formatos | Nivel |
| --- | --- | --- | --- |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS), `%APPDATA%\Claude\…` (Windows) | `mcpServers` | Compatible |
| Claude Code | `~/.claude.json` (global y por proyecto en `projects[dir].mcpServers`), `<project>/.mcp.json` | `mcpServers` | Compatible |
| Cursor | `~/.cursor/mcp.json`, `<project>/.cursor/mcp.json` | `mcpServers` | Compatible |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | `mcpServers` | Compatible |
| VS Code | `<project>/.vscode/mcp.json` | `servers` (se conserva `type`) | Compatible |

## Servidores MCP (proxy `mnki-mcp`)

| Transporte | Nivel | Notas |
| --- | --- | --- |
| stdio (comando lanzado) | Verificado | ejecución en staging el 16 sep 2026: el modo observación registra lo que se denegaría, el modo enforce responde `-32003` con evidencia, una delegación cambia una herramienta a ALLOW |
| Streamable HTTP (respuestas JSON y SSE, `mcp-session-id`) | Compatible | probado contra un servidor sustituto; `DELETE` al cerrar |
| Pasarela alojada (`/api/gateway/mcp/<integration>`) | Verificado | solo servidores Streamable HTTP |

## Sistemas intermediados (bróker de acceso)

Proveedores para los que el bróker puede guardar una credencial y ejecutar en nombre de un agente. "Verificado"
significa que el catálogo de operaciones se ejecuta contra una simulación de la API documentada del proveedor en las
pruebas de integración; las ejecuciones reales contra cada proveedor se anotan aquí a medida que se hacen.

| Proveedor | Autenticación | Operaciones | Nivel |
| --- | --- | --- | --- |
| Stripe | clave restringida o secreta | reembolsos, cargos, intenciones de pago, clientes, facturas, saldo (sonda) | Verificado (API simulada) |
| GitHub | app OAuth o token | issues, comentarios, lista de pull requests, repositorio, usuario (sonda); lista de propietarios | Verificado (API simulada) |
| Slack | app OAuth | `chat.postMessage`, `conversations.list`, `auth.test` (sonda); los sobres `ok:false` hacen fallar la concesión | Verificado (API simulada) |
| Google | app OAuth | envío de Gmail, creación de eventos de Calendar, userinfo (sonda) | Verificado (API simulada) |
| Microsoft 365 | app OAuth | envío de correo, creación de eventos de calendario, `me` (sonda) | Verificado (API simulada) |
| AWS | par de claves IAM | STS AssumeRole (credencial nativa de corta duración), petición firmada SigV4 a servicios permitidos | Verificado (vectores de firma + STS simulado) |
| Cualquier API HTTP | clave de API en una cabecera | operaciones declaradas por conexión; solo https público | Verificado |

## Identidad y estándares

| Estándar | Dónde | Nivel |
| --- | --- | --- |
| JWT-SVID de SPIFFE como credencial del agente | encabezado `Agent-Credential`, anclas de confianza por organización | Verificado |
| Tokens de emisor OIDC (Okta, Entra) | anclas de confianza, SSO | Verificado |
| Evaluación AuthZEN 1.0 | `/api/access/v1/evaluation` | Verificado |
| MCP 2025-06 (tools/call) | proxy y pasarela | Verificado |
| A2A (tarjeta de agente, `mnki-sdk/a2a` signTaskRequest / verifyBeforeAccept) | `/v1/agents/{id}/agent-card`, `/.well-known/agent-card.json` | Compatible (atestación verificada sin conexión contra el JWKS de la organización llamante; probado con dos organizaciones locales) |
| Configuración de entidad de OpenID Federation | `/.well-known/openid-federation` | Compatible |
| Estado de atestaciones, perfil §12.1 | `/v1/orgs/{id}/status/attestation/{jti}` (público, sin autenticación) | Verificado |
| Permisos de un solo uso, perfil §9.2 | `atp.use` en una atestación; se consume con el primer `ALLOW` | Verificado |
| Declaración de ruta del efecto, perfil §15 | `context.effect_path` en `/v1/verify`; pasarela `custody`, receptor A2A `attested`, proxy local `none` | Verificado |

## Entornos de ejecución

| Entorno de ejecución | Nivel |
| --- | --- |
| Node 20, 22 (ESM) | Verificado |
| Python 3.10 – 3.14 | Compatible (3.14 en CI) |
| Go 1.22+ (`at-verify`) | Verificado |
| Bun / Deno | No compatible (sin probar) |

Los niveles solo suben cuando hay un despliegue real detrás. Para llevar un framework a **Verificado**, ejecútelo contra
staging con agentes reales y cuéntenoslo: [github.com/MNKIAgentOS/agent-trust/issues](https://github.com/MNKIAgentOS/agent-trust/issues).
