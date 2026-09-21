# Bróker de acceso

Los agentes piden capacidades, no credenciales. Una **conexión** es un sistema externo para el que su organización
guarda una credencial: una cuenta de Stripe, una organización de GitHub, un espacio de Slack, una cuenta de Google o
Microsoft 365, un rol de AWS o cualquier API HTTP. Un **permiso de agente** es una delegación que dice qué agente puede
ejecutar qué operaciones en qué conexión y con qué límites. Una **concesión** es el permiso de un solo uso que el
bróker emite cuando un agente pide ejecutar una operación: la petición se verifica con la conexión como audiencia, el
permiso se consume antes del efecto, el bróker realiza la llamada con la credencial guardada y la concesión registra lo
ocurrido. El agente nunca ve la credencial. La sección §17 del perfil define los objetos; esta página explica cómo
usarlos.

| Quiere… | Haga esto |
| --- | --- |
| Que un agente reembolse en Stripe sin darle una clave | Consola → **Acceso** → Conectar Stripe con una clave restringida → Conceder acceso → `POST /v1/grants/execute` |
| Usar cualquier conexión desde un cliente MCP | Apunte el cliente a `/api/gateway/access/<id de conexión>/mcp` |
| Que un agente pida el acceso que no tiene | `POST /v1/access-requests`; apruébelo en la consola; el agente reintenta |
| Dar a un agente credenciales de AWS de corta duración | Conecte AWS con un par de claves IAM; `sts.assume_role` las devuelve como concesión `native_token` |

## Conectar un sistema

Consola → **Acceso** → **Conectar un sistema**. Elija el proveedor, ponga nombre a la conexión y, después, inicie
sesión con el proveedor (OAuth: GitHub, Google, Slack, Microsoft), pegue una clave de API (Stripe, GitHub, cualquier
API HTTP) o un par de claves IAM (AWS). El secreto se cifra en reposo con la `TOOL_ENC_KEY` del despliegue y solo lo
lee el bróker al ejecutar; ningún endpoint, evento ni registro lo transporta.

Cada proveedor trae un **catálogo de operaciones**: las operaciones que los agentes pueden pedir, cada una con un
esquema de parámetros (claves permitidas, tipos, patrones, límites), un método HTTP y un nivel de riesgo. Active solo
lo que necesite; las operaciones desactivadas no pueden concederse. Las **restricciones** limitan cada concesión de la
conexión diga lo que diga la delegación del agente: un tope de importe aparece en la evidencia como regla de política
(`connection:<id>:<op>:max_value`); moneda y región se rechazan antes de la verificación.

| Proveedor | Autenticación | Operaciones (primera versión) |
| --- | --- | --- |
| Stripe | Clave de API | `refund.create`, `charge.get`, `payment_intent.get`, `customer.get`, `invoice.list`, `balance.get` (sonda) |
| GitHub | OAuth o token | `issue.create`, `issue.comment.create`, `pull.list`, `repo.get`, `user.get` (sonda); lista de propietarios permitidos |
| Slack | OAuth | `chat.postMessage`, `conversations.list`, `auth.test` (sonda) |
| Google | OAuth | `gmail.send`, `calendar.event.create`, `userinfo.get` (sonda) |
| Microsoft 365 | OAuth | `mail.send`, `calendar.event.create`, `me.get` (sonda) |
| AWS | Par de claves IAM | `sts.assume_role` (credenciales de corta duración, mínimo 15 minutos, registradas como `native_token`), `request` (llamada firmada SigV4 a un servicio permitido) |
| Kubernetes | Token de ServiceAccount | `version.get` (sonda), `namespace.list`, `pod.list`, `pod.get`, `pod.logs`, `deployment.get`, `deployment.restart`, `deployment.scale`, `pod.delete`, `namespace.delete`; lista de espacios de nombres permitidos con `*` final |
| Cloudflare | Token de API acotado | `zone.list` (sonda), `zone.get`, `dns.list`, `dns.get`, `dns.create`, `dns.update`, `dns.delete`, `cache.purge`, `cache.purge_everything`; lista de zonas permitidas |
| API HTTP | Clave de API | Operaciones que usted declara por conexión (id, método, ruta con marcadores `{param}`, esquema de parámetros, riesgo); solo https público, sin direcciones IP, redirecciones rechazadas |

### Conectar un clúster de Kubernetes

1. **Compruebe que el API server es accesible con un certificado de confianza pública.** Desde su equipo, sin `-k`:

   ```bash
   curl -sS https://SU-API-SERVER/version
   ```

   Si devuelve la versión, el plano de control alojado también llega. Un error de certificado significa que no, y ese
   clúster necesita el plano de control autoalojado. Los endpoints gestionados de EKS, GKE y AKS presentan la CA del
   clúster y no pasan esta comprobación.

2. **Cree un ServiceAccount con solo los verbos que necesitan las operaciones** y un token para él (mismo manifiesto
   que en la versión en inglés de esta página: ServiceAccount, ClusterRole, ClusterRoleBinding y un Secret de tipo
   `kubernetes.io/service-account-token`). Quite las reglas que no quiera: no conceder `delete` sobre namespaces
   significa que ninguna política es lo único que separa a un agente de un espacio de nombres borrado.

3. **Conéctelo.** Consola → Acceso → Conectar un sistema → Kubernetes. La URL del API server es la URL base, el token
   es la credencial y los espacios de nombres permitidos aceptan un `*` final. **Probar conexión** llama a `/version`,
   que no requiere RBAC: una prueba correcta demuestra que el token llega al clúster, no que el rol sea el adecuado.

Kubernetes no ofrece deliberadamente ninguna forma de leer un Secret, crear un Pod o un Job, ni de ejecutar un
intérprete dentro de un contenedor: cada una entrega al agente ejecución arbitraria o las credenciales que el bróker
existe para mantener fuera de su alcance. El API server debe ser accesible por internet con un **certificado de
confianza pública**, porque el plano de control alojado valida TLS contra el almacén raíz público. Un clúster con
endpoint privado, o con un certificado firmado por la CA del propio clúster, se alcanza desde el plano de control
autoalojado, donde el entorno confía en la CA que usted le indique.

`POST /v1/connections/{id}/test` ejecuta la sonda de lectura del proveedor con la credencial guardada y marca la
conexión como `active` o `needs_reconnect`. Desconectar destruye la credencial, desactiva la conexión y revoca toda
concesión no ejecutada; el libro de registro conserva el historial.

## Conceder acceso

Los agentes obtienen acceso como cualquier otra autoridad: con una delegación. Consola → Acceso → **Conceder acceso**
emite una desde el principal propietario del agente con capacidades en el vocabulario del bróker, acción
`<proveedor>:<operación>` sobre el recurso `<proveedor>:<id de conexión>/*`, y restricciones acotadas a las de la
conexión. Desde la CLI:

```bash
mnki delegate --issuer principal:<id> --to <agente> --cap "stripe:refund.create=stripe:con_…/*;max_value=500;currency=EUR" --expires 30d
```

Una delegación temporal se sitúa **junto a** la cadena existente del agente, no encima: el verificador elige, entre las
delegaciones activas del agente, la que cubre la acción y el recurso (§17.3), así que conceder una semana de acceso a
Stripe no oculta los demás permisos del agente y su caducidad no los rompe.

## Ejecutar

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
```

```python
from mnki import AgentTrustClient, Guard
g = Guard(AgentTrustClient("https://mnki.com", api_key=os.environ["MNKI_API_KEY"]), agent="invoice-agent")
r = g.access("con_…", "refund.create", {"charge": "ch_1…", "amount": 42000, "currency": "EUR"})
```

En orden: interruptor de plataforma y configuración → plan y cuota → límites de frecuencia → operación resuelta y
parámetros validados → restricciones de la conexión → verificación con la conexión como audiencia (`aud`) y las
restricciones como reglas de política → permiso de un solo uso emitido y consumido → la llamada, con clave de
idempotencia cuando el proveedor la admite → concesión marcada `executed` o `failed` → `grant.issued` y
`grant.executed` en el libro de registro. Respuestas:

| Estado | Cuerpo | Significado |
| --- | --- | --- |
| 200 | `{ grant, decision, result }` | Hecho. `result.body` se proyecta a los campos que necesita un agente y se le quita todo lo que parezca un secreto; la concesión guarda su hash. |
| 202 | `{ decision, approval_id, poll_url, resume }` | Una persona debe aprobar. Consulte `poll_url` y reenvíe con `approval_id`; la aprobación se ejecuta exactamente una vez y solo con los mismos parámetros. |
| 403 | `{ error: "denied", decision, access_request_hint?, agent_hint? }` | Denegado con motivos y la evidencia fallida. `capability_missing` incluye una pista para pedir acceso. Una negativa causada por el ciclo de vida del propio agente (`agent_pending`, `agent_suspended`, `agent_revoked`, `agent_retired`) incluye `agent_hint`: qué tiene que hacer una persona con la identidad y la URL de la consola donde hacerlo. Volver a pedir de otra forma no servirá hasta entonces. |
| 409 | `approval_already_used`, `grant_already_executed`, `approval_mismatch`, `permit_already_used` | Repeticiones y aprobaciones alteradas. |
| 402 | `plan_feature_required`, `plan_limit_reached` | Plan o cuota de verificaciones. |
| 502 | `{ grant: { status: "failed" }, result: { error } }` | La llamada al destino falló (tiempo de espera, redirección, cuerpo demasiado grande, error del proveedor); nada se reintenta sin una concesión nueva. |
| 503 | `feature_disabled`, `broker_unconfigured` | Bróker apagado por el operador, o `TOOL_ENC_KEY` sin definir. |

Las cabeceras `agent-trust-decision`, `agent-trust-request` y `agent-trust-grant` nombran la decisión, la petición y la
concesión. Envíe `Agent-Proof` para firmar la petición y `Agent-Attestation` para presentar un permiso emitido antes.

**Emitir sin ejecutar.** `POST /v1/grants` con el mismo cuerpo devuelve el permiso (una atestación de un solo uso con
`aud` = la conexión y `atp.grant` = la operación y un hash de los parámetros) en lugar de ejecutar la llamada;
preséntelo después como `attestation`. Un permiso para la conexión A se rechaza en la conexión B
(`attestation_invalid:audience`); un permiso para otros parámetros se rechaza (`attestation_invalid:request_hash`);
un permiso presentado dos veces se rechaza (`attestation_invalid:consumed`). Para `sts.assume_role` el intercambio
ocurre al emitir y la credencial de corta duración es el resultado.

## Una conexión como servidor MCP

Cada conexión es también un servidor MCP Streamable-HTTP en `https://mnki.com/api/gateway/access/<id de conexión>/mcp`:
`tools/list` son las operaciones activadas con sus esquemas de parámetros y cada `tools/call` recorre la ruta de
ejecución anterior.

```json
{ "mcpServers": { "stripe": { "url": "https://mnki.com/api/gateway/access/con_…/mcp",
  "headers": { "Authorization": "Bearer at_verify_…", "Agent-Id": "invoice-agent" } } } }
```

Errores JSON-RPC: `-32001` aprobación necesaria (reenvíe con `params.approval_id`), `-32003` denegado, `-32004` no
disponible, `-32005` cuota. No interviene ningún servidor MCP de destino: responde el propio bróker.

## Pedir acceso

Cuando a un agente se le deniega por falta de capacidad, puede pedírsela a una persona:

```bash
curl -X POST https://mnki.com/api/v1/access-requests -H "authorization: Bearer $MNKI_API_KEY" -H "content-type: application/json" \
  -d '{ "agent": "invoice-agent", "connection": "con_…", "operations": ["customer.get"], "duration_seconds": 3600, "reason": "Investigación de reembolso, ticket 4711" }'
```

Propietarios y administradores reciben una notificación push y un correo; Consola → Acceso → **Solicitudes** aprueba
por un tiempo limitado (más corto o más acotado que lo pedido, si lo prefieren) o deniega con un motivo. La aprobación
emite una delegación temporal desde el propietario del agente; el agente consulta `GET /v1/access-requests/{id}` y
después pide concesiones con normalidad. Las solicitudes pendientes caducan a las 72 horas; la delegación se barre
cuando se cierra su ventana (`delegation.expired`).

## Qué guarda el libro de registro

`connection.created|updated|credential.set|connected|tested|disconnected`, `grant.issued|executed|failed|refused|revoked`,
`access_request.created|approved|denied|cancelled`, `access.permission_granted`, `delegation.expired`. Las concesiones
guardan la decisión, la aprobación, el `jti` del permiso, el estado y el id de petición del destino, un hash del cuerpo
entregado al agente y la latencia. Nunca se guardan cuerpos ni credenciales.

## Planes

Todos los planes incluyen conexiones (Free 1, Individual 3, Team 25, Enterprise ilimitadas con proveedores de
credenciales tipo vault y firma); por encima de las incluidas se compran conexiones de una en una como complemento,
junto a SSO. El interruptor `broker` del portal de administración detiene todas las concesiones de la plataforma;
`/api/health` informa `access_broker: ready` cuando `TOOL_ENC_KEY` está definida.
