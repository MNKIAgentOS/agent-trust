/**
 * The proxy core, transport-agnostic: JSON-RPC frames come in from the MCP client, `tools/call` requests are
 * verified, everything else is forwarded untouched; upstream frames go back verbatim. Batches that contain a
 * `tools/call` are split and each call verified on its own (the hosted gateway rejects them — here we can
 * do better). Errors are always JSON-RPC error objects on stdio, so clients never see transport failures.
 */
export interface Upstream { send(frame: string): void; onMessage(cb: (frame: string) => void): void; close(): Promise<void> | void }
export type VerifyOutcome = { allowed: true } | { allowed: false; error: { code: number; message: string; data?: unknown } };
export interface Verifier { check(tool: string, args: unknown): Promise<VerifyOutcome>; mode: string }
export interface ProxyOptions { upstream: Upstream; verifier: Verifier; toClient: (frame: string) => void; log?: (msg: string) => void }
export interface Proxy { fromClient(frame: string): Promise<void>; /** Waits for in-flight verifications (and `drainMs` for upstream replies) before closing the upstream. */ close(drainMs?: number): Promise<void>; readonly inflight: number }

interface Rpc { jsonrpc?: string; id?: string | number | null; method?: string; params?: { name?: string; arguments?: unknown } }
const rpcError = (id: Rpc["id"], code: number, message: string, data?: unknown) => JSON.stringify({ jsonrpc: "2.0", id: id ?? null, error: { code, message, ...(data === undefined ? {} : { data }) } });

/** Newline-delimited JSON: split a chunk into complete frames, keeping the remainder. */
export function splitFrames(buffer: string): { frames: string[]; rest: string } {
  const parts = buffer.split("\n"); const rest = parts.pop() ?? "";
  return { frames: parts.map((p) => p.trim()).filter(Boolean), rest };
}

export function createProxy(o: ProxyOptions): Proxy {
  o.upstream.onMessage((frame) => o.toClient(frame));
  const handleOne = async (msg: Rpc, raw: string): Promise<void> => {
    if (msg.method !== "tools/call") { o.upstream.send(raw); return; }
    const tool = msg.params?.name;
    if (typeof tool !== "string" || !tool) { o.toClient(rpcError(msg.id, -32602, "tools/call requires params.name")); return; }
    const outcome = await o.verifier.check(tool, msg.params?.arguments ?? {});
    if (outcome.allowed) { o.upstream.send(JSON.stringify(msg)); return; }
    if (msg.id === undefined || msg.id === null) { o.log?.(`notification-style tools/call for ${tool} refused: ${outcome.error.message}`); return; }
    o.toClient(rpcError(msg.id, outcome.error.code, outcome.error.message, outcome.error.data));
  };
  const pending = new Set<Promise<void>>();
  const run = async (frame: string): Promise<void> => {
    let msg: Rpc | Rpc[]; try { msg = JSON.parse(frame) as Rpc | Rpc[]; } catch { o.toClient(rpcError(null, -32700, "parse error")); return; }
    if (Array.isArray(msg)) { for (const m of msg) await handleOne(m, JSON.stringify(m)); return; }
    await handleOne(msg, frame);
  };
  return {
    get inflight() { return pending.size; },
    fromClient(frame) { const p = run(frame).finally(() => pending.delete(p)); pending.add(p); return p; },
    async close(drainMs = 0) { while (pending.size) await Promise.allSettled([...pending]); if (drainMs > 0) await new Promise((r) => setTimeout(r, drainMs)); await o.upstream.close(); },
  };
}
