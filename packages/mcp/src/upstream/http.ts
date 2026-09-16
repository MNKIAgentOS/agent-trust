/**
 * A Streamable HTTP MCP server as the upstream: each client frame is POSTed; JSON responses and SSE streams are
 * both turned back into frames; the session id is kept for the whole run and released with DELETE on close.
 */
import type { Upstream } from "../proxy";

export function httpUpstream(url: string, headers: Record<string, string> = {}, fetcher: typeof fetch = fetch, log: (m: string) => void = () => {}): Upstream {
  let cb: ((frame: string) => void) | null = null; let session: string | null = null;
  const h = () => ({ ...headers, accept: "application/json, text/event-stream", "content-type": "application/json", ...(session ? { "mcp-session-id": session } : {}) });
  const emitSse = async (body: ReadableStream<Uint8Array>) => {
    const reader = body.getReader(); const dec = new TextDecoder(); let buf = ""; let data: string[] = [];
    for (;;) {
      const { value, done } = await reader.read(); if (done) break; buf += dec.decode(value, { stream: true });
      let i: number; while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i).replace(/\r$/, ""); buf = buf.slice(i + 1);
        if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
        else if (line === "") { if (data.length) cb?.(data.join("\n")); data = []; }
      }
    }
    if (data.length) cb?.(data.join("\n"));
  };
  return {
    send: (frame) => { void (async () => {
      try {
        const r = await fetcher(url, { method: "POST", headers: h(), body: frame });
        const sid = r.headers.get("mcp-session-id"); if (sid) session = sid;
        const ct = r.headers.get("content-type") ?? "";
        if (r.status === 202 || r.status === 204) return;
        if (ct.includes("text/event-stream") && r.body) { await emitSse(r.body); return; }
        const text = await r.text(); if (!text.trim()) return;
        if (!r.ok) { let id: unknown = null; try { id = (JSON.parse(frame) as { id?: unknown }).id ?? null; } catch { /* keep null */ } cb?.(JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32000, message: `upstream ${r.status}`, data: text.slice(0, 500) } })); return; }
        cb?.(text.trim());
      } catch (e) { log(`upstream error: ${e instanceof Error ? e.message : e}`); let id: unknown = null; try { id = (JSON.parse(frame) as { id?: unknown }).id ?? null; } catch { /* keep null */ } cb?.(JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32000, message: "upstream unreachable" } })); }
    })(); },
    onMessage: (fn) => { cb = fn; },
    close: async () => { if (session) await fetcher(url, { method: "DELETE", headers: h() }).catch(() => undefined); },
  };
}
