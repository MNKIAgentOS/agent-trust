import { describe, it, expect } from "vitest";
import { httpUpstream } from "../src/upstream/http";
import { stdioUpstream } from "../src/upstream/stdio";

describe("upstreams", () => {
  it("http: posts frames, keeps the session id, turns JSON and SSE answers into frames, 202 for notifications, DELETE on close", async () => {
    const calls: { method: string; headers: Record<string, string>; body?: string }[] = []; let n = 0;
    const f = (async (_u: string, init?: RequestInit) => {
      calls.push({ method: init?.method ?? "GET", headers: init?.headers as Record<string, string>, body: init?.body as string | undefined });
      if (init?.method === "DELETE") return new Response(null, { status: 200 });
      n++;
      if (n === 1) return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { ok: true } }), { headers: { "content-type": "application/json", "mcp-session-id": "sess_9" } });
      if (n === 2) return new Response(null, { status: 202 });
      return new Response("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"a\":1}}\n\n", { headers: { "content-type": "text/event-stream" } });
    }) as unknown as typeof fetch;
    const up = httpUpstream("https://m/mcp", { Authorization: "Bearer t" }, f); const got: string[] = []; up.onMessage((x) => got.push(x));
    up.send('{"jsonrpc":"2.0","id":1,"method":"initialize"}'); await new Promise((r) => setTimeout(r, 20));
    up.send('{"jsonrpc":"2.0","method":"notifications/initialized"}'); await new Promise((r) => setTimeout(r, 20));
    up.send('{"jsonrpc":"2.0","id":3,"method":"tools/list"}'); await new Promise((r) => setTimeout(r, 30));
    await up.close();
    expect(got).toEqual(['{"jsonrpc":"2.0","id":1,"result":{"ok":true}}', '{"jsonrpc":"2.0","id":3,"result":{"a":1}}']);
    expect(calls[0].headers).toMatchObject({ Authorization: "Bearer t", accept: "application/json, text/event-stream" }); expect(calls[0].headers).not.toHaveProperty("mcp-session-id");
    expect(calls[1].headers["mcp-session-id"]).toBe("sess_9"); expect(calls[3]).toMatchObject({ method: "DELETE", headers: { "mcp-session-id": "sess_9" } });
  });
  it("http: transport failures come back as JSON-RPC errors carrying the request id", async () => {
    const up = httpUpstream("https://m/mcp", {}, (async () => { throw new Error("down"); }) as unknown as typeof fetch); const got: string[] = []; up.onMessage((x) => got.push(x));
    up.send('{"jsonrpc":"2.0","id":7,"method":"tools/list"}'); await new Promise((r) => setTimeout(r, 20));
    expect(JSON.parse(got[0])).toMatchObject({ id: 7, error: { code: -32000, message: "upstream unreachable" } });
  });
  it("stdio: spawns the server, frames its stdout, closes cleanly", async () => {
    const up = stdioUpstream(process.execPath, ["-e", "process.stdin.on('data',d=>{for(const l of d.toString().split('\\n'))if(l)process.stdout.write(JSON.stringify({echo:JSON.parse(l).id})+'\\n')})"], process.env, { write: () => true } as unknown as NodeJS.WritableStream);
    const got: string[] = []; up.onMessage((x) => got.push(x));
    up.send('{"id":1}'); up.send('{"id":2}'); await new Promise((r) => setTimeout(r, 300));
    expect(got).toEqual(['{"echo":1}', '{"echo":2}']); await up.close();
  });
});
