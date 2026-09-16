import { describe, it, expect } from "vitest";
import { createProxy, splitFrames, type Upstream, type Verifier } from "../src/proxy";

/** In-process upstream: records what it received and can answer. */
function fakeUpstream() {
  const received: string[] = []; let cb: (f: string) => void = () => {};
  const up: Upstream & { received: string[]; reply: (f: string) => void; closed: boolean } = { received, closed: false, send: (f) => { received.push(f); }, onMessage: (fn) => { cb = fn; }, close: () => { up.closed = true; }, reply: (f) => cb(f) };
  return up;
}
const verifier = (allow: (tool: string) => boolean): Verifier => ({ mode: "enforce", check: async (tool) => allow(tool) ? { allowed: true } : { allowed: false, error: { code: -32003, message: "denied by Agent Trust", data: { decision_id: "dec_1", reasons: ["capability_missing"] } } } });

describe("mnki-mcp proxy core", () => {
  it("forwards everything except tools/call, verifies tools/call, and relays upstream frames verbatim", async () => {
    const up = fakeUpstream(); const toClient: string[] = [];
    const p = createProxy({ upstream: up, verifier: verifier((t) => t === "read_file"), toClient: (f) => toClient.push(f) });
    await p.fromClient(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }));
    await p.fromClient(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }));
    await p.fromClient(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "read_file", arguments: { path: "/x" } } }));
    await p.fromClient(JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "delete_repo", arguments: {} } }));
    expect(up.received.map((f) => JSON.parse(f).method)).toEqual(["initialize", "notifications/initialized", "tools/call"]);
    expect(JSON.parse(up.received[2]).params.name).toBe("read_file");
    expect(toClient).toHaveLength(1); const err = JSON.parse(toClient[0]); expect(err).toMatchObject({ jsonrpc: "2.0", id: 3, error: { code: -32003, message: "denied by Agent Trust", data: { decision_id: "dec_1" } } });
    up.reply('{"jsonrpc":"2.0","id":2,"result":{"content":[]}}'); expect(toClient[1]).toBe('{"jsonrpc":"2.0","id":2,"result":{"content":[]}}');
    await p.close(); expect(up.closed).toBe(true);
  });
  it("splits batches so each tools/call is verified on its own, answers parse errors and malformed calls as JSON-RPC errors", async () => {
    const up = fakeUpstream(); const toClient: string[] = [];
    const p = createProxy({ upstream: up, verifier: verifier((t) => t === "ok"), toClient: (f) => toClient.push(f) });
    await p.fromClient(JSON.stringify([{ jsonrpc: "2.0", id: 1, method: "tools/list" }, { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "ok" } }, { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "bad" } }]));
    expect(up.received.map((f) => JSON.parse(f).id)).toEqual([1, 2]); expect(JSON.parse(toClient[0])).toMatchObject({ id: 3, error: { code: -32003 } });
    await p.fromClient("{not json"); expect(JSON.parse(toClient[1])).toMatchObject({ id: null, error: { code: -32700 } });
    await p.fromClient(JSON.stringify({ jsonrpc: "2.0", id: 4, method: "tools/call", params: {} })); expect(JSON.parse(toClient[2])).toMatchObject({ id: 4, error: { code: -32602 } });
    const logs: string[] = []; const p2 = createProxy({ upstream: fakeUpstream(), verifier: verifier(() => false), toClient: (f) => toClient.push(f), log: (m) => logs.push(m) });
    await p2.fromClient(JSON.stringify({ jsonrpc: "2.0", method: "tools/call", params: { name: "x" } })); expect(toClient).toHaveLength(3); expect(logs[0]).toMatch(/refused/);
  });
  it("splits newline-delimited chunks and keeps the remainder", () => {
    expect(splitFrames('{"a":1}\n{"b":2}\n{"c"')).toEqual({ frames: ['{"a":1}', '{"b":2}'], rest: '{"c"' });
    expect(splitFrames("\n \n")).toEqual({ frames: [], rest: "" });
  });
});
