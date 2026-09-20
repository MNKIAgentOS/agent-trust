import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createVerifier, parseAmountMap, JSONRPC_DENIED, JSONRPC_APPROVAL_REQUIRED, JSONRPC_QUOTA_EXCEEDED, JSONRPC_UNREACHABLE } from "../src/verify";
import { appendShadow, readShadow, summarizeShadow, shadowLogPath } from "../src/shadow";
import { parseArgs } from "../src/config";
import type { GuardRecord } from "mnki-sdk";

const decision = (d: string, reasons?: string[]) => ({ decision: d, reasons: reasons ?? (d === "ALLOW" ? ["identity_verified", "authority_valid"] : ["capability_missing"]), evidence: [{ step: "capability", status: d === "ALLOW" ? "pass" : "fail", title: "Capability" }, { step: "identity", status: "pass", title: "Identity" }], request_id: "req_1", decision_id: "dec_1", approval_id: d === "REQUIRE_APPROVAL" ? "apr_1" : null, latency_ms: 2 });
function api(answer: (body: Record<string, unknown>) => Response | Promise<Response>) {
  const bodies: Record<string, unknown>[] = [];
  const f = (async (_u: string, init?: RequestInit) => { const b = JSON.parse(String(init?.body ?? "{}")); bodies.push(b); return answer(b); }) as unknown as typeof fetch;
  return { f, bodies };
}
const opts = (mode: "observe" | "warn" | "require_approval" | "enforce", f: typeof fetch, extra: Record<string, unknown> = {}) => ({ baseUrl: "https://c.test", apiKey: "k", agent: "agt_1", server: "github", mode, fetch: f, approval: { wait: false }, ...extra });

describe("mnki-mcp verifier", () => {
  it("maps tools/call to the gateway's request shape (action, resource, context.mcp, arguments_hash, amount map)", async () => {
    const { f, bodies } = api(() => new Response(JSON.stringify(decision("ALLOW"))));
    const v = createVerifier(opts("enforce", f, { amountMap: parseAmountMap("create_payment=total:ccy") }));
    expect(await v.check("create_payment", { total: "1200", ccy: "EUR", note: "x" })).toEqual({ allowed: true });
    expect(bodies[0]).toMatchObject({ agent: "agt_1", action: "mcp:tools/call:create_payment", resource: "mcp://github/tools/create_payment", amount: 1200, currency: "EUR", context: { mcp: { server: "github", tool: "create_payment" }, tool: "create_payment" } });
    expect(typeof (bodies[0].context as { arguments_hash: string }).arguments_hash).toBe("string");
    expect((bodies[0].context as { effect_path: string }).effect_path).toBe("none");   // §15: honest — the local proxy cannot claim custody
    await v.check("other", { amount: 5, currency: "usd" }); expect(bodies[1]).toMatchObject({ amount: 5 }); expect(bodies[1]).not.toHaveProperty("currency");
    expect(parseAmountMap(" a=x:y , b=z, c ")).toEqual({ a: { amount: "x", currency: "y" }, b: { amount: "z" }, c: {} });
  });
  it("mode matrix: observe/warn forward denials (recording them), require_approval escalates only, enforce refuses with evidence", async () => {
    const records: GuardRecord[] = [];
    const deny = api(() => new Response(JSON.stringify(decision("DENY")))).f;
    for (const mode of ["observe", "warn"] as const) { records.length = 0; const v = createVerifier(opts(mode, deny, { onDecision: (r: GuardRecord) => { records.push(r); } })); expect(await v.check("t", {})).toEqual({ allowed: true }); expect(records[0]).toMatchObject({ mode, decision: "DENY", enforced: false, tags: ["would_deny", "excess_capability"] }); }
    expect(await createVerifier(opts("require_approval", deny)).check("t", {})).toEqual({ allowed: true });
    const r = await createVerifier(opts("enforce", deny)).check("t", {});
    expect(r).toMatchObject({ allowed: false, error: { code: JSONRPC_DENIED, data: { decision_id: "dec_1", reasons: ["capability_missing"], evidence: [{ step: "capability", status: "fail" }] } } });
    const esc = api(() => new Response(JSON.stringify(decision("REQUIRE_APPROVAL", ["policy:big:require_approval"])))).f;
    for (const mode of ["require_approval", "enforce"] as const) expect(await createVerifier(opts(mode, esc)).check("t", {})).toMatchObject({ allowed: false, error: { code: JSONRPC_APPROVAL_REQUIRED, data: { approval_id: "apr_1", status: "pending", poll_url: "/api/v1/approvals/apr_1/status" } } });
    expect(await createVerifier(opts("warn", esc)).check("t", {})).toEqual({ allowed: true });
  });
  it("quota → -32005; control plane unreachable → -32006 in enforce, forwarded in observe/warn", async () => {
    const errors: string[] = []; const onError = (k: string, d: string) => errors.push(`${k}:${d}`);
    const quota = api(() => new Response(JSON.stringify({ error: "plan_limit_reached" }), { status: 402 })).f;
    expect(await createVerifier(opts("enforce", quota, { onError })).check("t", {})).toMatchObject({ allowed: false, error: { code: JSONRPC_QUOTA_EXCEEDED } });
    const down = (async () => { throw new Error("ECONNREFUSED"); }) as unknown as typeof fetch;
    expect(await createVerifier(opts("enforce", down, { onError })).check("t", {})).toMatchObject({ allowed: false, error: { code: JSONRPC_UNREACHABLE, data: { detail: "ECONNREFUSED" } } });
    expect(await createVerifier(opts("observe", down, { onError })).check("t", {})).toEqual({ allowed: true });
    expect(errors).toEqual(["quota:plan_limit_reached (402)", "unreachable:ECONNREFUSED", "unreachable:ECONNREFUSED"]);
  });
});

describe("shadow log + report", () => {
  let home: string;
  beforeEach(() => { home = mkdtempSync(join(tmpdir(), "mnki-shadow-")); process.env.MNKI_HOME = home; });
  afterEach(() => { delete process.env.MNKI_HOME; rmSync(home, { recursive: true, force: true }); });
  it("appends one line per decision under $MNKI_HOME/shadow and summarises what enforcing would change", () => {
    const rec = (tool: string, decision: string, reasons: string[], tags: string[]): GuardRecord => ({ at: "2026-09-16T00:00:00Z", mode: "observe", tool, action: `mcp:tools/call:${tool}`, decision, enforced: false, reasons, evidence: [], tags });
    appendShadow("gh/x", rec("read", "ALLOW", [], [])); appendShadow("gh/x", rec("push", "DENY", ["capability_missing"], ["would_deny", "excess_capability"])); appendShadow("gh/x", rec("push", "DENY", ["no_delegation"], ["would_deny", "missing_delegation"])); appendShadow("gh/x", rec("merge", "REQUIRE_APPROVAL", ["policy:m:require_approval"], ["approval_required", "policy_mismatch"]));
    expect(shadowLogPath("gh/x")).toBe(join(home, "shadow", "gh_x.ndjson")); expect(existsSync(shadowLogPath("gh/x"))).toBe(true); expect(readFileSync(shadowLogPath("gh/x"), "utf8").split("\n").filter(Boolean)).toHaveLength(4);
    const s = summarizeShadow("gh/x", [...readShadow("gh/x"), "garbage"]);
    expect(s).toMatchObject({ calls: 4, wouldAllow: 1, wouldDeny: 2, approvalRequired: 1, missingDelegation: 1, excessCapability: 1, policyMismatch: 1, byTool: { push: { calls: 2, deny: 2, approval: 0 }, merge: { calls: 1, deny: 0, approval: 1 } } });
    expect(s.suggestions.join("\n")).toMatch(/Issue a delegation/); expect(s.suggestions.join("\n")).toMatch(/mcp:tools\/call:push/); expect(s.suggestions.join("\n")).toMatch(/policy explain/);
    expect(summarizeShadow("clean", [JSON.stringify({ tool: "a", decision: "ALLOW" })]).suggestions).toEqual(["Every observed call would have been allowed — safe to switch to --mode enforce."]);
    expect(readShadow("none")).toEqual([]);
  });
});

describe("proxy argv", () => {
  it("parses stdio and http upstreams, modes, and requires a console", () => {
    const env = { MNKI_URL: "https://c.test", MNKI_API_KEY: "k", MNKI_HOME: "/nonexistent" } as NodeJS.ProcessEnv;
    const s = parseArgs(["--agent", "a", "--server", "gh", "--mode", "enforce", "--upstream", "--", "npx", "-y", "srv", "--flag"], env);
    expect(s).toMatchObject({ agent: "a", server: "gh", mode: "enforce", baseUrl: "https://c.test", apiKey: "k", upstream: { kind: "stdio", command: "npx", args: ["-y", "srv", "--flag"] }, approvalWait: true, telemetry: true });
    const h = parseArgs(["--agent", "a", "--upstream-url", "https://m/mcp", "--upstream-header", "Authorization=Bearer x=y", "--no-wait", "--approval-timeout", "10"], { ...env, MNKI_TELEMETRY: "0" });
    expect(h).toMatchObject({ server: "mcp", mode: "observe", upstream: { kind: "http", url: "https://m/mcp", headers: { Authorization: "Bearer x=y" } }, approvalWait: false, approvalTimeoutMs: 10000, telemetry: false });
    expect(() => parseArgs(["--upstream", "x"], env)).toThrow(/--agent/); expect(() => parseArgs(["--agent", "a", "--upstream", "x"], {} as NodeJS.ProcessEnv)).toThrow(/no console/); expect(() => parseArgs(["--agent", "a", "--mode", "yolo", "--upstream", "x"], env)).toThrow(/--mode/);
    expect(() => parseArgs(["--agent", "a"], env)).toThrow(/--upstream/);
  });
});
