import { describe, it, expect } from "vitest";
import { createGuard, demoWorld, Denied } from "../src/index";
import { guardTools as guardOpenAI } from "../src/adapters/openai-agents";
import { guardTools as guardLangChain } from "../src/adapters/langchain";
import { guardTools as guardAi } from "../src/adapters/ai";
import { preToolUse, parseToolName } from "../src/adapters/claude-agent-sdk";
import { refusal } from "../src/adapters/shared";

/** Every adapter is exercised against the local demo world: no framework installed, no network. */
const guard = () => createGuard({ world: demoWorld(), agent: "invoice-agent", actionPrefix: "" });
const ok = { customer_id: "customer:1", amount: 420, currency: "EUR" }, big = { customer_id: "customer:1", amount: 47000, currency: "EUR" }, mid = { customer_id: "customer:1", amount: 3200, currency: "EUR" };

describe("framework adapters", () => {
  it("OpenAI Agents JS: invoke() is verified; refusals come back as a JSON string result, or throw when asked", async () => {
    class FunctionTool { constructor(public name: string) {} async invoke(_ctx: unknown, input: string) { return `ran ${this.name} ${input}`; } }
    const [refund] = guardOpenAI(guard(), [new FunctionTool("refund.create")]);
    expect(refund).toBeInstanceOf(FunctionTool);
    expect(await refund.invoke({}, JSON.stringify(ok))).toBe(`ran refund.create ${JSON.stringify(ok)}`);
    const r = JSON.parse((await refund.invoke({}, JSON.stringify(big))) as string);
    expect(r).toMatchObject({ error: "denied", reasons: expect.arrayContaining(["constraint_violated"]) }); expect(r.evidence.some((e: { status: string }) => e.status === "fail")).toBe(true);
    const [strict] = guardOpenAI(guard(), [new FunctionTool("refund.create")], { onRefused: "throw" });
    await expect(strict.invoke({}, JSON.stringify(big))).rejects.toBeInstanceOf(Denied);
    const [skipped] = guardOpenAI(guard(), [new FunctionTool("database.write")], { skip: ["database.write"] }); expect(await skipped.invoke({}, "{}")).toMatch(/^ran/);
  });
  it("LangChain.js: invoke(args | ToolCall) is verified and the prototype survives", async () => {
    class StructuredTool { name = "refund.create"; async invoke(input: unknown) { return { done: input }; } }
    const [t] = guardLangChain(guard(), [new StructuredTool()]);
    expect(t).toBeInstanceOf(StructuredTool);
    expect(await t.invoke(ok)).toEqual({ done: ok });
    expect(await t.invoke({ name: "refund.create", args: ok, id: "call_1", type: "tool_call" })).toEqual({ done: { name: "refund.create", args: ok, id: "call_1", type: "tool_call" } });
    expect(JSON.parse((await t.invoke({ name: "refund.create", args: big, id: "call_2" })) as unknown as string)).toMatchObject({ error: "denied" });
  });
  it("Vercel AI SDK: execute() is verified, client-side tools untouched, other properties kept", async () => {
    const tools = guardAi(guard(), { "refund.create": { description: "refund", execute: async (a: unknown) => ({ ran: a }) }, ui: { description: "client only" } });
    expect(tools.ui).toEqual({ description: "client only" }); expect(tools["refund.create"].description).toBe("refund");
    expect(await tools["refund.create"].execute!(ok)).toEqual({ ran: ok });
    expect(await tools["refund.create"].execute!(big)).toMatchObject({ error: "denied" });
  });
  it("Claude Agent SDK: PreToolUse answers allow / deny with evidence / ask for approvals; MCP names are parsed", async () => {
    const hook = preToolUse(createGuard({ world: demoWorld(), agent: "invoice-agent", actionPrefix: "", onApproval: "throw" }), { toolName: (n) => parseToolName(n).tool });
    expect(await hook({ tool_name: "mcp__billing__refund.create", tool_input: ok }, "tu_1")).toEqual({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow" } });
    const deny = await hook({ tool_name: "refund.create", tool_input: big }, "tu_2");
    expect(deny.decision).toBe("block"); expect(deny.hookSpecificOutput?.permissionDecision).toBe("deny"); expect(deny.reason).toMatch(/constraint_violated/); expect(deny.reason).toMatch(/✕ Request exceeds capability constraints/);
    const ask = await hook({ tool_name: "refund.create", tool_input: mid }, "tu_3");
    expect(ask.hookSpecificOutput).toMatchObject({ permissionDecision: "ask", permissionDecisionReason: expect.stringMatching(/human must approve/) });
    expect(parseToolName("mcp__my_server__list_issues")).toEqual({ server: "my_server", tool: "list_issues" }); expect(parseToolName("Bash")).toEqual({ server: null, tool: "Bash" });
    expect(await preToolUse(guard(), { skip: ["Read"] })({ tool_name: "Read", tool_input: {} }, "tu_4")).toEqual({});
  });
  it("refusal() re-throws anything that is not a guard refusal", () => { expect(() => refusal(new TypeError("boom"))).toThrow(TypeError); });
});
