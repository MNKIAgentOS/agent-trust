/**
 * LangChain.js / LangGraph.js — `@langchain/core` tools (`tool()`, `StructuredTool`, `DynamicStructuredTool`).
 * `invoke(input, config)` is verified before the original tool runs; the returned object keeps the tool's
 * prototype so `ToolNode`, `bindTools` and schema introspection see an ordinary tool.
 *
 *   import { guardTools } from "mnki-sdk/langchain";
 *   const node = new ToolNode(guardTools(guard, [refund, lookup]));
 */
import { guarded, wanted, type AdapterOptions, type GuardLike } from "./shared";

export interface LangChainTool { name: string; invoke: (input: unknown, config?: unknown) => Promise<unknown> }

/** LangChain hands a ToolCall (`{ name, args, id }`) or the raw args; verify against the args either way. */
const argsOf = (input: unknown): unknown => (input && typeof input === "object" && "args" in (input as object) && "name" in (input as object) ? (input as { args: unknown }).args : input ?? {});

export function guardTool<T extends LangChainTool>(guard: GuardLike, tool: T, o: AdapterOptions = {}): T {
  if (!wanted(tool.name, o)) return tool;
  const name = o.toolName ? o.toolName(tool.name) : tool.name;
  const original = tool.invoke.bind(tool);
  const invoke: LangChainTool["invoke"] = (input, config) => guarded(guard, name, argsOf(input), () => original(input, config), o).then((r) => (isRefusal(r) ? JSON.stringify(r) : r));
  return Object.assign(Object.create(Object.getPrototypeOf(tool) as object), tool, { invoke }) as T;
}
const isRefusal = (r: unknown): boolean => !!r && typeof r === "object" && "error" in (r as object) && "reasons" in (r as object) && Array.isArray((r as { reasons: unknown }).reasons);
export const guardTools = <T extends LangChainTool>(guard: GuardLike, tools: T[], o: AdapterOptions = {}): T[] => tools.map((t) => guardTool(guard, t, o));
