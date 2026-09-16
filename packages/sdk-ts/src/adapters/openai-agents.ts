/**
 * OpenAI Agents SDK (JavaScript) — `@openai/agents`. Tools built with `tool({ name, execute })` expose
 * `invoke(runContext, input)`; the guarded copy verifies before the original runs. Type-only: the framework
 * is never imported, so this file loads without it.
 *
 *   import { guardTools } from "mnki-sdk/openai-agents";
 *   const agent = new Agent({ name: "invoice-agent", tools: guardTools(guard, [refundTool, lookupTool]) });
 */
import { guarded, parseJsonArgs, wanted, type AdapterOptions, type GuardLike } from "./shared";

/** The subset of `FunctionTool` the adapter relies on. */
export interface OpenAIAgentsTool { name: string; invoke: (runContext: unknown, input: string, ...rest: unknown[]) => Promise<unknown> }

export function guardTool<T extends OpenAIAgentsTool>(guard: GuardLike, tool: T, o: AdapterOptions = {}): T {
  if (!wanted(tool.name, o)) return tool;
  const name = o.toolName ? o.toolName(tool.name) : tool.name;
  const original = tool.invoke.bind(tool);
  const invoke: OpenAIAgentsTool["invoke"] = async (runContext, input, ...rest) => {
    const r = await guarded(guard, name, parseJsonArgs(input), () => original(runContext, input, ...rest), o);
    // A refusal is returned to the model as a JSON string, the shape every function tool result takes.
    return typeof r === "object" && r !== null && "error" in (r as object) && "reasons" in (r as object) ? JSON.stringify(r) : r;
  };
  return Object.assign(Object.create(Object.getPrototypeOf(tool) as object), tool, { invoke }) as T;
}
export const guardTools = <T extends OpenAIAgentsTool>(guard: GuardLike, tools: T[], o: AdapterOptions = {}): T[] => tools.map((t) => guardTool(guard, t, o));
