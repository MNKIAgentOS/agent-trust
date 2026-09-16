/**
 * Vercel AI SDK — `ai`. Tools are `{ [name]: { description, inputSchema, execute } }`; the guarded set keeps
 * every property and verifies before `execute`. Tools without `execute` (client-side tools) are left as-is.
 *
 *   import { guardTools } from "mnki-sdk/ai";
 *   generateText({ model, tools: guardTools(guard, { refund, lookup }), prompt });
 */
import { guarded, wanted, type AdapterOptions, type GuardLike } from "./shared";

export interface AiTool { execute?: (args: unknown, options?: unknown) => unknown | Promise<unknown>; [k: string]: unknown }

export function guardTools<T extends Record<string, AiTool>>(guard: GuardLike, tools: T, o: AdapterOptions = {}): T {
  const out: Record<string, AiTool> = {};
  for (const [name, tool] of Object.entries(tools)) {
    if (!wanted(name, o) || typeof tool.execute !== "function") { out[name] = tool; continue; }
    const original = tool.execute.bind(tool); const verifiedName = o.toolName ? o.toolName(name) : name;
    out[name] = { ...tool, execute: (args: unknown, options?: unknown) => guarded(guard, verifiedName, args ?? {}, async () => original(args, options), o) };
  }
  return out as T;
}
