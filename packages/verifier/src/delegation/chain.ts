import type { CapSet, Delegation } from "../types";
import { attenuate } from "./attenuate";

export const MAX_CHAIN_DEPTH = 8;

export type ChainResult =
  | { ok: true; chain: Delegation[] }                                    // root → leaf
  | { ok: false; reason: "missing" | "cycle" | "depth"; at: string };

/** Walk parent links from the leaf to the root. Bounded, cycle-safe, never throws. */
export function resolveChain(
  leafId: string,
  get: (id: string) => Delegation | undefined,
  opts: { maxDepth?: number } = {},
): ChainResult {
  const maxDepth = opts.maxDepth ?? MAX_CHAIN_DEPTH;
  const seen = new Set<string>();
  const chain: Delegation[] = [];
  let cursor: string | null = leafId;
  while (cursor !== null) {
    if (seen.has(cursor)) return { ok: false, reason: "cycle", at: cursor };
    if (chain.length >= maxDepth) return { ok: false, reason: "depth", at: cursor };
    const d = get(cursor);
    if (!d) return { ok: false, reason: "missing", at: cursor };
    seen.add(cursor);
    chain.push(d);
    cursor = d.parent_id;
  }
  return { ok: true, chain: chain.reverse() };
}

/** A link confers authority only while active and inside its validity window. */
export function linkValidAt(d: Delegation, now: Date): boolean {
  if (d.status !== "active") return false;
  const t = now.getTime();
  if (d.not_before && t < Date.parse(d.not_before)) return false;
  if (d.not_after && t >= Date.parse(d.not_after)) return false;
  return true;
}

/**
 * Effective authority of the leaf = the root's capabilities attenuated through
 * every link. Any invalid link anywhere in the chain yields no authority.
 */
export function computeEffectiveAuthority(chain: Delegation[], now: Date): CapSet {
  if (chain.length === 0) return [];
  if (!chain.every((d) => linkValidAt(d, now))) return [];
  let effective: CapSet = chain[0].capabilities;
  for (let i = 1; i < chain.length; i++) effective = attenuate(effective, chain[i].capabilities);
  return effective;
}
