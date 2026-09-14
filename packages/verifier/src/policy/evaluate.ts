import { resourceContains } from "../delegation/attenuate";
import type { Condition, Effect, PolicyDoc, PolicyInput, PolicyOutcome, Rule } from "./schema";

const RANK: Record<Effect, number> = { allow: 0, require_approval: 1, deny: 2 };

function actionMatches(pattern: string | string[] | undefined, action: string): boolean {
  if (pattern === undefined) return true;
  const list = Array.isArray(pattern) ? pattern : [pattern];
  return list.some((p) => (p.endsWith("*") ? action.startsWith(p.slice(0, -1)) : p === action));
}

function minutesUTC(d: Date) { return d.getUTCHours() * 60 + d.getUTCMinutes(); }
function parseHM(s: string) { const [h, m] = s.split(":").map(Number); return (h || 0) * 60 + (m || 0); }

export function conditionHolds(c: Condition, i: PolicyInput): boolean {
  switch (c.kind) {
    case "amount_lte": return i.amount !== undefined && i.amount <= c.value;
    case "amount_gt": return i.amount !== undefined && i.amount > c.value;
    case "currency_in": return i.currency !== undefined && c.values.includes(i.currency);
    case "region_in": return i.region !== undefined && c.values.includes(i.region);
    case "requires_attestation": return c.attestation ? i.attestations.includes(c.attestation) : i.attestations.length > 0;
    case "missing_attestation": return c.attestation ? !i.attestations.includes(c.attestation) : i.attestations.length === 0;
    case "delegation_depth_lte": return i.delegation_depth <= c.value;
    case "delegation_depth_gt": return i.delegation_depth > c.value;
    case "time_window": {
      const t = minutesUTC(i.time), a = parseHM(c.start), b = parseHM(c.end);
      return a <= b ? t >= a && t < b : t >= a || t < b;          // window may wrap midnight
    }
    default: return false;                                          // unknown condition never holds
  }
}

export function ruleMatches(r: Rule, i: PolicyInput): boolean {
  const m = r.match;
  if (!m) return true;
  if (!actionMatches(m.action, i.action)) return false;
  if (m.resource !== undefined && (i.resource === undefined || !resourceContains(m.resource, i.resource))) return false;
  if (m.risk_tier && !m.risk_tier.includes(i.risk_tier)) return false;
  if (m.agent_labels && !Object.entries(m.agent_labels).every(([k, v]) => i.agent_labels[k] === v)) return false;
  return true;
}

/** Deterministic: same doc + input + clock ⇒ same outcome. No I/O. */
export function evaluate(doc: PolicyDoc, input: PolicyInput): PolicyOutcome {
  const fired: string[] = []; const reasons: string[] = [];
  let effect: Effect | null = null;
  for (const r of doc.rules) {
    if (!ruleMatches(r, input)) continue;
    if (!(r.conditions ?? []).every((c) => conditionHolds(c, input))) continue;
    fired.push(r.id); reasons.push(`policy:${r.id}:${r.effect}`);
    if (effect === null || RANK[r.effect] > RANK[effect]) effect = r.effect;
  }
  if (effect === null) { effect = doc.default ?? "allow"; reasons.push(`policy:default:${effect}`); }
  return { effect, fired, reasons };
}

/** Dry-run a draft against many inputs — the console's policy simulator. */
export function simulate(doc: PolicyDoc, inputs: PolicyInput[]): PolicyOutcome[] {
  return inputs.map((i) => evaluate(doc, i));
}
