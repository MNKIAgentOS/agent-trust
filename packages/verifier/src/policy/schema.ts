import type { RiskTierName } from "../types";

/**
 * Policy document — understandable without reading code. Rules match a
 * request; when every condition holds the rule "fires" with its effect.
 * Precedence across fired rules: deny > require_approval > allow.
 * `default` applies when nothing fires. Authority itself (capabilities /
 * delegation) is checked before policy and is default-deny; policy narrows.
 */
export type Effect = "allow" | "deny" | "require_approval";

export type Condition =
  | { kind: "amount_lte"; value: number }
  | { kind: "amount_gt"; value: number }
  | { kind: "currency_in"; values: string[] }
  | { kind: "region_in"; values: string[] }
  | { kind: "requires_attestation"; attestation?: string }
  | { kind: "missing_attestation"; attestation?: string }   // holds when NO (matching) verified attestation is present
  | { kind: "delegation_depth_lte"; value: number }
  | { kind: "delegation_depth_gt"; value: number }
  | { kind: "time_window"; start: string; end: string };   // "HH:MM"–"HH:MM" UTC

export interface RuleMatch {
  action?: string | string[];            // exact, or trailing-* prefix
  resource?: string;                     // exact, or trailing-* prefix
  risk_tier?: RiskTierName[];
  agent_labels?: Record<string, string>; // all must be present and equal
}

export interface Rule {
  id: string;
  description?: string;
  match?: RuleMatch;                     // omitted = matches everything
  conditions?: Condition[];              // omitted = always
  effect: Effect;
}

export interface PolicyDoc {
  version: 1;
  default?: Effect;                      // default "allow" (authority is already default-deny)
  rules: Rule[];
}

export interface PolicyInput {
  action: string;
  resource?: string;
  amount?: number;
  currency?: string;
  region?: string;
  risk_tier: RiskTierName;
  agent_labels: Record<string, string>;
  delegation_depth: number;              // 0 = direct authority, n = chain length
  attestations: string[];                // verified attestation kinds present
  time: Date;
}

export interface PolicyOutcome {
  effect: Effect;
  fired: string[];                       // rule ids that fired, in document order
  reasons: string[];                     // machine-readable
}

/** Runtime check for untrusted policy JSON. Never throws. */
export function parsePolicyDoc(input: unknown): { ok: true; doc: PolicyDoc } | { ok: false; error: string } {
  if (!input || typeof input !== "object") return { ok: false, error: "not_object" };
  const o = input as Record<string, unknown>;
  if (o.version !== 1) return { ok: false, error: "version" };
  if (!Array.isArray(o.rules)) return { ok: false, error: "rules" };
  const effects = new Set(["allow", "deny", "require_approval"]);
  if (o.default !== undefined && !effects.has(o.default as string)) return { ok: false, error: "default" };
  for (const [i, r] of (o.rules as unknown[]).entries()) {
    if (!r || typeof r !== "object") return { ok: false, error: `rules[${i}]` };
    const rule = r as Record<string, unknown>;
    if (typeof rule.id !== "string" || !rule.id) return { ok: false, error: `rules[${i}].id` };
    if (!effects.has(rule.effect as string)) return { ok: false, error: `rules[${i}].effect` };
    if (rule.conditions !== undefined && !Array.isArray(rule.conditions)) return { ok: false, error: `rules[${i}].conditions` };
  }
  return { ok: true, doc: input as PolicyDoc };
}
