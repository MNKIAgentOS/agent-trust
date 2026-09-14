/** Machine-readable constraints on a capability. Unknown keys are carried through and treated conservatively. */
export interface Constraints {
  max_value?: number;          // per-request ceiling
  max_total?: number;          // lifetime budget across allowed requests (tracked per delegation / agent + action + currency)
  currency?: string;
  region?: string[];
  [key: string]: unknown;
}

export interface Capability {
  action: string;              // e.g. "purchase.create"
  resource: string;            // exact ("supplier:123") or prefix glob ("supplier:*")
  constraints?: Constraints;
}

export type CapSet = Capability[];

export type DelegationStatus = "active" | "expired" | "revoked";

export interface Delegation {
  id: string;
  parent_id: string | null;
  subject_agent_id: string;
  capabilities: CapSet;
  constraints?: Constraints;
  not_before?: string | null;
  not_after?: string | null;
  status: DelegationStatus;
}

export type Decision = "ALLOW" | "DENY" | "REQUIRE_APPROVAL";
export type RiskTierName = "low" | "medium" | "high" | "critical";

export interface VerifyRequest {
  agent: string;
  action: string;
  resource?: string;
  principal?: string;
  delegation_id?: string;
  amount?: number;
  currency?: string;
  context?: Record<string, unknown>;
  /** Agent Authorization Attestation (compact JWS) presented with the request. */
  attestation?: string;
}
