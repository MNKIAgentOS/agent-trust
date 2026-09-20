/**
 * Contract between the Agent Trust control plane and the mobile apps (/api/mobile/*). The route handlers in
 * the control plane import these types, so the app and the server cannot drift without a type error.
 * Sessions: `Authorization: Bearer sess_….<hmac>` from POST /api/mobile/session; optional `x-agent-trust-org`.
 * Nothing here carries prices, checkout or billing links — plans are read-only in the apps.
 */
import type { Evidence } from "./index";
/** Re-exported so the app can import the whole contract from `mnki-sdk/mobile` alone. */
export type { Evidence };

export type DevicePlatform = "ios" | "android";
export type NotifyCategory = "denied" | "escalations" | "integrity" | "weekly_digest" | "quota" | "licence";
export type NotifyPrefs = Record<NotifyCategory, boolean>;

export interface DeviceRegistration {
  install_id: string; platform: DevicePlatform; name?: string | null; model?: string | null; os_version?: string | null; app_version?: string | null;
  push_token?: string | null; /** P-256 public key { kty: "EC", crv: "P-256", x, y } — the private half never leaves the Secure Enclave / Keystore. */ public_jwk: JsonWebKey;
  key_backing?: "hardware" | "software"; jailbroken?: boolean; notify_prefs?: Partial<NotifyPrefs> | null;
}
export interface Device { id: string; userId: string; installId: string; platform: DevicePlatform; name: string | null; model: string | null; osVersion: string | null; appVersion: string | null; pushEnabled: boolean; pushStatus: "unknown" | "ok" | "dead"; keyBacking: "hardware" | "software"; jailbroken: boolean; notifyPrefs: Partial<NotifyPrefs> | null; createdAt: string; lastSeenAt: string | null; revokedAt: string | null; current?: boolean }

export type MobileSessionGrant = { grant: "otp"; email: string; code: string; device?: DeviceRegistration } | { grant: "sso_code"; code: string; device?: DeviceRegistration };
export interface MobileSession { session: string; expires_at: string; device?: Device; me: MobileMe | null }

export interface Membership { orgId: string; name: string; role: "owner" | "admin" | "member" | "viewer"; active: boolean }
/** A promo code the organisation saved (from the phone or the web) for its next checkout in the web console. Terms only — never a price. */
export interface MobilePromo { code: string; name: string; description: string; saved_at: string; source: "web" | "ios" | "android" | "admin"; expires_at: string | null; plans: ("individual" | "team")[] | null; intervals: ("monthly" | "annual")[] | null; min_seats: number | null; valid: boolean; reason: string | null; detail: string | null }
export interface MobileMe {
  user: { id: string; email: string; name: string | null };
  org: { id: string; name: string; role: Membership["role"] | null };
  memberships: Membership[];
  plan: { tier: string; effective_tier: string; name: string; trial: { active: boolean; ends_at: string | null }; limits: { agents: number | null; verifications: number | null; members: number | null; retentionDays: number; trustDomains: number | null }; features: string[]; quota_exceeded_at: string | null;
    /** Charge/display currency ("eur" | "usd" | "gbp") and the list prices in it; absent on older servers. */
    currency?: string; prices?: { individual_monthly: number; individual_annual: number; team_monthly: number; team_annual: number; sso_monthly: number; sso_annual: number; overage_per_1000: number; enterprise_floor: number } };
  usage: { agents: number; verifications_30d: number; members: number; api_keys: number; trust_domains: number; period_start: string };
  notify: NotifyPrefs;
  platform_admin: boolean;
  stepped_up: boolean;
  device_id: string | null;
  console: { runtime: "node" | "cloudflare"; mobile_api: number; push_enabled: boolean };
  /** Saved promo code waiting for the next web checkout (owners and admins can add or remove it via /api/mobile/promo). Absent on consoles older than mobile_api 1 with promo support. */
  promo?: MobilePromo | null;
}

export interface MobileOverview {
  kpis: { agents_discovered: number; verified_trust: number; high_risk_flags: number; denied_actions_24h: number; pending: number; unowned: number };
  decisions_24h: { ALLOW: number; DENY: number; REQUIRE_APPROVAL: number };
  pending_approvals: number;
  risk_distribution: { low: number; medium: number; high: number; critical: number };
  feed: { id: string; agent_name: string | null; action: string; resource: string | null; decision: string; created_at: string }[];
  integrations: { id: string; kind: string; name: string; status: string; last_health_at: string | null }[];
}

export interface PendingApproval { id: string; decisionId: string; agentId: string | null; agentName: string | null; action: string; resource: string | null; summary: string | null; requestedAt: string; expiresAt: string | null }
export interface ApprovalDetail { id: string; decisionId: string; agentId: string | null; agentName: string | null; action: string; resource: string | null; summary: string | null; status: string; requestedAt: string; expiresAt: string | null; resolvedAt: string | null; reviewerId: string | null; reviewReason: string | null; amount: number | null; currency: string | null; requestHash: string | null; deviceId: string | null; deviceProofHash: string | null; proofHash: string | null }
export interface ChainStep { id: string; label: string; role: "Human" | "Agent" | "Leaf" }
export interface DecisionDetail { id: string; correlationId: string; agentId: string | null; agentName: string | null; action: string; resource: string | null; decision: string; latencyMs: number | null; createdAt: string; reasons: string[]; evidence: Evidence[]; policyVersionId: string | null; policyHash: string | null; chain: string[]; requestHash: string | null; approval: { id: string; status: string; reviewerEmail: string | null; reviewReason: string | null; resolvedAt: string | null; expiresAt?: string | null; proof?: string | null } | null; chainPath?: ChainStep[] }

/** What the device signs. Header { alg: "ES256", typ: "agent-trust-approval+jwt", kid: <device id> }; exp − iat ≤ 600. */
export interface ApprovalJwtPayload { iss: string; sub: string; jti: string; iat: number; exp: number; atp: { v: 1; decision_id: string; action: string; resource: string | null; maximum: number | null; currency: string | null; request_hash: string | null; approver: string; device: string; status: "approved" | "rejected"; reason: string } }
export interface MobileApproval { approval: ApprovalDetail; decision: DecisionDetail | null; chain_path: ChainStep[]; agent: { id: string; name: string; stable_id: string; risk_tier: string; lifecycle: string; owner: { id: string; name: string } | null } | null; signing: { typ: "agent-trust-approval+jwt"; alg: "ES256"; max_lifetime_s: number; claims: Omit<ApprovalJwtPayload, "iat" | "exp" | "atp"> & { atp: Omit<ApprovalJwtPayload["atp"], "status" | "reason" | "device"> & { device: string | null } } } }
export interface ApprovalResolved { status: "approved" | "rejected"; device_id: string; device_proof_hash: string | null; proof_hash: string | null }

/** Step-up: sign the challenge as { alg: "ES256", typ: "agent-trust-stepup+jwt", kid: <device id> } with exp − iat ≤ 600. */
export interface StepUpChallenge { challenge: string; expires_in: number; typ: "agent-trust-stepup+jwt"; alg: "ES256"; kid: string; claims: { iss: string; sub: string; jti: string; atp: { v: 1; purpose: "step_up" } } }
export interface StepUpJwtPayload { iss: string; sub: string; jti: string; iat: number; exp: number; atp: { v: 1; purpose: "step_up" } }

export interface GraphNode { id: string; type: "principal" | "organization" | "agent" | "resource" | "integration"; label: string; sublabel?: string; tone: "verified" | "warning" | "revoked" | "neutral"; href?: string; meta?: Record<string, string>; chips?: string[] }
export interface GraphEdge { id: string; source: string; target: string; label: string; tone: GraphNode["tone"] }
export interface MobileTrustGraph { nodes: GraphNode[]; edges: GraphEdge[]; truncated: boolean; layers: { depth: number; node_ids: string[] }[] }

/** Read-only policies for the app: what governs the organisation's agents, evaluated on every verification. Editing stays on the web console. */
export interface MobilePolicyRule { id: string; description?: string; effect: "allow" | "deny" | "require_approval"; match?: { action?: string | string[]; resource?: string; risk_tier?: string[]; agent_labels?: Record<string, string> }; conditions?: { kind: string; [k: string]: unknown }[] }
export interface MobilePolicy { id: string; name: string; description: string | null; status: string; version: number | null; versionId: string | null; hash: string | null; affectedAgents: number; updatedAt: string; rules: MobilePolicyRule[] }
export interface MobilePolicyVersion { id: string; version: number; hash: string; changeNote: string | null; createdByEmail: string | null; createdAt: string; activatedAt: string | null; ruleCount: number }
export interface MobilePolicyDetail extends MobilePolicy { default: "allow" | "deny" | "require_approval"; versions: MobilePolicyVersion[]; orgDefaults: MobilePolicyRule[] }
/** Passport links for an agent when its organisation and the agent opted in (private otherwise). */
export interface MobilePassport { public_id: string; url: string; badge_url: string; served: boolean }
export type PushKind = "approval" | "denied" | "integrity" | "quota" | "licence" | "lifecycle" | "test";
/** `data` of every push: the app opens `url` (agenttrust://approvals/<id>?org=…, decisions/<id>?org=…, alerts?org=…). */
export interface PushData { kind: PushKind; url: string; org_id: string; approval_id?: string; decision_id?: string; agent_id?: string }

/** Error codes the app maps to copy. Plan/feature refusals never carry prices or upgrade links. */
export type MobileErrorCode = "unauthenticated" | "rate_limited" | "org_suspended" | "read_only_impersonation" | "forbidden" | "step_up_required" | "sso_required" | "domain_not_allowed" | "invalid_code" | "expired" | "too_many_attempts" | "code_unknown" | "approval_jws_required" | "invalid_approval_jws" | "device_revoked" | "device_not_yours" | "approval_mismatch" | "not_pending" | "push_disabled" | "last_owner_with_members";
