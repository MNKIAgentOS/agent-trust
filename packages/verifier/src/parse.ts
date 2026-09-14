import type { VerifyRequest } from "./types";

export type ParseResult =
  | { ok: true; request: VerifyRequest }
  | { ok: false; code: "not_object" | "agent" | "action" | "resource" | "principal" | "delegation_id" | "amount" | "currency" | "context" | "attestation" };

const nonEmpty = (v: unknown): v is string => typeof v === "string" && v.trim().length > 0 && v.length <= 512;
const optStr = (v: unknown): boolean => v === undefined || nonEmpty(v);

/** Validate an untrusted verify request. Never throws; unknown keys are dropped. */
export function parseVerifyRequest(input: unknown): ParseResult {
  if (input === null || typeof input !== "object" || Array.isArray(input)) return { ok: false, code: "not_object" };
  const o = input as Record<string, unknown>;
  if (!nonEmpty(o.agent)) return { ok: false, code: "agent" };
  if (!nonEmpty(o.action)) return { ok: false, code: "action" };
  if (!optStr(o.resource)) return { ok: false, code: "resource" };
  if (!optStr(o.principal)) return { ok: false, code: "principal" };
  if (!optStr(o.delegation_id)) return { ok: false, code: "delegation_id" };
  if (o.amount !== undefined && !(typeof o.amount === "number" && Number.isFinite(o.amount) && o.amount >= 0)) return { ok: false, code: "amount" };
  if (o.currency !== undefined && !(typeof o.currency === "string" && /^[A-Z]{3}$/.test(o.currency))) return { ok: false, code: "currency" };
  if (o.attestation !== undefined && !(typeof o.attestation === "string" && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(o.attestation) && o.attestation.length <= 16384)) return { ok: false, code: "attestation" };
  if (o.context !== undefined && (o.context === null || typeof o.context !== "object" || Array.isArray(o.context))) return { ok: false, code: "context" };
  const request: VerifyRequest = { agent: (o.agent as string).trim(), action: (o.action as string).trim() };
  if (o.resource !== undefined) request.resource = (o.resource as string).trim();
  if (o.principal !== undefined) request.principal = (o.principal as string).trim();
  if (o.delegation_id !== undefined) request.delegation_id = (o.delegation_id as string).trim();
  if (o.amount !== undefined) request.amount = o.amount as number;
  if (o.currency !== undefined) request.currency = o.currency as string;
  if (o.context !== undefined) request.context = o.context as Record<string, unknown>;
  if (o.attestation !== undefined) request.attestation = o.attestation as string;
  return { ok: true, request };
}
