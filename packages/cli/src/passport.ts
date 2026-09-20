/**
 * `mnki passport publish|unpublish <agent-id>` — flips the agent's public passport flag through the console endpoint
 * (POST /api/agents/{id}/public, admin-scope key). The organisation's own opt-in (Settings → Security) still decides
 * whether anything is served; the result says so instead of pretending.
 */
export interface PassportResult { status?: string; public_id?: string | null; is_public?: boolean; org_opted_in?: boolean; served?: boolean; passport_url?: string | null; badge_url?: string | null; error?: string }

/** The one line `mnki identity create` prints after registering an agent. */
export const publishHint = (agentId: string): string => `Publish a public passport for this agent: mnki passport publish ${agentId}`;

export async function setPassport(c: { baseUrl: string; apiKey: string }, agentId: string, isPublic: boolean, fetcher: typeof fetch = fetch): Promise<PassportResult> {
  if (!/^agt_[A-Za-z0-9_-]+$/.test(agentId)) throw new Error(`usage: mnki passport ${isPublic ? "publish" : "unpublish"} <agent id>   (ids look like agt_…)`);
  const res = await fetcher(`${c.baseUrl.replace(/\/+$/, "")}/api/agents/${encodeURIComponent(agentId)}/public`, { method: "POST", headers: { authorization: `Bearer ${c.apiKey}`, "content-type": "application/json" }, body: JSON.stringify({ public: isPublic }) });
  const j = (await res.json().catch(() => ({}))) as PassportResult;
  if (res.status === 409 && j.error === "unchanged") return { status: "unchanged", is_public: isPublic };
  if (!res.ok) throw new Error(`passport ${isPublic ? "publish" : "unpublish"} refused: ${j.error ?? res.status}${res.status === 403 ? " (needs an admin-scope key)" : res.status === 404 ? " (no such agent in this organisation)" : ""}`);
  return j;
}

/** Human output for the command; `--json` callers print the raw result instead. */
export function formatPassportResult(agentId: string, isPublic: boolean, r: PassportResult): string {
  if (r.status === "unchanged") return `Passport of ${agentId} was already ${isPublic ? "public" : "private"}.`;
  if (!isPublic) return `Passport of ${agentId} is private again. The public page, badge and A2A card answer 404 within five minutes.`;
  const lines = [`Passport of ${agentId} published.`];
  if (r.passport_url) lines.push(`  passport  ${r.passport_url}`);
  if (r.badge_url) lines.push(`  badge     ${r.badge_url}`, `  markdown  [![Agent Trust passport](${r.badge_url})](${r.passport_url})`);
  if (r.org_opted_in === false) lines.push(`Not served yet: public passports are off for your organisation. Enable them under Settings → Security in the console.`);
  return lines.join("\n");
}
