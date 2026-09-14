import type { CapSet, Capability, Constraints } from "../types";

/** "supplier:*" → "supplier:", exact resources → null. Only a trailing "*" is a glob. */
function globPrefix(resource: string): string | null {
  return resource.endsWith("*") ? resource.slice(0, -1) : null;
}

/** Does the parent resource pattern cover the child pattern? */
export function resourceContains(parent: string, child: string): boolean {
  if (parent === child) return true;
  const pp = globPrefix(parent);
  if (pp === null) return false;                       // an exact parent covers only itself
  const cp = globPrefix(child);
  return (cp ?? child).startsWith(pp);                 // child (or its glob prefix) sits under the parent prefix
}

/**
 * Are the child's constraints at least as tight as the parent's?
 * - numeric limits (max_value): child must carry one, and it must not exceed the parent's
 * - currency: must match when the parent fixes it
 * - region: child set must be a subset when the parent restricts it
 * - any other parent key: child must carry an identical value (conservative)
 * The child may add constraint keys the parent lacks (that only tightens).
 */
export function constraintsTighter(parent: Constraints | undefined, child: Constraints | undefined): boolean {
  if (!parent) return true;
  const c = child ?? {};
  for (const key of Object.keys(parent)) {
    const p = parent[key];
    if (p === undefined) continue;
    if (key === "max_value" || key === "max_total") {
      const cv = c[key];
      if (typeof cv !== "number" || !(cv <= (p as number))) return false;
    } else if (key === "region") {
      const pr = new Set(p as string[]);
      const cr = c.region;
      if (!Array.isArray(cr) || cr.length === 0 || !cr.every((r) => pr.has(r))) return false;
    } else if (JSON.stringify(c[key]) !== JSON.stringify(p)) {
      return false;
    }
  }
  return true;
}

/** Is `child` capability covered by `parent` capability? */
export function capabilityCovered(parent: Capability, child: Capability): boolean {
  return parent.action === child.action
    && resourceContains(parent.resource, child.resource)
    && constraintsTighter(parent.constraints, child.constraints);
}

/** Every child capability is covered by some parent capability. */
export function isSubset(child: CapSet, parent: CapSet): boolean {
  return child.every((c) => parent.some((p) => capabilityCovered(p, c)));
}

/**
 * Attenuate: keep only the requested capabilities the parent actually covers.
 * By construction `isSubset(attenuate(parent, requested), parent)` always holds,
 * and the result never contains anything absent from `requested`.
 */
export function attenuate(parent: CapSet, requested: CapSet): CapSet {
  return requested.filter((c) => parent.some((p) => capabilityCovered(p, c)));
}
