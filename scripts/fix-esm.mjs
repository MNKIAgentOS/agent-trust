// tsc emits extensionless relative imports; Node ESM needs explicit ".js". Run after `tsc` on every dist/.
import { readdirSync, readFileSync, writeFileSync, statSync } from "node:fs";
import { join } from "node:path";
const walk = (d) => readdirSync(d).flatMap((f) => { const p = join(d, f); return statSync(p).isDirectory() ? walk(p) : p; });
import { existsSync } from "node:fs";
for (const pkg of ["verifier", "sdk-ts", "cli", "mcp"].filter((p) => existsSync(join("packages", p, "dist")))) {
  for (const f of walk(join("packages", pkg, "dist")).filter((p) => /\.(js|d\.ts)$/.test(p))) {
    const src = readFileSync(f, "utf8");
    const out = src.replace(/(from\s+["'])(\.\.?\/[^"']+?)(["'])/g, (m, a, spec, b) => (/\.(js|json)$/.test(spec) ? m : `${a}${spec}.js${b}`));
    if (out !== src) writeFileSync(f, out);
  }
}
