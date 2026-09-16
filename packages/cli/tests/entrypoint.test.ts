import { describe, it, expect } from "vitest";
import { pathToFileURL } from "node:url";
import { isEntrypoint } from "../src/main";
import { isEntrypoint as isMcpEntrypoint } from "../../mcp/src/main";

/** `npx mnki-cli` runs the bin named after the package; before this the guard only knew `mnki`, so the CLI exited silently. */
describe("entry-point detection across bin names", () => {
  const self = new URL("../src/main.ts", import.meta.url);
  for (const [name, fn] of [["cli", isEntrypoint], ["mcp", isMcpEntrypoint]] as const) {
    it(`${name}: recognises the real file, every bin name, and nothing else`, () => {
      expect(fn(undefined, self.href)).toBe(false);
      // A real path that resolves to this module.
      expect(isEntrypoint(new URL("../src/main.ts", import.meta.url).pathname, pathToFileURL(new URL("../src/main.ts", import.meta.url).pathname).href)).toBe(true);
      // Bin symlinks that cannot be resolved here fall back to the name list.
      for (const bin of ["/tmp/x/node_modules/.bin/mnki", "/tmp/x/node_modules/.bin/mnki-cli", "/tmp/x/node_modules/.bin/agenttrust", "/tmp/x/node_modules/.bin/mnki-mcp", "/usr/local/lib/node_modules/mnki-cli/dist/main.js"]) expect(fn(bin, self.href), bin).toBe(true);
      for (const other of ["/tmp/x/node_modules/.bin/vitest", "/tmp/x/other.js", "/tmp/mnki-something"]) expect(fn(other, self.href), other).toBe(false);
    });
  }
});
