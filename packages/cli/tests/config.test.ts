import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import * as m from "../src/config";

// Paths are resolved at call time, so each case just sets the environment.
async function fresh(env: Record<string, string | undefined>) {
  for (const k of ["MNKI_HOME", "AGENTTRUST_HOME", "MNKI_URL", "MNKI_API_KEY", "MNKI_TELEMETRY"]) delete process.env[k];
  Object.assign(process.env, env);
  return m;
}

describe("mnki CLI config", () => {
  let home: string;
  beforeEach(() => { home = mkdtempSync(join(tmpdir(), "mnki-cfg-")); });
  afterEach(() => { rmSync(home, { recursive: true, force: true }); });

  it("lives in $MNKI_HOME/config.json and survives a save/load round-trip with 0600", async () => {
    const m = await fresh({ MNKI_HOME: home });
    expect(m.configPath()).toBe(join(home, "config.json"));
    expect(m.loadConfig()).toBeNull();
    m.saveConfig({ baseUrl: "https://staging.mnki.com", apiKey: "at_verify_x", identities: {} });
    expect(m.loadConfig()).toMatchObject({ baseUrl: "https://staging.mnki.com", apiKey: "at_verify_x" });
  });
  it("copies a legacy ~/.agenttrust/config.json once", async () => {
    const legacyHome = mkdtempSync(join(tmpdir(), "legacy-"));
    mkdirSync(join(legacyHome, ".agenttrust"), { recursive: true });
    writeFileSync(join(legacyHome, ".agenttrust", "config.json"), JSON.stringify({ baseUrl: "https://old", apiKey: "at_old", identities: { agt_1: { v: 1 } } }));
    const m = await fresh({ MNKI_HOME: home, AGENTTRUST_HOME: legacyHome });
    expect(m.loadConfig()).toMatchObject({ baseUrl: "https://old", identities: { agt_1: { v: 1 } } });
    expect(existsSync(join(home, "config.json"))).toBe(true);
    // a later edit of the new file is not overwritten by the legacy one
    writeFileSync(join(home, "config.json"), JSON.stringify({ baseUrl: "https://new", apiKey: "at_new", identities: {} }));
    expect(JSON.parse(readFileSync(join(home, "config.json"), "utf8")).baseUrl).toBe("https://new");
    expect(m.loadConfig()?.baseUrl).toBe("https://new");
    rmSync(legacyHome, { recursive: true, force: true });
  });
  it("environment overrides win and are never persisted; telemetry honours MNKI_TELEMETRY=0", async () => {
    const m = await fresh({ MNKI_HOME: home, MNKI_URL: "https://env.mnki.com", MNKI_API_KEY: "at_env" });
    expect(m.loadConfig()).toMatchObject({ baseUrl: "https://env.mnki.com", apiKey: "at_env" });
    expect(existsSync(join(home, "config.json"))).toBe(false);
    expect(m.telemetryEnabled({ baseUrl: "", apiKey: "", identities: {} })).toBe(true);
    expect(m.telemetryEnabled({ baseUrl: "", apiKey: "", identities: {}, telemetry: false })).toBe(false);
    process.env.MNKI_TELEMETRY = "0"; expect(m.telemetryEnabled(null)).toBe(false); delete process.env.MNKI_TELEMETRY;
  });
});
