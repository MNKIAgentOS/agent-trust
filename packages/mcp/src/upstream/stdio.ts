/** A stdio MCP server as the upstream: spawn it, speak newline-delimited JSON on its stdin/stdout, pass its stderr through. */
import { spawn } from "node:child_process";
import { splitFrames, type Upstream } from "../proxy";

export function stdioUpstream(command: string, args: string[], env: NodeJS.ProcessEnv = process.env, stderr: NodeJS.WritableStream = process.stderr): Upstream {
  const child = spawn(command, args, { env, stdio: ["pipe", "pipe", "pipe"] });
  child.stderr.on("data", (d: Buffer) => stderr.write(d));
  let cb: ((frame: string) => void) | null = null; let buf = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => { buf += chunk; const { frames, rest } = splitFrames(buf); buf = rest; for (const f of frames) cb?.(f); });
  return {
    send: (frame) => { child.stdin.write(frame + "\n"); },
    onMessage: (fn) => { cb = fn; },
    close: () => new Promise<void>((resolve) => { child.once("exit", () => resolve()); child.stdin.end(); setTimeout(() => { child.kill(); resolve(); }, 1500).unref(); }),
  };
}
