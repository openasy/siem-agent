// What siem may ask, and how the agent does it. siem is not trusted here (ADR 0031): every job is checked before
// anything connects, the script is the one built into the agent, the values put before it are checked to be what
// they claim, and certificates are always for the openasy principal. A compromised siem cannot run commands of its
// own on any host.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseRead, type Event } from "./events.ts";
import { runScript, scanHostKey, SshError, type Credential, type Endpoint, type SshFailure } from "./ssh.ts";

export const READ_SCRIPT = readFileSync(new URL("./read.sh", import.meta.url), "utf8");
/** Journal entries in one read. A host with more is read again at once; siem takes up to 10 000 in one result. */
export const MAX_LINES = 5_000;
/** Where the first read of a host starts. */
const FIRST_READ_MS = 10 * 60_000;

export interface Job {
  id: string;
  hostId: string;
  action: "read" | "host-key";
  /** keyFile: a private key in the agent's key folder, for auth key; without it, the agent's own key. */
  target: Endpoint & { auth: "certificate" | "key"; keyFile?: string };
  cursor: { journal: string | null };
}

export type Result =
  | {
      jobId: string;
      hostId: string;
      ok: true;
      events: Event[];
      cursor: { journal: string | null };
      more: boolean;
      unreadable: string[];
    }
  | { jobId: string; hostId: string; ok: true; hostKeys: string[] }
  | { jobId: string; hostId: string; ok: false; error: { kind: SshFailure | "invalid-job"; message: string }; hostKeys?: string[] };

// The same rules siem applies, checked again: nothing ssh or the shell could read as an option or a command.
const ADDRESS = /^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$|^\[[0-9a-fA-F:]+\]$/;
const USER = /^[a-z_][a-z0-9_-]{0,31}$/;
// A file name in the key folder: no slash, so it never leaves the folder, and no leading dot.
const KEY_FILE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const HOST_KEY = /^(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|ssh-rsa|sk-ssh-ed25519@openssh\.com) [A-Za-z0-9+/]+={0,2}$/;
const CURSOR = /^[a-z]=[0-9a-f]+(;[a-z]=[0-9a-f]+){0,7}$/;

/** Throws when siem sent something the agent will not do. */
export function checkJob(raw: unknown): Job {
  const j = raw as Partial<Job> | null;
  if (!j || typeof j !== "object" || typeof j.id !== "string" || typeof j.hostId !== "string") throw new Error("a job needs an id and a host id");
  if (j.action !== "read" && j.action !== "host-key") throw new Error("action is read or host-key");
  const t = j.target as Partial<Job["target"]> | undefined;
  if (!t || typeof t !== "object") throw new Error("target is missing");
  if (typeof t.address !== "string" || !ADDRESS.test(t.address)) throw new Error("target: address is not a host name or IP address");
  if (typeof t.port !== "number" || !Number.isInteger(t.port) || t.port < 1 || t.port > 65535) throw new Error("target: port is not 1 to 65535");
  if (typeof t.user !== "string" || !USER.test(t.user)) throw new Error("target: user is not a Unix account name");
  if (!Array.isArray(t.hostKeys) || t.hostKeys.length > 8 || t.hostKeys.some((k) => typeof k !== "string" || !HOST_KEY.test(k)))
    throw new Error("target: host keys are not OpenSSH public keys");
  if (t.auth !== "certificate" && t.auth !== "key") throw new Error("target: auth is certificate or key");
  if (t.keyFile !== undefined && (typeof t.keyFile !== "string" || !KEY_FILE.test(t.keyFile))) throw new Error("target: keyFile is a file name");
  if (t.keyFile !== undefined && t.auth !== "key") throw new Error("target: keyFile needs auth key");
  const c = (j.cursor ?? { journal: null }) as Partial<Job["cursor"]>;
  if (c.journal != null && (typeof c.journal !== "string" || !CURSOR.test(c.journal))) throw new Error("cursor: journal is not a journalctl cursor");
  return {
    id: j.id,
    hostId: j.hostId,
    action: j.action,
    target: {
      address: t.address,
      port: t.port,
      user: t.user,
      hostKeys: t.hostKeys,
      auth: t.auth,
      ...(t.keyFile !== undefined && { keyFile: t.keyFile }),
    },
    cursor: { journal: c.journal ?? null },
  };
}

/** The script with its variables before it. Every value was checked by checkJob or made here. */
export function scriptFor(job: Job, now = Date.now()): string {
  const first = new Date(now - FIRST_READ_MS);
  const vars = [`OPENASY_CURSOR='${job.cursor.journal ?? ""}'`, `OPENASY_SINCE='${Math.floor(first.getTime() / 1000)}'`, `OPENASY_MAX='${MAX_LINES}'`];
  return `${vars.join("\n")}\n${READ_SCRIPT}`;
}

export interface Transport {
  runScript: typeof runScript;
  scanHostKey: typeof scanHostKey;
}

/** The certificate, the agent's own key, or a key file the install put in the key folder; what is in it never leaves here. */
function credential(job: Job, keys: { caPrivateKey: string; keyPrivateKey: string }, keyDir: string): Credential {
  if (job.target.auth === "certificate") return { mode: "certificate", caPrivateKey: keys.caPrivateKey };
  if (job.target.keyFile === undefined) return { mode: "key", privateKey: keys.keyPrivateKey };
  let key: string;
  try {
    key = readFileSync(join(keyDir, job.target.keyFile), "utf8");
  } catch {
    throw new Error(`key file ${job.target.keyFile} is not readable in ${keyDir}`);
  }
  if (!/^-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(key.trimStart())) throw new Error(`key file ${job.target.keyFile} is not a private key`);
  // ssh refuses a key file without a final newline, as an editor may save it.
  return { mode: "key", privateKey: key.endsWith("\n") ? key : `${key}\n` };
}

export async function runJob(
  raw: unknown,
  keys: { caPrivateKey: string; keyPrivateKey: string },
  transport: Transport = { runScript, scanHostKey },
  keyDir = process.env.OPENASY_KEYS_DIR ?? "/keys",
): Promise<Result> {
  let job: Job;
  try {
    job = checkJob(raw);
  } catch (err) {
    const r = raw as { id?: unknown; hostId?: unknown } | null;
    return { jobId: String(r?.id ?? ""), hostId: String(r?.hostId ?? ""), ok: false, error: { kind: "invalid-job", message: (err as Error).message } };
  }
  const base = { jobId: job.id, hostId: job.hostId };
  let cred: Credential;
  try {
    cred = credential(job, keys, keyDir);
  } catch (err) {
    return { ...base, ok: false, error: { kind: "auth-failed", message: (err as Error).message } };
  }
  try {
    if (job.action === "host-key") return { ...base, ok: true, hostKeys: await transport.scanHostKey(job.target, cred) };
    const out = await transport.runScript(job.target, cred, scriptFor(job));
    return { ...base, ok: true, ...parseRead(out, MAX_LINES, job.cursor) };
  } catch (err) {
    const e = err instanceof SshError ? err : new SshError("error", err instanceof Error ? err.message : String(err));
    // A changed key: say which key the host presents now, so an admin can compare it.
    const hostKeys = e.kind === "host-key-changed" ? await transport.scanHostKey(job.target, cred).catch(() => undefined) : undefined;
    return { ...base, ok: false, error: { kind: e.kind, message: e.message }, ...(hostKeys && { hostKeys }) };
  }
}
