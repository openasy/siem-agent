// What read.sh prints, as flat events for siem, with where the next read starts (ADR 0040). The messages security
// rules care about most (sshd, sudo, su and account changes) are also read into fields such as user, src_ip and
// outcome, so a correlation can group by them. Values that look like passwords, tokens or keys are masked here, so they
// never leave the host's network (ADR 0031).

export type Event = Record<string, string | number | boolean>;

export interface Read {
  events: Event[];
  cursor: { journal: string | null };
  /** The journal had more than one read takes: read again at once. */
  more: boolean;
  /** What the account may not read, in words for the screens. */
  unreadable: string[];
}

/** The same patterns as Logs' mask-secrets step (logs/server/pipeline.ts) and logs-agent: change them together. */
export const SECRET_PATTERNS: Array<[RegExp, string]> = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g, "[private key masked]"],
  [/\b(authorization|proxy-authorization)(["']?\s*[:=]\s*["']?)(bearer|basic|token|apikey)?\s*[A-Za-z0-9._~+/=-]{8,}/gi, "$1$2$3 ***"],
  [/\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key)(["']?\s*[:=]\s*["']?)[^\s"'&,;]{3,}/gi, "$1$2***"],
  [/\b(AKIA|ASIA)[A-Z0-9]{16}\b/g, "$1****************"],
  [/\b(gh[pousr]_)[A-Za-z0-9]{30,}\b/g, "$1***"],
  [/\b(xox[abprs]-)[A-Za-z0-9-]{10,}/g, "$1***"],
  [/\b(sk_live_|rk_live_)[A-Za-z0-9]{10,}/g, "$1***"],
  [/(:\/\/[^:/\s@]+:)[^@/\s]{1,}@/g, "$1***@"],
];

export function mask(s: string): string {
  let out = s;
  for (const [re, repl] of SECRET_PATTERNS) out = out.replace(re, repl);
  return out;
}

/** siem keeps values of up to 4096 characters; a longer message is cut and says so. */
const MAX_VALUE = 4000;
/** What journalctl says when the account sees only its own journal, or none of it. */
const PARTIAL_JOURNAL =
  /^Hint: You are currently not seeing messages from other users and the system|^No journal files were opened due to insufficient permissions/;
const LEVELS = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"];

/** journald fields kept, under the names siem's rules use. */
const JOURNAL_FIELDS: Record<string, string> = {
  _COMM: "process",
  _EXE: "exe",
  _PID: "pid",
  _UID: "uid",
  _SYSTEMD_UNIT: "unit",
  _TRANSPORT: "transport",
  SYSLOG_FACILITY: "facility",
};

/** MESSAGE is a string, or an array of bytes when it is not valid UTF-8. */
function text(v: unknown): string {
  if (typeof v === "string") return v;
  if (Array.isArray(v) && v.every((b) => typeof b === "number")) return Buffer.from(v as number[]).toString("utf8");
  return v === undefined || v === null ? "" : JSON.stringify(v);
}

const cut = (s: string) => (s.length > MAX_VALUE ? `${s.slice(0, MAX_VALUE)}…` : s);

const SSH_FAILED = /^Failed (\S+) for (invalid user )?(\S*) from (\S+) port (\d+)/;
const SSH_ACCEPTED = /^Accepted (\S+) for (\S+) from (\S+) port (\d+)/;
const SSH_INVALID = /^Invalid user (\S*) from (\S+) port (\d+)/;
const SUDO = /^\s*(\S+) : (?:(.*?) ; )?TTY=(\S+) ; PWD=(.*?) ; USER=(\S+) ; (?:.*?; )?COMMAND=(.*)$/;
const SU = /^(FAILED SU )?\(to (\S+)\) (\S+) on (\S+)/;
const USERADD = /^new user: name=([^,\s]+)/;
const USERDEL = /^delete user '([^']+)'/;
const USERMOD = /^(?:change user '([^']+)'|add '([^']+)' to (?:shadow )?group '([^']+)')/;
const GROUPADD = /^new group: name=([^,\s]+)/;
const PASSWD = /^password changed for (\S+)/;

/**
 * The fields of the messages security rules read most, named as Sigma's Linux rules and correlations group by:
 * user, target_user, src_ip, src_port, outcome, auth_method, command, tty, cwd, group and action.
 */
export function messageFields(source: string, message: string): Event {
  if (source === "sshd" || source === "sshd-session") {
    let m = SSH_FAILED.exec(message);
    if (m) return { outcome: "failure", auth_method: m[1]!, user: m[3]!, src_ip: m[4]!, src_port: Number(m[5]), ...(m[2] && { invalid_user: true }) };
    m = SSH_ACCEPTED.exec(message);
    if (m) return { outcome: "success", auth_method: m[1]!, user: m[2]!, src_ip: m[3]!, src_port: Number(m[4]) };
    m = SSH_INVALID.exec(message);
    if (m) return { outcome: "failure", user: m[1]!, src_ip: m[2]!, src_port: Number(m[3]), invalid_user: true };
    return {};
  }
  if (source === "sudo") {
    const m = SUDO.exec(message);
    if (!m) return {};
    // A refusal says why before TTY: "3 incorrect password attempts", "user NOT in sudoers".
    return { user: m[1]!, outcome: m[2] ? "failure" : "success", ...(m[2] && { reason: m[2] }), tty: m[3]!, cwd: m[4]!, target_user: m[5]!, command: m[6]! };
  }
  if (source === "su") {
    const m = SU.exec(message);
    return m ? { outcome: m[1] ? "failure" : "success", target_user: m[2]!, user: m[3]!, tty: m[4]! } : {};
  }
  if (source === "useradd") {
    const m = USERADD.exec(message);
    return m ? { action: "user-added", target_user: m[1]! } : {};
  }
  if (source === "userdel") {
    const m = USERDEL.exec(message);
    return m ? { action: "user-deleted", target_user: m[1]! } : {};
  }
  if (source === "usermod") {
    const m = USERMOD.exec(message);
    if (!m) return {};
    return m[1] ? { action: "user-changed", target_user: m[1] } : { action: "group-member-added", target_user: m[2]!, group: m[3]! };
  }
  if (source === "groupadd") {
    const m = GROUPADD.exec(message);
    return m ? { action: "group-added", group: m[1]! } : {};
  }
  if (source === "passwd" || source === "chpasswd") {
    const m = PASSWD.exec(message);
    return m ? { action: "password-changed", target_user: m[1]! } : {};
  }
  return {};
}

function journalEvent(j: Record<string, unknown>): Event {
  const us = Number(j.__REALTIME_TIMESTAMP);
  const source = text(j.SYSLOG_IDENTIFIER) || text(j._COMM) || text(j._SYSTEMD_UNIT).replace(/\.service$/, "") || (j._TRANSPORT === "audit" ? "audit" : "");
  const raw = text(j.MESSAGE);
  const message = mask(raw);
  const e: Event = {
    time: Number.isFinite(us) && us > 0 ? new Date(Math.floor(us / 1000)).toISOString() : new Date().toISOString(),
    ...(source && { source }),
    message: cut(message),
  };
  const priority = text(j.PRIORITY);
  if (/^[0-7]$/.test(priority)) e.level = LEVELS[Number(priority)]!;
  for (const [k, name] of Object.entries(JOURNAL_FIELDS)) {
    const v = text(j[k]);
    if (v) e[name] = cut(mask(v));
  }
  // Read from the message as written, and each value masked on its own: sudo's PWD= is a folder, not a password.
  for (const [k, v] of Object.entries(messageFields(source, raw))) e[k] = typeof v === "string" ? cut(mask(v)) : v;
  return e;
}

/** Parses read.sh's output. `max` is the OPENASY_MAX the script ran with. */
export function parseRead(out: string, max: number, previous: { journal: string | null }): Read {
  const sections = new Map<string, string[]>();
  let current = "";
  for (const line of out.split("\n")) {
    if (line.startsWith("@@")) {
      current = line.slice(2).trim();
      sections.set(current, []);
    } else if (current) sections.get(current)!.push(line);
  }
  if (!sections.has("meta") || !sections.has("end")) throw new Error("the read did not finish: no end marker in its output");
  const unreadable: string[] = [];
  const events: Event[] = [];
  let journalCursor = previous.journal;
  let more = false;

  const journal = (sections.get("journal") ?? []).filter((l) => l.trim());
  if (journal[0]?.startsWith("@missing")) unreadable.push("journald: journalctl is not on this host");
  for (const line of journal) {
    if (!line.startsWith("{")) {
      if (PARTIAL_JOURNAL.test(line)) unreadable.push("the system journal: add the openasy account to the systemd-journal group");
      continue;
    }
    if (events.length === max) {
      more = true;
      break;
    }
    let j: Record<string, unknown>;
    try {
      j = JSON.parse(line) as Record<string, unknown>;
    } catch {
      continue;
    }
    events.push(journalEvent(j));
    if (typeof j.__CURSOR === "string") journalCursor = j.__CURSOR;
  }
  return { events, cursor: { journal: journalCursor }, more, unreadable: [...new Set(unreadable)] };
}
