import { describe, expect, it } from "vitest";
import { mask, messageFields, parseRead } from "./events.ts";

const output = (lines: string[]) => ["", "@@meta", "format 1", "user openasy", "", "@@journal", ...lines, "", "@@end", ""].join("\n");
const entry = (over: Record<string, unknown>, cursor = "s=1;i=1") =>
  JSON.stringify({ __CURSOR: cursor, __REALTIME_TIMESTAMP: "1761040000000000", PRIORITY: "6", ...over });

describe("reading the journal into events", () => {
  it("names each event's source and fields as siem's rules read them, and moves the cursor", () => {
    const r = parseRead(
      output([
        entry({ SYSLOG_IDENTIFIER: "sshd", _COMM: "sshd", _PID: "812", MESSAGE: "Failed password for invalid user admin from 203.0.113.7 port 52211 ssh2" }),
        entry({ SYSLOG_IDENTIFIER: "sudo", MESSAGE: "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id" }, "s=1;i=2"),
      ]),
      100,
      { journal: null },
    );
    expect(r.cursor).toEqual({ journal: "s=1;i=2" });
    expect(r.events).toEqual([
      {
        time: "2025-10-21T09:46:40.000Z",
        source: "sshd",
        message: "Failed password for invalid user admin from 203.0.113.7 port 52211 ssh2",
        level: "info",
        process: "sshd",
        pid: "812",
        outcome: "failure",
        auth_method: "password",
        user: "admin",
        src_ip: "203.0.113.7",
        src_port: 52211,
        invalid_user: true,
      },
      expect.objectContaining({
        source: "sudo",
        user: "alice",
        target_user: "root",
        command: "/usr/bin/id",
        outcome: "success",
        tty: "pts/0",
        cwd: "/home/alice",
      }),
    ]);
  });

  it("reads logins, sudo refusals, su and account changes", () => {
    expect(messageFields("sshd-session", "Accepted publickey for deploy from 10.0.0.9 port 40022 ssh2: ED25519 SHA256:abc")).toEqual({
      outcome: "success",
      auth_method: "publickey",
      user: "deploy",
      src_ip: "10.0.0.9",
      src_port: 40022,
    });
    expect(messageFields("sshd", "Invalid user oracle from 198.51.100.4 port 3322")).toMatchObject({ user: "oracle", invalid_user: true, outcome: "failure" });
    expect(messageFields("sudo", "bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh")).toMatchObject({
      user: "bob",
      outcome: "failure",
      reason: "3 incorrect password attempts",
      command: "/bin/sh",
    });
    expect(messageFields("su", "FAILED SU (to root) bob on pts/1")).toEqual({ outcome: "failure", target_user: "root", user: "bob", tty: "pts/1" });
    expect(messageFields("useradd", "new user: name=eve, UID=1002, GID=1002, home=/home/eve, shell=/bin/sh, from=/dev/pts/0")).toEqual({
      action: "user-added",
      target_user: "eve",
    });
    expect(messageFields("usermod", "add 'eve' to group 'sudo'")).toEqual({ action: "group-member-added", target_user: "eve", group: "sudo" });
    expect(messageFields("cron", "anything")).toEqual({});
  });

  it("masks secrets, cuts long messages, and keeps to the limit", () => {
    const long = "x".repeat(10_000);
    const r = parseRead(
      output([entry({ SYSLOG_IDENTIFIER: "sudo", MESSAGE: "token=abcdef123 api_key: zzz" }), entry({ MESSAGE: long }), entry({ MESSAGE: "third" })]),
      2,
      { journal: "s=0" },
    );
    expect(r.events[0]!.message).toBe("token=*** api_key: ***");
    expect((r.events[1]!.message as string).length).toBe(4001);
    expect(r.more).toBe(true);
    expect(r.events).toHaveLength(2);
    expect(mask("https://u:p@example.com")).toBe("https://u:***@example.com");
  });

  it("says when the account may read only its own journal, or there is none", () => {
    const partial = parseRead(output(["Hint: You are currently not seeing messages from other users and the system."]), 10, { journal: "s=9" });
    expect(partial).toEqual({
      events: [],
      cursor: { journal: "s=9" },
      more: false,
      unreadable: ["the system journal: add the openasy account to the systemd-journal group"],
    });
    expect(parseRead(output(["No journal files were opened due to insufficient permissions."]), 10, { journal: null }).unreadable).toEqual([
      "the system journal: add the openasy account to the systemd-journal group",
    ]);
    expect(parseRead(output(["@missing journalctl"]), 10, { journal: null }).unreadable).toEqual(["journald: journalctl is not on this host"]);
    expect(() => parseRead("@@meta\n", 10, { journal: null })).toThrow(/did not finish/);
  });
});
