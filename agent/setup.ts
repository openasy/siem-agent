// What an admin puts on a host so this agent can read its security events (ADR 0031, 0040): an account, one sshd
// drop-in, and membership of the group that may read the system journal. Nothing else is installed, and no sudo rule
// is needed.
//
// The account, the drop-in and the CA file are the ones infra-agent and logs-agent use. sshd takes only the first
// TrustedUserCAKeys it reads, so a second drop-in with its own file would be ignored on hosts Infrastructure already
// reads: both agents' CAs go into the one file instead, one key per line.

export const ACCOUNT = "openasy";
export const CA_FILE = "/etc/ssh/openasy_ca.pub";

export function sshdConfig(account = ACCOUNT): string {
  return [
    "# /etc/ssh/sshd_config.d/openasy.conf",
    "# Trust the OpenAsy agents' certificate authorities only for the principals listed per account, so they can never",
    "# log in as root or anyone else.",
    `TrustedUserCAKeys ${CA_FILE}`,
    "AuthorizedPrincipalsFile /etc/ssh/principals/%u",
    `Match User ${account}`,
    "  PasswordAuthentication no",
    "  AllowTcpForwarding no",
    "  AllowAgentForwarding no",
    "  AllowStreamLocalForwarding no",
    "  X11Forwarding no",
    "  PermitTTY no",
    "",
  ].join("\n");
}

/** Shell commands for an admin to run once on a host, as root. Running them again changes nothing. */
export function hostSetup(caPublicKey: string, opts: { account?: string } = {}): string {
  const a = opts.account ?? ACCOUNT;
  const key = caPublicKey.trim();
  const lines = [
    `# Run as root on the host. Creates the ${a} account if it is not there, adds the siem-agent CA to the OpenAsy`,
    "# CA file for that account only, lets it read the system journal, and reloads sshd.",
    `id ${a} >/dev/null 2>&1 || { useradd --create-home --shell /bin/sh ${a} && passwd -l ${a}; }`,
    `install -d -m 755 /etc/ssh/principals && echo ${a} > /etc/ssh/principals/${a}`,
    `touch ${CA_FILE} && (grep -qxF '${key}' ${CA_FILE} || echo '${key}' >> ${CA_FILE})`,
    "[ -f /etc/ssh/sshd_config.d/openasy.conf ] || cat > /etc/ssh/sshd_config.d/openasy.conf <<'OPENASY'",
    ...sshdConfig(a).trimEnd().split("\n").slice(1),
    "OPENASY",
    "# The system journal, read-only. Without it only the account's own journal is readable.",
    `usermod -aG systemd-journal ${a}`,
    "sshd -t && (systemctl reload ssh 2>/dev/null || systemctl reload sshd)",
  ];
  return lines.join("\n") + "\n";
}

/** For hosts that cannot change sshd_config: one fixed key, without forwarding, TTY or agent. */
export const authorizedKeyLine = (publicKey: string) => `restrict ${publicKey.trim()}`;
