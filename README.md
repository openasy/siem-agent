# siem-agent

[![CI](https://github.com/openasy/siem-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/siem-agent/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The agent of [OpenAsy SIEM](https://github.com/openasy/siem). It is installed **once**, next to SIEM or in the network
of the hosts, and reads the security events in the system journal of those hosts over SSH: logins over SSH and at a
console, sudo and su, sessions, account and group changes, polkit, cron, and the kernel's audit records where journald
collects them. **Nothing is installed on the hosts** (ADR 0018, 0031, 0040). Hosts that already send their events
with a shipper need no agent.

- **It keeps the keys.** On first start it makes its SSH certificate authority and a fixed key, and keeps them in
  `/data/agent.state`, sealed with its own key-encryption key. SIEM never sees a private key.
- **It runs only its own script.** SIEM says which host to read and where the last read stopped; the agent checks
  every job again (address, account, port, host keys, the journal cursor), runs the read-only script built into it
  (`agent/read.sh`: `journalctl --after-cursor -o json`, for the programs above only), and signs certificates for the
  `openasy` principal only, valid for 5 minutes. A compromised SIEM cannot run commands on any host.
- **It sends events SIEM's rules can read.** Each journal entry becomes a flat event with its `source` (sshd, sudo...),
  `message`, `level`, `process`, `pid`, `uid` and `unit`. The messages rules read most are read into fields too:
  `user`, `src_ip`, `src_port`, `outcome` (success or failure), `auth_method` and `invalid_user` for SSH logins;
  `user`, `target_user`, `command`, `tty`, `cwd` and `outcome` for sudo and su; `action`, `target_user` and `group`
  for account changes. A correlation can group by them, such as failed logins by `src_ip`.
- **It masks secrets before they leave.** Values that look like passwords, tokens or keys become `***` on the agent,
  so they never leave the hosts' network.
- **It connects out, never in.** It asks SIEM for work and sends events; SIEM never connects to it. It enrols once
  with a one-time token and then uses its own secret (ADR 0023). When SIEM is down it keeps asking and says so in
  `/readyz`; the cursor stays with SIEM, so no event is lost or read twice.

## Run

Add the agent in SIEM under Agents. It shows a one-time enrolment token and this command:

```bash
openssl rand -hex 32 > openasy-agent-kek   # keep it with your backups
docker run -d --name siem-agent --restart unless-stopped --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges \
  -v siem-agent-data:/data -v "$PWD/openasy-agent-kek:/run/secrets/openasy-agent-kek:ro" \
  -e SIEM_URL=https://siem.example.com -e SIEM_ENROLL_TOKEN=oie_... \
  ghcr.io/openasy/siem-agent:0.6.0
```

The agent must be the same version as SIEM (ADR 0019); another version is refused. The hosts it reads come from the
install's hosts file (`OPENASY_HOSTS` on SIEM, ADR 0052), the same one Infrastructure and Logs read.

| Variable | Default | |
| --- | --- | --- |
| `SIEM_URL` | | Where SIEM is, such as `http://siem:8080` or its https:// address |
| `SIEM_ENROLL_TOKEN` | | One-time, for the first start only |
| `SIEM_AGENT_SECRETS_KEY_FILE` | `/run/secrets/openasy-agent-kek` | 32-byte key that seals the CA, keys and secret |
| `SIEM_AGENT_STATE` | `/data/agent.state` | The sealed state, on its volume |
| `POLL_SECONDS` | `10` | How often it asks for work |
| `CONCURRENCY` | `8` | Hosts read at the same time |
| `OPENASY_KEYS_DIR` | `/keys` | Private keys a host in the hosts file names with `keyFile`; mount it read-only |
| `PORT` | `9100` | `/healthz`, `/readyz` and `/metrics` |

## What a host needs

SIEM prints the commands under Agents with this agent's CA. They create the `openasy` account, trust the CA for that
account only, and add it to `systemd-journal` so it reads the system journal; without that group it reads only its own
journal, and SIEM says so. No sudo rule is needed.

A host Infrastructure or Logs already reads keeps its account and sshd drop-in: this agent's CA is added as another
line of `/etc/ssh/openasy_ca.pub`, because sshd reads only one `TrustedUserCAKeys` file.

## Develop

```bash
npm install
npm test   # jobs, the read script's output, the fields read from messages, masking, host setup, the loop
```

## Licence

AGPL-3.0 (ADR 0008).
