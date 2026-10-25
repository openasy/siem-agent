# Read-only, run on the host as `sh -s` over SSH (ADR 0031, 0040). It writes nothing and starts nothing that keeps
# running. The agent puts these variables before it, each checked first, so none can carry a command:
#   OPENASY_CURSOR      where the last read of the journal stopped (a journalctl cursor), or empty
#   OPENASY_SINCE       Unix seconds to start from when there is no cursor yet
#   OPENASY_MAX         the most entries to read in one go
# Sections start with "@@name"; the agent parses them (agent/events.ts).
export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin
s() { printf '\n@@%s\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }
MORE=$((OPENASY_MAX + 1))

s meta
printf 'format 1\nuser %s\ngroups %s\nnow %s\n' "$(id -un)" "$(id -nG)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Only what security rules read: logins over SSH and at a console, sudo and su, sessions, account and group
# changes, polkit, cron, and the kernel's audit records where journald collects them. The rest of the journal is
# Logs' to read.
s journal
if have journalctl; then
  set -- SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sshd-session SYSLOG_IDENTIFIER=sudo SYSLOG_IDENTIFIER=su \
    SYSLOG_IDENTIFIER=login SYSLOG_IDENTIFIER=systemd-logind SYSLOG_IDENTIFIER=useradd SYSLOG_IDENTIFIER=userdel \
    SYSLOG_IDENTIFIER=usermod SYSLOG_IDENTIFIER=groupadd SYSLOG_IDENTIFIER=groupdel SYSLOG_IDENTIFIER=groupmod \
    SYSLOG_IDENTIFIER=gpasswd SYSLOG_IDENTIFIER=passwd SYSLOG_IDENTIFIER=chpasswd SYSLOG_IDENTIFIER=chage \
    SYSLOG_IDENTIFIER=polkitd SYSLOG_IDENTIFIER=pkexec SYSLOG_IDENTIFIER=CRON SYSLOG_IDENTIFIER=crond + _TRANSPORT=audit
  # Oldest first, one more than the limit so the agent knows whether more are waiting. The hint journalctl prints
  # when the account may read only its own journal goes to the same stream, so the agent can say so.
  if [ -n "$OPENASY_CURSOR" ]; then
    journalctl --no-pager --output=json --after-cursor="$OPENASY_CURSOR" "$@" 2>&1 | head -n "$MORE"
  else
    journalctl --no-pager --output=json --since="@$OPENASY_SINCE" "$@" 2>&1 | head -n "$MORE"
  fi
else
  echo '@missing journalctl'
fi
s end
