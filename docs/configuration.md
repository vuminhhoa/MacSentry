# Configuration

MacSentry is configured through a few plain text files. The daemon and the Endpoint Security helper re-read the
lists below about once a minute, so edits take effect without a restart.

## `/etc/macsentry.conf`

Written by `sudo ./daemon/install.sh` and readable by root only (mode 0600). One `KEY=value` per line; lines
starting with `#` are ignored and values may be quoted.

| Key | Default | Meaning |
|---|---|---|
| `TOKEN` | the app's bot token | Telegram bot token the daemon sends with. A separate bot is recommended, see below. |
| `CHAT` | the app's chat ID | Telegram chat that receives alerts. |
| `HEARTBEAT_URL` | empty | URL the daemon requests once a minute, for a dead man's switch such as healthchecks.io. |
| `ES_EXEC` | `1` | `0` turns off process execution monitoring in `macsentry-es`, the most expensive part (~2-3% of one core on a busy machine). Other monitoring keeps working. |
| `FIM` | `auto` | File integrity monitoring mode, see below. |

Run `sudo ./daemon/install.sh --reconfigure` to answer the token, heartbeat and `ES_EXEC` questions again.

### A separate bot for the daemon

The app keeps its token in `~/Library/Application Support/MacSentry/telegram.json`. Any program running as
your user can read that file and use the token to delete what that bot sent in the last 48 hours. Create a
second bot with [@BotFather](https://t.me/BotFather), send `/start` to it from your chat, and give its token to
the installer. The daemon's alerts then cannot be deleted from your account. The daemon sends a weekly reminder
while both use the same token.

### `FIM` modes

- `auto`: for sensitive files that [Wazuh](https://wazuh.com) syscheck already watches in real time
  (`realtime="yes"` or `whodata="yes"`, not ignored), MacSentry leaves the diffing to Wazuh, but only while
  `wazuh-syscheckd` is running and the agent is connected to its manager. If Wazuh stops or disconnects,
  MacSentry takes those files back immediately. Wazuh's scheduled scans (12 hours by default) do not count.
  The daily report shows how many files are delegated. MacSentry always keeps watching Wazuh itself.
- `local`: MacSentry watches every sensitive file itself and sends the diff over Telegram.

## `/etc/macsentry.trusted`

Hosts that shells and `netcat` may connect to without a reverse shell alert; such connections are only logged.
One entry per line, either `host:port` or `host` for any port. Host names are resolved again every minute.

```text
git.example.com:22
build.example.com
```

## `/etc/macsentry.agents`

Agents to watch in addition to the built-in catalog (EDR and antivirus, MDM, firewalls, VPNs, remote control
tools; see `daemon/Sources/Agents.swift`). An agent is watched only when its install path exists. MacSentry
alerts when one of its processes stops, and when one of its configuration files changes (with a masked diff).

```text
# Name | process,names | install path | config file globs (space separated)
Company Agent | company-agentd,company-helper | /Library/CompanyAgent | /Library/CompanyAgent/etc/*.conf
```

## `/etc/macsentry.allow`

Regular expressions (case insensitive), one per line, for commands that `macsentry-es` should only log instead
of alerting on. Each expression is matched against `<full command line> || <parent process chain>`, so a rule can
require a specific parent:

```text
# Claude Code reading its own login token from the keychain
(^|/)security find-generic-password .*-s Claude Code-credentials\b.*\|\| claude\(
```

Keep rules as narrow as possible: anything that matches is no longer reported.

## App data

`~/Library/Application Support/MacSentry/` (mode 0700) holds the app's Telegram settings (`telegram.json`, mode
0600), the connection history and the trusted IP list. You can edit the Telegram settings and trusted IPs from
the app.

`update.command` in the same folder is written by **Settings → Updates → Update…** and opened in Terminal.
The update check itself is stored in the app's defaults (`autoCheckUpdates`, `lastUpdateCheck`).

## Environment variables for development

The daemon reads these so it can run unprivileged against test data:

| Variable | Default | Meaning |
|---|---|---|
| `CONF` | `/etc/macsentry.conf` | Configuration file |
| `LOG` | `/var/log/macsentry.log` | Log file |
| `STATE` | `/var/db/macsentry` | State directory (also read by `macsentry-es`) |
| `PUB_DIR` | `/var/run/macsentry` | State shared with the app |
| `TRUSTED` | `/etc/macsentry.trusted` | Trusted hosts |
| `WAZUH_DIR` | `/Library/Ossec` | Wazuh installation |
| `DRYRUN` | unset | When set, nothing is sent to Telegram |
| `ALLOW` | `/etc/macsentry.allow` | Allowlist for `macsentry-es` |
