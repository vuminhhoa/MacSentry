# Architecture

MacSentry is three Swift programs with no third-party dependencies, built with plain `swiftc` by
[`build.sh`](../build.sh).

## Components

### `macsentryd`: root daemon

A LaunchDaemon (`io.github.vuminhhoa.macsentry.daemon`) that runs from boot, before anyone logs in. It owns
the Telegram delivery for root-level findings, the append-only log at `/var/log/macsentry.log` (`sappnd` flag),
the daily report and the heartbeat.

Changes are reported from system events, and periodic scans are only a fallback:

| Source | Used for |
|---|---|
| FSEvents | LaunchAgents/Daemons, `/etc`, `~/.ssh`, persistence folders, MacSentry's own files, Wazuh |
| IOKit | USB devices, power source, sleep and wake |
| DiskArbitration | External volumes |
| SCDynamicStore | Network changes, proxy, DNS |
| Spool (`/var/db/macsentry/spool`) | Messages from `macsentry-es` |
| 2-second timer | Remote connections, reverse shell candidates, and fallback scans at slower intervals |

Data is read through APIs where one exists (libproc and sysctl instead of `ps`/`lsof`, utmpx instead of `who`,
the Security framework instead of `codesign`, IOKit instead of `ioreg`/`pmset`, plists read directly instead of
`defaults`/`launchctl`). External commands are kept for things with no API, such as `netstat`, `profiles`,
`kmutil`, `security` and `sfltool`, and run infrequently on a separate low-priority queue.

All checks run serially on one dispatch queue, so state needs no locks. State lives in `/var/db/macsentry`
(mode 0700). `diffState` compares a new list with the stored one; the first run only records a baseline, so
installing MacSentry does not flood you with alerts about what was already there.

### `macsentry-es`: Endpoint Security helper

A second LaunchDaemon (`io.github.vuminhhoa.macsentry.es`) that runs `/usr/bin/eslogger` and reads its JSON
stream. Using `eslogger` avoids the Endpoint Security entitlement, which Apple grants only to approved
developers; the price is that the helper needs Full Disk Access.

The helper turns events into alerts (authentication, TCC, XProtect, Gatekeeper, launch items, profiles, users
and groups, and dangerous commands matched by an Aho-Corasick prefilter plus per-program rules) and writes them
into the daemon's spool with an atomic rename. It never holds the Telegram token, and it masks tokens and
secrets before writing anything.

Real event samples are kept in `/var/db/macsentry/es_samples/`, and `es/schema.py` prints their structure, to
check the parser when macOS changes the format.

### `MacSentry.app`: menu bar app

A per-user LaunchAgent (`io.github.vuminhhoa.macsentry`) with `KeepAlive`. The app cannot be quit from its
menu, and launchd restarts it if it is killed. It handles what is tied to the user session: popups for remote
connections, screen lock and unlock, camera and microphone (CoreAudio and CoreMediaIO listeners), sleep. It
also provides the history, trusted IPs, the event viewer and settings, and it alerts if the daemon or the helper
stops.

The daemon publishes its connection scan in `/var/run/macsentry/remote`, so the app does not scan on its own.
Without the daemon, the app falls back to its own scan. macOS hides other processes' sockets from `netstat` when
it is called from a non-Apple binary, so the app hands that job to a small launchd job
(`io.github.vuminhhoa.macsentry.netstat`) that writes `netstat` output to a file.

## Source layout

```text
Sources/                  menu bar app
  main.swift                entry point (--scan, --render-icon)
  AppDelegate*.swift        lifecycle; +Monitoring (daemon watch, camera/mic), +Menu, +Alerts (popups, notifications)
  Monitor.swift             remote connections (daemon results, own scan as fallback)
  MainWindow.swift, *Page.swift, ContentView.swift   main window and pages
  AVSensors, Telegram, LaunchAtLogin, Store, Model, EventLog
daemon/
  Sources/                  root daemon macsentryd
    main.swift                startup, shutdown, fallback timer, --check mode
    Events.swift              event sources: FSEvents, IOKit, DiskArbitration, SCDynamicStore, spool
    Core.swift                configuration, log, Telegram, state (diff, hash, tail), throttling
    Detail.swift              code signatures, process details, whois, trusted hosts
    Network.swift             TCP sockets via libproc, netstat, utmpx
    Remote, System, Persistence, Posture, Wazuh, Agents, Hardware, Auth, Report
  install.sh, uninstall.sh
es/                       Endpoint Security helper macsentry-es
  main.swift                configuration, eslogger loop
  Handlers.swift            one handler per event type
  Rules.swift               exec rules, Aho-Corasick, allowlist
  Spool.swift               delivery through the daemon, secret masking
  EventJSON.swift           tolerant JSON access
  schema.py                 prints the structure of sample events
shared/Proc.swift         libproc and sysctl helpers shared by the daemon and the helper
```

## Adding a check to the daemon

1. Write a `checkX()` function in the relevant file under `daemon/Sources/`, or in a new file.
2. Call it from the matching event source in `Events.swift`, from the fallback timer in `onTick()`
   (`main.swift`), or both.
3. Compare state with `diffState` (lists), `hashChanges` (file contents) or `statChanged` (cheap prefilter),
   and use `throttle` to avoid repeating the same alert.
4. Send with `alert()` (with sound) or `info()` (silent); both also write to the log.
5. Add the check to `--check` mode if it reads data that is worth inspecting.

Test it with `DRYRUN=1` and the environment variables listed in [configuration.md](configuration.md).
