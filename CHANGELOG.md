# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-10-24

First public release.

### Added

- Menu bar app: remote access sessions with popups for unknown IPs, connection history, trusted IPs, screen
  lock and unlock, camera and microphone, sleep, a Console-style event viewer and in-app Telegram settings.
- `macsentryd`, an event-driven root daemon: boot and shutdown, logins and failed passwords, remote access
  services, listening ports, reverse shells, persistence (launch items, profiles, extensions, sensitive files
  with diffs), security posture, Wazuh and other critical agents, remote control tools and tunnels, hardware and
  network changes, a daily report, an append-only log and an optional heartbeat.
- `macsentry-es`, an Endpoint Security helper based on `eslogger`: authentication with the calling process, TCC
  grants, XProtect, Gatekeeper, launch items, profiles, users and groups, and dangerous commands.
- `uninstall.sh` to remove the app and the daemon, with `--purge` to remove app data.
- `build.sh --no-install` and `ARCHS` for CI and universal builds.
- Project documentation, contribution guidelines, a security policy, issue forms and CI (build, ShellCheck,
  actionlint, CodeQL).

### Changed

- Bundle identifier and launchd labels are now `io.github.vuminhhoa.macsentry*`. `build.sh` and
  `daemon/install.sh` remove jobs left by earlier labels.
- The minimum macOS version is stated as 26.0 and used as the build target for all binaries.
- The default `/etc/macsentry.allow` ships with its example rule commented out.

### Security

- The app's data folder is created with mode 0700 and its files, including the Telegram token, are written
  with mode 0600 from the start.
- The daemon masks Telegram bot tokens and secret values (`TOKEN=`, `PASSWORD:`...) in everything it writes to
  its world-readable log and sends to Telegram, including process command lines.

[Unreleased]: https://github.com/vuminhhoa/macsentry/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/vuminhhoa/macsentry/releases/tag/v1.0.0
