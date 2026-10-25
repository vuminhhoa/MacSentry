# Security Policy

MacSentry runs as root and handles sensitive data, so security reports are taken seriously and are very welcome.

## Supported versions

Only the latest release and the `main` branch receive security fixes.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a vulnerability.**

Report it privately through GitHub:
[**Report a vulnerability**](https://github.com/vuminhhoa/macsentry/security/advisories/new)
(Security tab → Advisories → Report a vulnerability).

A useful report includes:

- the affected component (`MacSentry.app`, `macsentryd`, `macsentry-es`, the install scripts) and version or commit
- the macOS version and hardware
- steps to reproduce, or a proof of concept
- the impact you see, for example privilege escalation, reading the Telegram token, or silencing alerts
  without being reported

Please remove tokens, chat IDs, host names and other personal data from logs before sharing them.

## What to expect

This is a project maintained by one person in their spare time, so timelines are best effort:

- an acknowledgement within 7 days
- an assessment and a plan within 30 days
- a fix and a published advisory once it is ready, crediting you unless you prefer otherwise

## Scope

In scope:

- privilege escalation through MacSentry's components, files or install scripts
- disclosure of the Telegram token or other secrets MacSentry handles
- ways for a non-root process to stop, blind or silence MacSentry without an alert being sent
- injection through data MacSentry reads (logs, plists, Endpoint Security events) into commands or messages

Out of scope:

- an attacker who already has root disabling MacSentry; this is a documented limit (see the
  [security model](README.md#security-model))
- detection gaps for a specific technique; please open a regular issue with the detection request template
- vulnerabilities in macOS, Telegram or third-party agents themselves
