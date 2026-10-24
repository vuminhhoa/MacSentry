# Detections

What MacSentry reports, grouped by the component that reports it. Alerts with sound are for things that need
your attention; routine events are sent silently or only logged.

## Menu bar app (`MacSentry.app`)

- Remote access sessions (SSH, Screen Sharing/VNC, Remote Desktop, SMB, AFP, Remote Apple Events), with a popup
  for IPs that are not on your trusted list, and a connection history
- Screen lock and unlock; an unlock between midnight and 6 a.m. rings
- Camera and microphone turned on or off, with the process using them
- The Mac going to sleep
- The daemon or the Endpoint Security helper not running

## Root daemon (`macsentryd`)

**Lifecycle and access**
- Boot, shutdown and wake; the daemon being killed with `kill -9`
- Remote connections and SSH logins, remote access services turned on or off, new ports listening on the network
- Failed passwords (lock screen, SSH, `sudo`) and `sudo` use
- Suspected reverse shells: a shell or `netcat` holding an outbound connection, with the command line, user,
  parent chain, code signature, reverse DNS and whois owner of the remote IP

**Persistence**
- Sensitive files, with a diff of what changed and secrets masked: `authorized_keys`, `sshd_config`, `sudoers`,
  PAM, cron, `/etc/hosts`, system shell rc files, and users' shell rc files and `~/.ssh/config`
- LaunchAgents and LaunchDaemons: new, removed, plist content changed, or the executable's code signature
  changed (a swapped binary); services disabled with `launchctl disable`
- Login and Background Items, configuration profiles, system extensions, kexts, authorization plugins,
  `PrivilegedHelperTools`, `StartupItems`, login hooks, trusted root certificates, browser extensions
- Proxy and DNS changes, new apps, new users and admins

**Security posture**
- Firewall, Gatekeeper, SIP, FileVault, automatic security updates
- Automatic login, Guest account, screen lock settings, Find My, MDM enrollment, Remote Management, legacy VNC
  password, outdated XProtect data
- MacSentry's own files modified, the app not running, the daemon lacking Full Disk Access, the app and daemon
  sharing a bot token

**Remote control tools and tunnels**
- TeamViewer, AnyDesk, RustDesk, Chrome Remote Desktop and similar tools, and tunnels such as ngrok and
  cloudflared: the process running, and incoming sessions found in their logs. These tools relay through their
  own servers, so they do not show up as listening ports.

**Agents**
- Wazuh: the agent stopping, losing or changing its manager, configuration changes (including `agent.conf` pushed
  by the manager), remote commands being enabled, active responses executed on the machine, executables or
  scripts replaced
- A catalog of EDR, antivirus, MDM, firewall, VPN and remote control agents (CrowdStrike, SentinelOne, Microsoft
  Defender, Sophos, ESET, Kaspersky, Malwarebytes, Santa, Jamf, Kandji, Intune, Little Snitch, LuLu, Tailscale,
  Cloudflare WARP, OpenVPN, Tunnelblick, TeamViewer, AnyDesk...) plus your own in `/etc/macsentry.agents`:
  a process stopping, or a configuration file changing (with a masked diff)

**Hardware and network**
- USB devices and external volumes (known ones are silent), power source and battery, network changes, a disk
  close to full

**Health**
- A daily morning summary. If it does not arrive, something is wrong with the Mac or the daemon.
- An optional heartbeat to an outside monitor every minute

## Endpoint Security helper (`macsentry-es`)

- Failed authentication with the exact calling process, which avoids false alarms from iCloud or FileVault
  services checking the password
- Someone viewing or controlling the screen (Screen Sharing, Apple Remote Desktop)
- TCC grants for sensitive permissions: screen recording, accessibility, input monitoring, Full Disk Access,
  camera, microphone and others
- XProtect malware detections, Gatekeeper bypass, account password changes, kext loads
- New launch items (Login Item, `SMAppService`, LaunchAgent) with the process that installed them, configuration
  profiles, users created or deleted, admin rights granted, all reported immediately
- Dangerous commands: reverse shells in any language, keychain password reads, disabling SIP, Gatekeeper or the
  firewall, stopping MacSentry, Wazuh or an EDR, creating an admin, installing a login hook, fake password
  dialogs, `curl | sh`, removing the quarantine attribute
