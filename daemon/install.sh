#!/bin/bash
# Cài macsentryd (LaunchDaemon chạy bằng root). Chạy: sudo ~/MacSentry/daemon/install.sh
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Cần quyền root: sudo $0"; exit 1; }
cd "$(dirname "$0")"
LABEL=io.github.vuminhhoa.macsentry.daemon
SRC_CONF="$(eval echo ~"${SUDO_USER:-$USER}")/Library/Application Support/MacSentry/telegram.json"

TOKEN=$(plutil -extract botToken raw -o - "$SRC_CONF")
CHAT=$(plutil -extract chatId raw -o - "$SRC_CONF")
( umask 077; printf 'TOKEN=%s\nCHAT=%s\n' "$TOKEN" "$CHAT" > /etc/macsentry.conf )
chown root:wheel /etc/macsentry.conf; chmod 600 /etc/macsentry.conf

mkdir -p /usr/local/libexec /var/db/macsentry
install -o root -g wheel -m 755 macsentryd.sh /usr/local/libexec/macsentryd
chmod 700 /var/db/macsentry

# Log: ai cũng đọc được (app hiển thị tab "Sự kiện"), chỉ root ghi, và chỉ được ghi thêm
touch /var/log/macsentry.log; chown root:wheel /var/log/macsentry.log; chmod 644 /var/log/macsentry.log
chflags sappnd /var/log/macsentry.log

cat > /Library/LaunchDaemons/$LABEL.plist <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array><string>/bin/sh</string><string>/usr/local/libexec/macsentryd</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ExitTimeOut</key><integer>15</integer>
</dict></plist>
PLIST
chown root:wheel /Library/LaunchDaemons/$LABEL.plist; chmod 644 /Library/LaunchDaemons/$LABEL.plist

launchctl bootout system/$LABEL 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/$LABEL.plist
echo "Đã cài macsentryd. Log: /var/log/macsentry.log"
