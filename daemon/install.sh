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
# (Chỉ làm lần đầu: file đã có cờ sappnd thì touch/chmod đều bị từ chối, kể cả root)
if [ ! -e /var/log/macsentry.log ]; then
  touch /var/log/macsentry.log; chown root:wheel /var/log/macsentry.log; chmod 644 /var/log/macsentry.log
  chflags sappnd /var/log/macsentry.log
fi

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

# bootout trả về ngay nhưng daemon cũ còn gửi tin 🔴 trước khi thoát → chờ nó dừng hẳn rồi mới bootstrap
launchctl bootout system/$LABEL 2>/dev/null || true
for i in $(seq 1 20); do launchctl print system/$LABEL >/dev/null 2>&1 || break; sleep 1; done
for i in 1 2 3 4 5; do
  launchctl bootstrap system /Library/LaunchDaemons/$LABEL.plist 2>/dev/null && break
  [ $i = 5 ] && { echo "Không khởi động được daemon"; exit 1; }
  sleep 2
done
launchctl print system/$LABEL | grep -q "state = running" && echo "Đã cài và chạy macsentryd. Log: /var/log/macsentry.log"
