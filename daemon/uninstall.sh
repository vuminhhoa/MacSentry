#!/bin/bash
# Gỡ macsentryd. Chạy: sudo ~/MacSentry/daemon/uninstall.sh  (giữ lại /var/log/macsentry.log)
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Cần quyền root: sudo $0"; exit 1; }
LABEL=io.github.vuminhhoa.macsentry.daemon
launchctl bootout system/$LABEL 2>/dev/null || true
rm -f /Library/LaunchDaemons/$LABEL.plist /usr/local/libexec/macsentryd /etc/macsentry.conf
rm -rf /var/db/macsentry
echo "Đã gỡ macsentryd (log vẫn còn ở /var/log/macsentry.log)"
