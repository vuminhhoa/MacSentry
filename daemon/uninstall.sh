#!/bin/bash
# Gỡ macsentryd + macsentry-es. Chạy: sudo ./daemon/uninstall.sh  (giữ lại /var/log/macsentry.log)
# Gỡ cả app: ./uninstall.sh ở thư mục gốc
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Cần quyền root: sudo $0"; exit 1; }
touch /var/db/macsentry/clean_stop 2>/dev/null || true
for LABEL in io.github.vuminhhoa.macsentry.es io.github.vuminhhoa.macsentry.daemon; do
  launchctl bootout system/$LABEL 2>/dev/null || true
  rm -f /Library/LaunchDaemons/$LABEL.plist
done
rm -rf /usr/local/libexec/macsentry
rm -f /usr/local/libexec/macsentryd /usr/local/libexec/macsentry-es /etc/macsentry.conf /etc/macsentry.trusted /etc/macsentry.agents /etc/macsentry.allow
rm -rf /var/db/macsentry /var/run/macsentry
echo "Đã gỡ macsentryd và macsentry-es (log vẫn còn ở /var/log/macsentry.log)"
