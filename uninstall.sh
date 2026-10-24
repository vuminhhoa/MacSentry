#!/bin/bash
# Gỡ MacSentry: daemon (cần sudo) rồi app thanh menu của user hiện tại.
#   ./uninstall.sh          gỡ, giữ dữ liệu của app (~/Library/Application Support/MacSentry) và /var/log/macsentry.log
#   ./uninstall.sh --purge  gỡ và xoá cả dữ liệu của app (lịch sử, IP tin cậy, cấu hình Telegram)
set -euo pipefail
cd "$(dirname "$0")"
[ "$(id -u)" != 0 ] || { echo "Chạy bằng user thường (không sudo): ./uninstall.sh"; exit 1; }
PURGE=0
case "${1:-}" in --purge) PURGE=1 ;; "") ;; *) echo "Tham số không hợp lệ: $1" >&2; exit 2 ;; esac

# Gỡ daemon trước: nếu gỡ app trước, daemon sẽ báo "app MacSentry không chạy"
if ls /Library/LaunchDaemons/*.macsentry.daemon.plist >/dev/null 2>&1; then
  sudo ./daemon/uninstall.sh
fi

for plist in "$HOME"/Library/LaunchAgents/*.macsentry.plist; do
  [ -e "$plist" ] || continue
  launchctl bootout "gui/$(id -u)/$(basename "$plist" .plist)" 2>/dev/null || true
  rm -f "$plist"
done
launchctl list | awk '$3 ~ /\.macsentry\.netstat$/ {print $3}' | while read -r label; do launchctl remove "$label" 2>/dev/null || true; done
pkill -x MacSentry || true
rm -rf "$HOME/Applications/MacSentry.app"
[ "$PURGE" = 1 ] && rm -rf "$HOME/Library/Application Support/MacSentry"
echo "Đã gỡ MacSentry.app$([ "$PURGE" = 1 ] && echo " và dữ liệu của app")"
