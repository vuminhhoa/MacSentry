#!/bin/bash
# macsentryd — daemon cảnh báo an ninh chạy bằng root qua LaunchDaemon: chạy từ lúc bật máy (trước khi
# đăng nhập), user thường không tắt/sửa được. Gửi Telegram khi có:
#   - Bật / tắt máy, máy thức dậy
#   - Kết nối truy cập từ xa (SSH, Screen Sharing/VNC, Remote Desktop, SMB, AFP) mở/đóng, đăng nhập SSH
#   - Nhập sai mật khẩu (màn hình khoá, SSH, sudo), dùng sudo
#   - Thay đổi hệ thống: LaunchAgent/Daemon mới, user/admin mới, firewall, Gatekeeper, dịch vụ từ xa bật/tắt,
#     cổng mới mở ra mạng
#   - Phần cứng & mạng: USB, ổ đĩa ngoài, nguồn điện/pin, đổi mạng, ổ đĩa sắp đầy
#   - Chống cài cắm: authorized_keys, sshd_config, sudoers, PAM, cron, shell rc hệ thống, /etc/hosts,
#     Login/Background Items, configuration profile, system extension, proxy, DNS, app mới
#   - Nghi reverse shell (shell/netcat giữ kết nối mạng)
#   - Tư thế bảo mật: SIP, FileVault, tự cập nhật, tự đăng nhập, Guest, khoá màn hình, Find My, MDM, Remote
#     Management / VNC mật khẩu cũ, XProtect; file của chính MacSentry bị sửa; báo cáo hằng ngày
#   - App điều khiển từ xa (TeamViewer, AnyDesk, RustDesk...) và tunnel (ngrok, cloudflared...): chạy + phiên kết nối
#   - Wazuh agent: tiến trình, kết nối manager, manager là ai, cấu hình (kể cả manager đẩy xuống), lệnh từ xa,
#     active response đã chạy, file thực thi bị thay
#   - Agent quan trọng nói chung (EDR/antivirus, MDM, firewall, VPN...): dừng tiến trình, đổi cấu hình
#   - Mọi LaunchDaemon/Agent: plist bị sửa, file chạy đổi chữ ký; authorization plugin, helper root, Root CA,
#     kext, login hook, extension trình duyệt, dịch vụ hệ thống bị tắt
#   - Chống bị tắt lén: phát hiện bị kill -9, heartbeat ra ngoài (HEARTBEAT_URL), nhận tin từ helper
#     Endpoint Security (macsentry-es) qua $STATE/spool
# Cấu hình: /etc/macsentry.conf (TOKEN=..., CHAT=..., HEARTBEAT_URL=...), chỉ root đọc được.
# Agent riêng cần theo dõi thêm: /etc/macsentry.agents.

CONF=${CONF:-/etc/macsentry.conf}
LOG=${LOG:-/var/log/macsentry.log}       # cờ sappnd: chỉ được ghi thêm, không xoá/sửa được
STATE=${STATE:-/var/db/macsentry}
. "$CONF" || exit 1
mkdir -p "$STATE/conn" "$STATE/throttle" "$STATE/spool"
# Thư mục chia sẻ trạng thái cho app (ai cũng đọc được, chỉ root ghi). /var/run bị xoá mỗi lần khởi động.
PUB_DIR=${PUB_DIR:-/var/run/macsentry}
mkdir -p "$PUB_DIR" && chmod 755 "$PUB_DIR"
HOST=$(scutil --get ComputerName 2>/dev/null || hostname)
MAIN_PID=$$

# Các module (mỗi file một nhóm giám sát): cạnh file này khi phát triển (daemon/lib), hoặc
# /usr/local/libexec/macsentry khi đã cài. Chỉ định nghĩa hàm/hằng số — các lệnh chạy ngay nằm ở file này.
if [ -z "$LIB_DIR" ]; then
  here=$(cd "$(dirname "$0")" && pwd)
  for LIB_DIR in "$here/lib" "$here/macsentry"; do [ -d "$LIB_DIR" ] && break; done
fi
for m in util detail auth remote system persistence posture remote_tools wazuh agents report hardware; do
  . "$LIB_DIR/$m.sh" || { echo "macsentryd: không nạp được $LIB_DIR/$m.sh" >&2; exit 1; }
done

# ---------------------------------------------------------------- 1. khởi động / tắt máy

boot=$(sysctl -n kern.boottime | sed 's/^{ sec = \([0-9]*\).*/\1/')
if [ "$(cat "$STATE/lastboot" 2>/dev/null)" != "$boot" ]; then
  echo "$boot" > "$STATE/lastboot"
  rm -f "$STATE/conn/"* "$STATE/remote_conns" "$STATE/who"
  alert "🟢 Máy vừa khởi động
Bật lúc: $(date -r "$boot" '+%d/%m/%Y %H:%M:%S')"
elif [ -f "$STATE/clean_stop" ]; then
  info "▶️ macsentryd chạy lại (máy bật từ $(date -r "$boot" '+%d/%m/%Y %H:%M:%S'))"
else
  # Không có dấu dừng bình thường → bị kill -9 / crash rồi launchd chạy lại (SIGKILL không chạy được trap)
  alert "⚠️ macsentryd vừa bị dừng ĐỘT NGỘT (kill -9 hoặc lỗi) và đã được launchd chạy lại
Máy bật từ: $(date -r "$boot" '+%d/%m/%Y %H:%M:%S')
(nếu không phải bạn → có thể có người cố tắt giám sát)"
fi
rm -f "$STATE/clean_stop"

# launchd gửi SIGTERM khi tắt máy / khởi động lại (hoặc khi có người gỡ daemon bằng sudo)
trap 'trap - TERM INT
touch "$STATE/clean_stop"
if [ -f "$STATE/updating" ]; then rm -f "$STATE/updating"; log "🔄 macsentryd dừng để cập nhật"
else send_now "🔴 Máy đang tắt / khởi động lại (hoặc macsentryd bị dừng)
Lúc: $(now)"; fi
[ -n "$AUTH_PID" ] && kill_tree "$AUTH_PID"; exit 0' TERM INT

# Theo dõi xác thực chạy nền (lib/auth.sh), đọc danh sách máy chủ tin cậy
auth_watch &
AUTH_PID=$!
resolve_trusted

# ---------------------------------------------------------------- vòng lặp chính

# Nhịp 2 giây. Tần suất từng nhóm kiểm tra chọn theo mức cần phản ứng nhanh và chi phí:
#   2s  hàng đợi tin của helper ES; kết nối truy cập từ xa (4s khi helper ES chạy)
#   4s  nghi reverse shell (10s khi helper ES chạy)
#   10s tự khởi động mới, dịch vụ từ xa, USB/ổ đĩa, app điều khiển từ xa
#   30s cổng mới, file nhạy cảm, Wazuh, agent, mạng/ổ đầy       60s tài khoản/firewall, cài cắm, tự bảo vệ, heartbeat
#   5 phút tư thế bảo mật, toàn vẹn LaunchDaemon
tick=0
while :; do
  t=$((BASE_T + SECONDS))   # không fork `date` mỗi nhịp

  [ $((tick % 30)) -eq 0 ] && { ES_UP=0; es_alive && ES_UP=1; }
  # Helper ES chạy → nó đã báo tức thì SSH / Screen Sharing / lệnh reverse shell, nên quét dự phòng thưa hơn
  if [ "$ES_UP" = 1 ]; then rem=2; rev=5; else rem=1; rev=2; fi
  [ $((tick % rem)) -eq 0 ] && check_remote "$t"
  check_spool
  [ $((tick % rev)) -eq 0 ] && check_revshell
  [ $((tick % 5)) -eq 0 ] && { check_system; check_hardware; check_remote_tools; }
  [ $((tick % 15)) -eq 0 ] && { check_listen; check_files; check_wazuh; check_agents; check_hardware_slow; }
  [ $((tick % 150)) -eq 0 ] && { check_posture; check_daemon_integrity; }   # trước daily_report: báo cáo cần số liệu tư thế
  [ $((tick % 30)) -eq 0 ] && { resolve_trusted; check_accounts; check_persistence; check_self; daily_report
    # Dead-man switch: dịch vụ ngoài (vd healthchecks.io) báo cho bạn khi KHÔNG nhận được ping nữa
    # (daemon bị bootout / kill hẳn / máy bị tắt nguồn — những lúc daemon không tự báo được)
    # URL đưa qua stdin, không để lộ trên dòng lệnh (`ps`) — ai có URL là giả được ping
    [ -n "$HEARTBEAT_URL" ] && printf 'url = "%s"\n' "$HEARTBEAT_URL" | curl -fsS -m 10 -o /dev/null -K - >/dev/null 2>&1 &
    cleanup_state; }
  tick=$((tick + 1))

  before=$SECONDS
  sleep 2 & wait $!   # wait để trap TERM chạy ngay, không đợi hết sleep
  # "sleep 2" kéo dài > 60s → máy đã ngủ trong lúc đó (đo riêng lệnh sleep, không tính các check chạy chậm)
  slept=$((SECONDS - before))
  if [ "$slept" -gt 60 ]; then
    info "☀️ Máy thức dậy
Lúc: $(now)
Đã ngủ khoảng: $(dur "$slept")"
  fi
done
