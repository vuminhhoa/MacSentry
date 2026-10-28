#!/bin/bash
# Cài macsentryd (LaunchDaemon chạy bằng root) + helper Endpoint Security macsentry-es.
# Chạy: ./build.sh rồi sudo ./daemon/install.sh
#   --reconfigure  nhập lại bot Telegram riêng cho daemon và URL heartbeat (mặc định giữ /etc/macsentry.conf cũ)
#   --auto         không hỏi gì (app gọi khi cài / cập nhật): lần đầu dùng chung bot của app, không heartbeat, bật exec.
#                  Tự bật khi không có terminal. Cấu hình cũ chưa có token mà app đã có Telegram → điền token của app.
set -euo pipefail
RECONFIGURE=0; AUTO=0
for arg in "$@"; do
  case $arg in
    --reconfigure) RECONFIGURE=1 ;;
    --auto) AUTO=1 ;;
    *) echo "Tham số không hợp lệ: $arg" >&2; exit 2 ;;
  esac
done
[ -t 0 ] || AUTO=1
[ "$(id -u)" = 0 ] || { echo "Cần quyền root: sudo $0"; exit 1; }
cd "$(dirname "$0")"
LABEL=io.github.vuminhhoa.macsentry.daemon
ES_LABEL=io.github.vuminhhoa.macsentry.es
ES_BIN=../build/macsentry-es
DAEMON_BIN=../build/macsentryd
TARGET_USER=${SUDO_USER:-$USER}
TARGET_HOME=$(dscl . -read "/Users/$TARGET_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
SRC_CONF="${TARGET_HOME:-/var/root}/Library/Application Support/MacSentry/telegram.json"
for b in "$ES_BIN" "$DAEMON_BIN"; do [ -x "$b" ] || { echo "Chưa có $b — chạy ./build.sh trước (không cần sudo)"; exit 1; }; done

# ---- cấu hình: giữ file cũ (có thể đã có HEARTBEAT_URL, token riêng) trừ khi --reconfigure
# Mỗi giá trị phải nằm gọn trên một dòng của /etc/macsentry.conf: một giá trị có xuống dòng (vd token trong
# telegram.json của user) sẽ thêm dòng mới như ES_EXEC=0 hay HEARTBEAT_URL=... vào file cấu hình của root.
valid_id() { [[ $1 =~ ^[A-Za-z0-9:_-]*$ ]]; }          # token bot, chat ID: chữ, số, : _ - (rỗng = chưa có)
valid_url() { [[ $1 =~ ^[^[:space:][:cntrl:]]*$ ]]; }  # URL heartbeat: không khoảng trắng, không ký tự điều khiển
app_telegram() { # đọc token và chat của app (rỗng nếu app chưa cấu hình Telegram)
  APP_TOKEN=""; CHAT=""
  [ -f "$SRC_CONF" ] || return 0
  APP_TOKEN=$(plutil -extract botToken raw -o - "$SRC_CONF" 2>/dev/null || true)
  CHAT=$(plutil -extract chatId raw -o - "$SRC_CONF" 2>/dev/null || true)
}
if [ "$AUTO" = 1 ]; then
  app_telegram
  if ! valid_id "$APP_TOKEN" || ! valid_id "$CHAT"; then
    echo "Bỏ qua Telegram của app: token hoặc chat ID có ký tự không hợp lệ" >&2
    APP_TOKEN=""; CHAT=""
  fi
  if [ ! -f /etc/macsentry.conf ]; then
    # Chưa có Telegram thì daemon vẫn chạy và ghi log; app cài lại sau khi lưu Telegram
    ( umask 077; printf 'TOKEN=%s\nCHAT=%s\nHEARTBEAT_URL=\nES_EXEC=1\nFIM=auto\n' "$APP_TOKEN" "$CHAT" > /etc/macsentry.conf )
  elif [ -n "$APP_TOKEN" ] && grep -q '^TOKEN=$' /etc/macsentry.conf; then
    # Token / chat ID chỉ gồm chữ, số, : _ - (valid_id ở trên) → dùng an toàn trong sed
    sed -i '' -e "s|^TOKEN=\$|TOKEN=$APP_TOKEN|" -e "s|^CHAT=.*|CHAT=$CHAT|" /etc/macsentry.conf
  fi
elif [ ! -f /etc/macsentry.conf ] || [ "$RECONFIGURE" = 1 ]; then
  [ -f "$SRC_CONF" ] || { echo "Chưa có $SRC_CONF — mở MacSentry.app → Cài đặt để nhập bot Telegram trước"; exit 1; }
  APP_TOKEN=$(plutil -extract botToken raw -o - "$SRC_CONF")
  CHAT=$(plutil -extract chatId raw -o - "$SRC_CONF")
  echo "Bot Telegram RIÊNG cho daemon (khuyên dùng: tạo bot mới với @BotFather, rồi /start bot đó trong chat của bạn)."
  echo "Lý do: token của app nằm trong thư mục user, phần mềm độc chạy bằng user đọc được và xoá được cảnh báo của bot đó."
  read -r -s -p "Token bot daemon (Enter = dùng chung bot của app): " TOKEN; echo
  TOKEN=${TOKEN:-$APP_TOKEN}
  echo "URL heartbeat (dead-man switch, vd https://hc-ping.com/<uuid> từ healthchecks.io — daemon ping mỗi phút,"
  echo "dịch vụ đó báo cho bạn khi mất ping: daemon bị gỡ / máy bị tắt nguồn)."
  read -r -p "URL heartbeat (Enter = bỏ qua): " HEARTBEAT_URL
  echo "Theo dõi lệnh nguy hiểm (exec: reverse shell, đọc keychain, tắt bảo vệ...) tốn thêm ~3% một nhân CPU"
  echo "trên máy chạy nhiều tiến trình (IDE, build). Tắt thì vẫn còn các giám sát khác."
  read -r -p "Bật theo dõi exec? [Y/n]: " ES_EXEC_ANS
  case $ES_EXEC_ANS in [nN]*) ES_EXEC=0 ;; *) ES_EXEC=1 ;; esac
  if ! valid_id "$TOKEN" || ! valid_id "$CHAT"; then echo "Token hoặc chat ID chỉ được gồm chữ, số, : _ -" >&2; exit 1; fi
  valid_url "$HEARTBEAT_URL" || { echo "URL heartbeat không được có khoảng trắng" >&2; exit 1; }
  # FIM=auto: file nhạy cảm mà Wazuh syscheck đã theo dõi thời gian thực thì để Wazuh lo; FIM=local: MacSentry tự theo dõi hết
  ( umask 077; printf 'TOKEN=%s\nCHAT=%s\nHEARTBEAT_URL=%s\nES_EXEC=%s\nFIM=auto\n' "$TOKEN" "$CHAT" "$HEARTBEAT_URL" "$ES_EXEC" > /etc/macsentry.conf )
fi
chown root:wheel /etc/macsentry.conf; chmod 600 /etc/macsentry.conf

# Máy chủ tin cậy: shell kết nối tới đây không bị coi là reverse shell (chỉ ghi log). Không ghi đè nếu đã có.
if [ ! -e /etc/macsentry.trusted ]; then
  cat > /etc/macsentry.trusted <<'TRUSTED'
# Máy chủ tin cậy của MacSentry — mỗi dòng "tên-miền:cổng" (hoặc "tên-miền" = mọi cổng).
# Shell/netcat kết nối tới đây sẽ chỉ được ghi log, không gửi cảnh báo reverse shell.
# Sửa: sudo nano /etc/macsentry.trusted (daemon tự đọc lại sau ~1 phút)
TRUSTED
  chown root:wheel /etc/macsentry.trusted; chmod 644 /etc/macsentry.trusted
fi

# Agent riêng cần giám sát thêm (ngoài danh mục có sẵn trong daemon). Không ghi đè nếu đã có.
if [ ! -e /etc/macsentry.agents ]; then
  cat > /etc/macsentry.agents <<'AGENTS'
# Agent quan trọng cần giám sát thêm (danh mục có sẵn: EDR/antivirus, MDM, firewall, VPN, điều khiển từ xa).
# Mỗi dòng: Tên | tiến trình,cách,nhau,dấu,phẩy | thư mục cài (có mới theo dõi) | file cấu hình (glob, cách nhau bằng dấu cách)
# Ví dụ:
# Agent công ty | company-agentd,company-helper | /Library/CompanyAgent | /Library/CompanyAgent/etc/*.conf
AGENTS
  chown root:wheel /etc/macsentry.agents; chmod 644 /etc/macsentry.agents
fi

# Danh sách cho phép của helper ES (lệnh hợp lệ hay chạy, không cần báo). Không ghi đè nếu đã có.
if [ ! -e /etc/macsentry.allow ]; then
  cat > /etc/macsentry.allow <<'ALLOW'
# Lệnh khớp một dòng (regex, không phân biệt hoa thường) sẽ chỉ được ghi log, không cảnh báo.
# Chuỗi được so: "<lệnh đầy đủ> || <chuỗi tiến trình cha>". Sửa: sudo nano /etc/macsentry.allow (tự đọc lại sau ~1 phút)
# Ví dụ — Claude Code đọc token đăng nhập của chính nó trong Keychain (bỏ dấu # ở dòng dưới để bật):
# (^|/)security find-generic-password .*-s Claude Code-credentials\b.*\|\| claude\(
ALLOW
  chown root:wheel /etc/macsentry.allow; chmod 644 /etc/macsentry.allow
fi

mkdir -p /usr/local/libexec /var/db/macsentry
install -o root -g wheel -m 755 "$DAEMON_BIN" /usr/local/libexec/macsentryd
rm -rf /usr/local/libexec/macsentry   # module shell của bản cũ (daemon nay là một binary Swift)
install -o root -g wheel -m 755 "$ES_BIN" /usr/local/libexec/macsentry-es
chmod 700 /var/db/macsentry

# Log: ai cũng đọc được (app hiển thị tab "Sự kiện"), chỉ root ghi, và chỉ được ghi thêm
# (Chỉ làm lần đầu: file đã có cờ sappnd thì touch/chmod đều bị từ chối, kể cả root)
if [ ! -e /var/log/macsentry.log ]; then
  touch /var/log/macsentry.log; chown root:wheel /var/log/macsentry.log; chmod 644 /var/log/macsentry.log
  chflags sappnd /var/log/macsentry.log
fi

write_plist() { # $1 = label, $2.. = ProgramArguments
  label=$1; shift
  args=""; for a in "$@"; do args="$args<string>$a</string>"; done
  cat > "/Library/LaunchDaemons/$label.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$label</string>
  <key>ProgramArguments</key><array>$args</array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ExitTimeOut</key><integer>15</integer>
  <!-- Ưu tiên thấp (khuyến nghị của launchd.plist(5)): macOS giới hạn CPU / I/O của job để không ảnh hưởng
       công việc của người dùng; giám sát chậm vài giây khi máy bận là chấp nhận được -->
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
</dict></plist>
PLIST
  chown root:wheel "/Library/LaunchDaemons/$label.plist"; chmod 644 "/Library/LaunchDaemons/$label.plist"
}
# Bản cũ dùng label khác: gỡ job của chúng để không chạy song song hai daemon
for old in /Library/LaunchDaemons/*.macsentry.daemon.plist /Library/LaunchDaemons/*.macsentry.es.plist; do
  [ -e "$old" ] || continue
  old_label=$(basename "$old" .plist)
  if [ "$old_label" = "$LABEL" ] || [ "$old_label" = "$ES_LABEL" ]; then continue; fi
  touch /var/db/macsentry/updating /var/db/macsentry/clean_stop
  launchctl bootout "system/$old_label" 2>/dev/null || true
  rm -f "$old"
done

write_plist $LABEL /usr/local/libexec/macsentryd
write_plist $ES_LABEL /usr/local/libexec/macsentry-es

restart() { # $1 = label
  launchctl bootout "system/$1" 2>/dev/null || true
  for _ in $(seq 1 20); do launchctl print "system/$1" >/dev/null 2>&1 || break; sleep 1; done
  for _ in 1 2 3 4 5; do
    launchctl bootstrap system "/Library/LaunchDaemons/$1.plist" 2>/dev/null && return 0
    sleep 2
  done
  echo "Không khởi động được $1"; return 1
}

# Daemon cũ thấy "updating" khi dừng → không báo nhầm là tắt máy; "clean_stop" → bản mới không báo nhầm là bị kill
# (bootout trả về ngay nhưng daemon cũ còn gửi tin trước khi thoát → restart() chờ nó dừng hẳn)
# "just_updated": file của MacSentry đổi trong 10 phút tới là do cài đặt → tin im lặng thay vì cảnh báo
touch /var/db/macsentry/updating /var/db/macsentry/clean_stop /var/db/macsentry/just_updated
restart $ES_LABEL
restart $LABEL
rm -f /var/db/macsentry/updating

for _ in 1 2 3 4 5; do
  launchctl print system/$LABEL 2>/dev/null | grep -q "state = running" && { echo "✅ macsentryd đang chạy. Log: /var/log/macsentry.log"; break; }
  sleep 1
done
sleep 4
if [ -f /var/db/macsentry/es_alive ]; then
  echo "✅ macsentry-es (Endpoint Security) đang chạy"
else
  cat <<MSG
⚠️  macsentry-es chưa đọc được sự kiện Endpoint Security: $(tail -1 /var/db/macsentry/es_status 2>/dev/null)
   Cấp Full Disk Access: Cài đặt → Quyền riêng tư & Bảo mật → Truy cập toàn bộ ổ đĩa → nút + →
   Cmd+Shift+G gõ /usr/local/libexec/macsentry-es → bật công tắc. Helper tự thử lại sau ~30 giây.
   Làm tương tự cho /usr/local/libexec/macsentryd (daemon cần để đọc đủ các vị trí được macOS bảo vệ).
MSG
  sudo -u "${SUDO_USER:-root}" open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles" 2>/dev/null || true
fi
