#!/bin/sh
# macsentryd — daemon cảnh báo an ninh chạy bằng root qua LaunchDaemon: chạy từ lúc bật máy (trước khi
# đăng nhập), user thường không tắt/sửa được. Gửi Telegram khi có:
#   - Bật / tắt máy, máy thức dậy
#   - Kết nối truy cập từ xa (SSH, Screen Sharing/VNC, Remote Desktop, SMB, AFP) mở/đóng, đăng nhập SSH
#   - Nhập sai mật khẩu (màn hình khoá, SSH, sudo), dùng sudo
#   - Thay đổi hệ thống: LaunchAgent/Daemon mới, user/admin mới, firewall, Gatekeeper, dịch vụ từ xa bật/tắt,
#     cổng mới mở ra mạng
#   - Phần cứng & mạng: USB, ổ đĩa ngoài, nguồn điện/pin, đổi mạng, ổ đĩa sắp đầy
# Cấu hình: /etc/macsentry.conf (TOKEN=..., CHAT=...), chỉ root đọc được.

CONF=${CONF:-/etc/macsentry.conf}
LOG=${LOG:-/var/log/macsentry.log}       # cờ sappnd: chỉ được ghi thêm, không xoá/sửa được
STATE=${STATE:-/var/db/macsentry}
. "$CONF" || exit 1
mkdir -p "$STATE/conn" "$STATE/throttle"
HOST=$(scutil --get ComputerName 2>/dev/null || hostname)
MAIN_PID=$$

# ---------------------------------------------------------------- tiện ích

now() { date '+%d/%m/%Y %H:%M:%S'; }
log() { printf '%s %s\n' "$(now)" "$(printf '%s' "$*" | tr '\n' ' ')" >> "$LOG"; }
post() { # $1 = nội dung, $2 = timeout giây, $3 = im lặng (true/false); in ra mã HTTP
  [ -n "$DRYRUN" ] && { echo 200; return; }   # chạy thử: không gửi thật
  curl -s -m "$2" -o /dev/null -w '%{http_code}' "https://api.telegram.org/bot$TOKEN/sendMessage" \
    --data-urlencode "chat_id=$CHAT" --data-urlencode "disable_notification=${3:-false}" \
    --data-urlencode "text=🛡 $HOST
$1"
}
# Gửi nền, thử lại tới ~5 phút (lúc mới bật/thức máy có thể chưa có mạng)
send() { # $1 = nội dung, $2 = im lặng
  log "$1"
  ( i=0; while [ $i -lt 30 ]; do [ "$(post "$1" 10 "${2:-false}")" = 200 ] && exit 0; i=$((i+1)); sleep 10; done
    log "Gửi Telegram thất bại" ) &
}
alert() { send "$1" false; }   # có chuông
info() { send "$1" true; }     # im lặng
# Gửi ngay và chờ (dùng khi sắp tắt máy)
send_now() { log "$1"; post "$1" 5 false >/dev/null; }

# Chống spam: trả về 0 nếu khoá $1 chưa gửi trong $2 giây gần đây
throttle() {
  f="$STATE/throttle/$(printf '%s' "$1" | cksum | cut -d' ' -f1)"
  t=$(date +%s); l=$(cat "$f" 2>/dev/null || echo 0)
  [ $((t - l)) -ge "$2" ] || return 1
  echo "$t" > "$f"
}

dur() { s=$1; if [ $s -lt 60 ]; then echo "${s}s"; elif [ $s -lt 3600 ]; then echo "$((s/60))m $((s%60))s"; else echo "$((s/3600))h $((s%3600/60))m"; fi; }

port_name() {
  case $1 in
    22) echo "SSH";; 5900) echo "Screen Sharing/VNC";; 3283) echo "Apple Remote Desktop";;
    445) echo "Chia sẻ file SMB";; 548) echo "AFP";; *) echo "cổng $1";;
  esac
}
REMOTE_PORTS_RE='^(22|5900|3283|445|548)$'

# So sánh danh sách mới ($2) với danh sách đã lưu ($1). Lần đầu chỉ lưu làm mốc, không báo.
# In ra các dòng "+ ..." (mới) và "- ..." (mất).
diff_state() {
  f="$STATE/$1"
  if [ ! -f "$f" ]; then printf '%s\n' "$2" | sed '/^$/d' | sort > "$f"; return; fi
  printf '%s\n' "$2" | sed '/^$/d' | sort > "$f.new"
  comm -13 "$f" "$f.new" | sed 's/^/+ /'
  comm -23 "$f" "$f.new" | sed 's/^/- /'
  mv "$f.new" "$f"
}

# ---------------------------------------------------------------- 1. khởi động / tắt máy

boot=$(sysctl -n kern.boottime | sed 's/^{ sec = \([0-9]*\).*/\1/')
if [ "$(cat "$STATE/lastboot" 2>/dev/null)" != "$boot" ]; then
  echo "$boot" > "$STATE/lastboot"
  rm -f "$STATE/conn/"* "$STATE/remote_conns" "$STATE/who"
  alert "🟢 Máy vừa khởi động
Bật lúc: $(date -r "$boot" '+%d/%m/%Y %H:%M:%S')"
else
  info "▶️ macsentryd chạy lại (máy bật từ $(date -r "$boot" '+%d/%m/%Y %H:%M:%S'))"
fi

# launchd gửi SIGTERM khi tắt máy / khởi động lại (hoặc khi có người gỡ daemon bằng sudo)
trap 'trap - TERM INT; send_now "🔴 Máy đang tắt / khởi động lại (hoặc macsentryd bị dừng)
Lúc: $(now)"; [ -n "$AUTH_PID" ] && { pkill -P "$AUTH_PID"; kill "$AUTH_PID"; } 2>/dev/null; exit 0' TERM INT

# ---------------------------------------------------------------- 2. xác thực (đọc log hệ thống, chạy nền)

user_of_uuid() { dscl . -search /Users GeneratedUID "$1" 2>/dev/null | awk 'NR==1{print $1}'; }

auth_watch() {
  /usr/bin/log stream --style compact --predicate '
      (process == "opendirectoryd" AND eventMessage CONTAINS "Authentication failed for")
   OR (eventMessage CONTAINS "OpenDirectory - The authtok is incorrect")
   OR (process BEGINSWITH "sshd" AND eventMessage CONTAINS "authentication error for")
   OR (process == "sudo" AND eventMessage CONTAINS "COMMAND=")' 2>/dev/null |
  while IFS= read -r line; do
    kill -0 "$MAIN_PID" 2>/dev/null || exit 0   # daemon chính đã chết → thoát, tránh gửi trùng
    proc=$(printf '%s' "$line" | awk '{print $4}' | sed 's/\[.*//')
    case "$line" in
      *"OpenDirectory - The authtok is incorrect"*)
        # Lỗi PAM từ sshd/sudo: đánh dấu để không báo trùng thành "sai mật khẩu" chung
        touch "$STATE/auth_marker" ;;
      *"Authentication failed for"*)
        uuid=$(printf '%s' "$line" | sed -n 's/.*Authentication failed for [^(]*(\([0-9A-Fa-f-]*\)).*/\1/p')
        u=$(user_of_uuid "$uuid"); u=${u:-?}
        # Đợi xem có phải từ sshd/sudo không (dòng PAM tới ngay sau); nếu không → màn hình khoá / hộp thoại xác thực
        ( sleep 3
          m=$(stat -f %m "$STATE/auth_marker" 2>/dev/null || echo 0)
          if [ $(( $(date +%s) - m )) -gt 5 ] && throttle "od_$u" 30; then
            alert "🔐 Nhập sai mật khẩu
User: $u
(màn hình khoá / đăng nhập / hộp thoại xác thực)
Lúc: $(now)"
          fi ) & ;;
      *"authentication error for"*)
        touch "$STATE/auth_marker"
        who_ip=$(printf '%s' "$line" | sed -n 's/.*authentication error for \(.*\) from \(.*\)$/\1 \2/p')
        u=${who_ip% *}; ip=${who_ip##* }
        if throttle "sshfail_$ip" 300; then
          alert "🔐 SSH sai mật khẩu
User: $u
IP: $ip
Lúc: $(now)
(các lần lặp lại từ IP này trong 5 phút sẽ không báo)"
        else log "SSH sai mật khẩu: $u từ $ip"; fi ;;
      *"incorrect password attempt"*)
        msg=$(printf '%s' "$line" | sed 's/.*sudo\[[^]]*\] *//')
        alert "🔐 sudo nhập sai mật khẩu
$msg" ;;
      *"COMMAND="*)
        msg=$(printf '%s' "$line" | sed 's/.*sudo\[[^]]*\] *//')
        throttle "sudo_$msg" 10 && info "⚡️ sudo
$msg" ;;
    esac
  done
}
auth_watch &
AUTH_PID=$!

# ---------------------------------------------------------------- 3. kết nối truy cập từ xa (mỗi 2 giây)

check_remote() {
  t=$1
  cur=$(netstat -an -p tcp | awk '$6=="ESTABLISHED" { n=split($4,a,"."); print a[n]" "$5 }' |
        awk -v re="$REMOTE_PORTS_RE" '$1 ~ re' | sort -u)
  diff_state remote_conns "$cur" | while read -r sign p r; do
    ip=${r%.*}; ip=${ip#::ffff:}; key=$(printf '%s_%s' "$p" "$r")
    if [ "$sign" = "+" ]; then
      echo "$t" > "$STATE/conn/$key"
      alert "🚨 Kết nối $(port_name "$p")
IP: $ip:${r##*.}
Lúc: $(now)"
    else
      start=$(cat "$STATE/conn/$key" 2>/dev/null || echo "$t"); rm -f "$STATE/conn/$key"
      info "🔌 Kết thúc $(port_name "$p")
IP: $ip:${r##*.}
Thời lượng: $(dur $((t - start)))"
    fi
  done

  # Đăng nhập SSH thành công (who có host trong ngoặc; bỏ tmux/screen/X11)
  logins=$(who | awk '/\(/ && !/\(:/ && !/tmux/ {print $1, $2, $NF}')
  diff_state who "$logins" | while read -r sign u tty host; do
    host=$(printf '%s' "$host" | tr -d '()')
    if [ "$sign" = "+" ]; then alert "🔑 Đăng nhập SSH thành công
User: $u
Từ: $host ($tty)"; fi
  done
}

# ---------------------------------------------------------------- 4. thay đổi hệ thống (mỗi 10 giây)

check_system() {
  # LaunchAgent/LaunchDaemon mới — cách phổ biến để mã độc tự chạy lại
  items=$(ls -1d /Library/LaunchAgents/* /Library/LaunchDaemons/* /Users/*/Library/LaunchAgents/* 2>/dev/null)
  diff_state persistence "$items" | while read -r sign path; do
    if [ "$sign" = "+" ]; then
      prog=$(plutil -extract Program raw -o - "$path" 2>/dev/null || plutil -extract ProgramArguments.0 raw -o - "$path" 2>/dev/null)
      alert "🧩 Có chương trình tự khởi động mới
File: $path
Chạy: ${prog:-?}"
    else info "🧩 Đã gỡ chương trình tự khởi động
File: $path"; fi
  done

  # Tài khoản user (UID >= 500) và nhóm admin
  users=$(dscl . -list /Users UniqueID | awk '$2 >= 500 {print $1}')
  diff_state users "$users" | while read -r sign u; do
    [ "$sign" = "+" ] && alert "👥 Có tài khoản user mới: $u" || alert "👥 Đã xoá tài khoản user: $u"
  done
  admins=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | cut -d: -f2- | tr ' ' '\n')
  diff_state admins "$admins" | while read -r sign u; do
    [ "$sign" = "+" ] && alert "👑 $u vừa được cấp quyền ADMIN" || info "👑 $u bị gỡ quyền admin"
  done

  # Firewall & Gatekeeper
  fw=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep -q 'enabled' && echo "BẬT" || echo "TẮT")
  diff_state firewall "$fw" | while read -r sign v; do
    [ "$sign" = "+" ] && { [ "$v" = "TẮT" ] && alert "🧱 Firewall vừa bị TẮT" || info "🧱 Firewall đã bật"; }
  done
  gk=$(spctl --status 2>/dev/null | grep -q 'enabled' && echo "BẬT" || echo "TẮT")
  diff_state gatekeeper "$gk" | while read -r sign v; do
    [ "$sign" = "+" ] && { [ "$v" = "TẮT" ] && alert "🛂 Gatekeeper vừa bị TẮT (cho chạy app không rõ nguồn gốc)" || info "🛂 Gatekeeper đã bật"; }
  done

  # Dịch vụ truy cập từ xa bật/tắt (đang lắng nghe trên cổng của nó)
  services=$(netstat -an -p tcp | awk '$6=="LISTEN" { n=split($4,a,"."); print a[n] }' |
             awk -v re="$REMOTE_PORTS_RE" '$1 ~ re' | sort -u)
  diff_state services "$services" | while read -r sign p; do
    [ "$sign" = "+" ] && alert "📡 Vừa BẬT $(port_name "$p") (cổng $p) — máy nhận kết nối từ xa" \
                      || info "📡 Đã tắt $(port_name "$p") (cổng $p)"
  done
}

# Cổng mới mở ra mạng (mỗi 30 giây). Chỉ báo lần đầu thấy mỗi cặp (chương trình, cổng) để tránh ồn.
check_listen() {
  cur=$(lsof +c 0 -nP -iTCP -sTCP:LISTEN -F cn 2>/dev/null |
        awk '/^c/ { c=substr($0,2) } /^n/ { name=substr($0,2); if (name ~ /^(127\.|\[::1\]|localhost)/) next
                                           n=split(name,a,":"); print c"|"a[n] }' | sort -u)
  seen="$STATE/listen_seen"
  if [ ! -f "$seen" ]; then printf '%s\n' "$cur" > "$seen"; return; fi
  printf '%s\n' "$cur" | while IFS='|' read -r cmd port; do
    [ -n "$cmd" ] || continue
    grep -qxF "$cmd|$port" "$seen" && continue
    echo "$cmd|$port" >> "$seen"
    info "🆕 Cổng mới mở ra mạng
Chương trình: $cmd
Cổng: $port"
  done
}

# ---------------------------------------------------------------- 5. phần cứng & mạng (mỗi 10 giây)

check_hardware() {
  usb=$(ioreg -p IOUSB -w0 | sed -n 's/.*+-o \(.*\)@[0-9a-f]*  <class.*/\1/p' | grep -v -E '^(Root|AppleT[0-9]+USBXHCI|USB[0-9.]* (Gen[0-9]+ )?Hub)$')
  diff_state usb "$usb" | while read -r sign name; do
    [ "$sign" = "+" ] && alert "🔌 Vừa cắm thiết bị USB: $name" || info "🔌 Đã rút thiết bị USB: $name"
  done

  vols=$(ls -1 /Volumes 2>/dev/null | grep -v -E '^(Macintosh HD|Recovery|Preboot|VM|Data)$')
  diff_state volumes "$vols" | while read -r sign name; do
    [ "$sign" = "+" ] && alert "💾 Vừa gắn ổ đĩa: $name" || info "💾 Đã tháo ổ đĩa: $name"
  done

  # Nguồn điện / pin (chỉ máy có pin)
  batt=$(pmset -g batt)
  if printf '%s' "$batt" | grep -q InternalBattery; then
    src=$(printf '%s' "$batt" | sed -n "s/.*'\(.*\)'.*/\1/p" | head -1)
    pct=$(printf '%s' "$batt" | grep -o '[0-9]*%' | head -1 | tr -d %)
    diff_state power "$src" | while read -r sign v; do
      [ "$sign" = "+" ] && { [ "$v" = "Battery Power" ] && alert "🔋 Vừa RÚT SẠC (đang chạy pin $pct%)" || info "🔌 Đã cắm sạc ($pct%)"; }
    done
    if [ "${pct:-100}" -le 15 ] && [ "$src" = "Battery Power" ]; then throttle battlow 3600 && alert "🪫 Pin yếu: $pct%"; fi
  fi

  # Mạng: interface mặc định + IP + tên Wi-Fi
  iface=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
  ip=$( [ -n "$iface" ] && ipconfig getifaddr "$iface" 2>/dev/null)
  ssid=$( [ -n "$iface" ] && ipconfig getsummary "$iface" 2>/dev/null | awk -F' SSID : ' '/ SSID : /{print $2; exit}')
  net="${iface:-không có mạng} ${ip:-} ${ssid:+Wi-Fi: $ssid}"
  diff_state network "$net" | while read -r sign v; do
    [ "$sign" = "+" ] && info "🌐 Mạng thay đổi: $v"
  done

  # Ổ đĩa hệ thống sắp đầy
  used=$(df -k /System/Volumes/Data 2>/dev/null | awk 'NR==2 {print $5}' | tr -d %)
  if [ "${used:-0}" -ge 90 ]; then throttle diskfull 21600 && alert "💽 Ổ đĩa sắp đầy: đã dùng $used%"; fi
}

# ---------------------------------------------------------------- vòng lặp chính

last=$(date +%s); tick=0
while :; do
  t=$(date +%s)
  # Vòng lặp 2s mà cách nhau > 60s → máy vừa ngủ dậy
  if [ $((t - last)) -gt 60 ]; then
    info "☀️ Máy thức dậy
Lúc: $(now)
Đã ngủ khoảng: $(dur $((t - last)))"
  fi
  last=$t

  check_remote "$t"
  [ $((tick % 5)) -eq 0 ] && { check_system; check_hardware; }
  [ $((tick % 15)) -eq 0 ] && check_listen
  tick=$((tick + 1))

  sleep 2 & wait $!   # wait để trap TERM chạy ngay, không đợi hết sleep
done
