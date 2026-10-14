#!/bin/sh
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
  local f t l
  f="$STATE/throttle/$(printf '%s' "$1" | cksum | cut -d' ' -f1)"
  t=$(date +%s); l=$(cat "$f" 2>/dev/null || echo 0)
  [ $((t - l)) -ge "$2" ] || return 1
  echo "$t" > "$f"
}

# Helper Endpoint Security (macsentry-es) còn sống: nó chạm file này mỗi phút khi eslogger đang chạy được
es_alive() { local f="$STATE/es_alive"; [ -f "$f" ] && [ $(( $(date +%s) - $(stat -f %m "$f") )) -lt 180 ]; }

# Hàng đợi tin nhắn: helper ghi file "<alert|info>\n<nội dung>" vào đây, daemon gửi đi (helper không cần token)
SPOOL="$STATE/spool"
check_spool() {
  local f level body
  for f in "$SPOOL"/*.msg; do
    [ -f "$f" ] || continue
    level=$(head -1 "$f"); body=$(tail -n +2 "$f"); rm -f "$f"
    case $level in alert) alert "$body" ;; info) info "$body" ;; *) log "$body" ;; esac
  done
}

# In phần mới ghi thêm vào file $2 kể từ lần gọi trước (lần đầu chỉ ghi mốc). $1 = tên state.
tail_new() {
  local f size off
  f="$STATE/tail_$1"; size=$(stat -f %z "$2" 2>/dev/null) || return 0
  off=$(cat "$f" 2>/dev/null); echo "$size" > "$f"
  [ -n "$off" ] || return 0
  [ "$size" -lt "$off" ] && off=0   # file bị xoay vòng / làm mới
  [ "$size" -gt "$off" ] && tail -c +"$((off + 1))" "$2" | head -c 200000
}

# Che giá trị bí mật trước khi gửi nội dung file ra Telegram (vd "export API_TOKEN=abc" → "export API_TOKEN=***")
mask_secrets() {
  sed -E 's/((KEY|TOKEN|SECRET|PASS|PASSWORD|PWD|AUTH|CREDENTIAL)[A-Za-z0-9_]*[[:space:]]*[=:][[:space:]]*).*/\1***/I'
}

dur() { local s=$1; if [ $s -lt 60 ]; then echo "${s}s"; elif [ $s -lt 3600 ]; then echo "$((s/60))m $((s%60))s"; else echo "$((s/3600))h $((s%3600/60))m"; fi; }

port_name() {
  case $1 in
    22) echo "SSH";; 5900) echo "Screen Sharing/VNC";; 3283) echo "Apple Remote Desktop";;
    445) echo "Chia sẻ file SMB";; 548) echo "AFP";; 3031) echo "Remote Apple Events";; *) echo "cổng $1";;
  esac
}
REMOTE_PORTS_RE='^(22|5900|3283|445|548|3031)$'

# So sánh danh sách mới ($2) với danh sách đã lưu ($1). Lần đầu chỉ lưu làm mốc, không báo.
# In ra các dòng "+ ..." (mới) và "- ..." (mất).
diff_state() {
  local f
  f="$STATE/$1"
  # $3 = "nonempty": danh sách không bao giờ rỗng thật (user, app, ...) → rỗng nghĩa là lệnh lỗi, bỏ qua lần này
  if [ "$3" = nonempty ] && [ -z "$(printf '%s' "$2" | tr -d '[:space:]')" ]; then return; fi
  if [ ! -f "$f" ]; then printf '%s\n' "$2" | sed '/^$/d' | sort > "$f"; return; fi
  printf '%s\n' "$2" | sed '/^$/d' | sort > "$f.new"
  comm -13 "$f" "$f.new" | sed 's/^/+ /'
  comm -23 "$f" "$f.new" | sed 's/^/- /'
  mv "$f.new" "$f"
}

# Theo dõi nội dung file qua mã băm. $1 = tên state, $2 = danh sách file.
# In ra "changed|new|removed <path>" (lần đầu chỉ lưu mốc).
# $2 là danh sách mỗi dòng một file (đường dẫn được phép có dấu cách)
hash_changes() {
  local sums
  sums=$(printf '%s\n' "$2" | while IFS= read -r f; do
           [ -f "$f" ] && printf '%s %s\n' "$(shasum -a 256 "$f" 2>/dev/null | cut -c1-16)" "$f"; done)
  diff_state "$1" "$sums" | awk '{ sign = $1; f = substr($0, length($1) + length($2) + 3); s[f] = s[f] sign } END {
      for (f in s) print (length(s[f]) == 2 ? "changed" : (s[f] == "+" ? "new" : "removed")), f }'
}
# Trả về 0 nếu danh sách file $2 (mỗi dòng một file) có thay đổi về ctime / kích thước / thành phần
# (ctime: mọi lần ghi hay đổi metadata đều cập nhật, không đặt lại được bằng touch như mtime)
# so với lần gọi trước cùng khoá $1 — dùng để bỏ qua việc băm (shasum) khi không có gì đổi.
stat_changed() {
  local f sig
  f="$STATE/statsig_$1"
  sig=$(printf '%s\n' "$2" | tr '\n' '\0' | xargs -0 stat -f '%c %z %N' 2>/dev/null)
  [ -f "$f" ] && [ "$sig" = "$(cat "$f")" ] && return 1
  printf '%s\n' "$sig" > "$f"
}

copy_of() { echo "$STATE/files/$(printf '%s' "$1" | tr '/' '_')"; }

# ---------------------------------------------------------------- chi tiết để phân biệt cảnh báo thật / giả

# Chữ ký số của file thực thi / app: Apple, nhà phát hành (Team ID), hay không ký
sig_of() {
  local out auth team
  [ -e "$1" ] || { echo "? (không tìm thấy file)"; return; }
  out=$(codesign -dv --verbose=2 "$1" 2>&1)
  case $out in *"not signed"*) echo "⚠️ KHÔNG có chữ ký số"; return ;; esac
  auth=$(printf '%s\n' "$out" | sed -n 's/^Authority=//p' | head -1)
  team=$(printf '%s\n' "$out" | sed -n 's/^TeamIdentifier=//p' | grep -v 'not set')
  case $auth in
    "Software Signing"|"macOS Software Signing") echo "✅ Apple (thành phần hệ thống)" ;;
    "") echo "⚠️ ký ad-hoc (không rõ nhà phát hành)" ;;
    *) case $auth in *"($team)"*) echo "$auth" ;; *) echo "$auth${team:+ (Team $team)}" ;; esac ;;
  esac
}

# Mô tả tiến trình: dòng lệnh, user, thời điểm chạy, chuỗi tiến trình cha, chữ ký số
proc_info() {
  local p cmd exe chain q n i
  p=$1
  cmd=$(ps -o command= -p "$p" 2>/dev/null | cut -c1-300)
  [ -n "$cmd" ] || { echo "(tiến trình $p đã kết thúc trước khi kịp ghi chi tiết)"; return; }
  # đường dẫn file thực thi = mục "txt" đầu tiên (ps chỉ cho tên, vd "bash")
  exe=$(lsof -nP -p "$p" -a -d txt -Fn 2>/dev/null | awk '/^n/ { print substr($0, 2); exit }')
  chain=""; q=$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' '); i=0
  while [ -n "$q" ] && [ "$q" -gt 1 ] && [ $i -lt 6 ]; do
    n=$(ps -o comm= -p "$q" 2>/dev/null | sed 's|.*/||'); [ -n "$n" ] || break
    chain="$chain ← $n($q)"; q=$(ps -o ppid= -p "$q" 2>/dev/null | tr -d ' '); i=$((i + 1))
  done
  printf 'Lệnh: %s\nUser: %s | Chạy từ: %s\nTiến trình cha:%s\nFile chạy: %s' "$cmd" \
    "$(ps -o user= -p "$p" | tr -d ' ')" "$(ps -o lstart= -p "$p")" "${chain:- launchd}" "${exe:-?} — $(sig_of "$exe")"
}

# Thông tin IP: tên miền (reverse DNS) và chủ sở hữu (whois) — có thể mất vài giây, gọi trong tiến trình nền
ip_info() {
  local ip name org
  ip=$1
  case $ip in 10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*|fe80:*|fd*)
    echo "IP mạng nội bộ / Tailscale"; return ;; esac
  name=$(host -W 2 "$ip" 2>/dev/null | awk '/domain name pointer/ { sub(/\.$/, "", $NF); print $NF; exit }')
  org=$(whois "$ip" 2>/dev/null | awk -F': *' 'tolower($1) ~ /^(orgname|org-name|descr|netname)$/ && !o { o = $2 }
                                               tolower($1) == "country" && !c { c = $2 } END { print o (c ? ", " c : "") }')
  echo "Tên miền: ${name:-không có} | Chủ IP: ${org:-không rõ}"
}

# Máy chủ tin cậy (/etc/macsentry.trusted, dạng "tên-miền:cổng" hoặc "tên-miền"): phân giải thành "ip:cổng tên"
TRUSTED=${TRUSTED:-/etc/macsentry.trusted}
resolve_trusted() {
  local entry h port ips ip
  sed 's/#.*//' "$TRUSTED" 2>/dev/null | while read -r entry; do
    [ -n "$entry" ] || continue
    h=${entry%%:*}; port=${entry#*:}; [ "$port" = "$entry" ] && port="*"
    ips=$(dscacheutil -q host -a name "$h" 2>/dev/null | awk '/_address:/ { print $2 }')
    [ -n "$ips" ] || ips=$h
    for ip in $ips; do echo "$ip:$port $h"; done
  done > "$STATE/trusted_resolved"
}
# $1 = "ip:cổng" → in tên máy chủ nếu tin cậy
trusted_name() {
  local ip port
  ip=${1%:*}; ip=${ip#[}; ip=${ip%]}; port=${1##*:}
  awk -v ip="$ip" -v port="$port" '{ split($1, a, ":"); p = a[length(a)]; sub(":[^:]*$", "", $1)
       if ($1 == ip && (p == port || p == "*")) { print $2; exit } }' "$STATE/trusted_resolved" 2>/dev/null
}

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
[ -n "$AUTH_PID" ] && { pkill -P "$AUTH_PID"; kill "$AUTH_PID"; } 2>/dev/null; exit 0' TERM INT

# ---------------------------------------------------------------- 2. xác thực (đọc log hệ thống, chạy nền)

user_of_uuid() { dscl . -search /Users GeneratedUID "$1" 2>/dev/null | awk 'NR==1{print $1}'; }

auth_watch() {
  while kill -0 "$MAIN_PID" 2>/dev/null; do auth_stream; sleep 5; done   # log stream chết → chạy lại
}
auth_stream() {
  /usr/bin/log stream --style compact --predicate '
      (process == "opendirectoryd" AND eventMessage CONTAINS "Authentication failed for")
   OR (eventMessage == "Verify basic credentials")
   OR (eventMessage CONTAINS "OpenDirectory - The authtok is incorrect")
   OR (process BEGINSWITH "sshd" AND eventMessage CONTAINS "authentication error for")
   OR (process == "sudo" AND eventMessage CONTAINS "COMMAND=")' 2>/dev/null |
  while IFS= read -r line; do
    kill -0 "$MAIN_PID" 2>/dev/null || exit 0   # daemon chính đã chết → thoát, tránh gửi trùng
    proc=$(printf '%s' "$line" | awk '{print $4}' | sed 's/\[.*//')
    case "$line" in
      *"(CFOpenDirectory) Verify basic credentials"*)
        # Tiến trình yêu cầu kiểm tra mật khẩu (dòng này tới ngay trước "Authentication failed for")
        printf '%s' "$line" | awk '{print $4}' > "$STATE/auth_caller" ;;
      *"OpenDirectory - The authtok is incorrect"*)
        # Lỗi PAM từ sshd/sudo: đánh dấu để không báo trùng thành "sai mật khẩu" chung
        touch "$STATE/auth_marker" ;;
      *"Authentication failed for"*)
        uuid=$(printf '%s' "$line" | sed -n 's/.*Authentication failed for [^(]*(\([0-9A-Fa-f-]*\)).*/\1/p')
        u=$(user_of_uuid "$uuid"); u=${u:-?}
        caller=$(cat "$STATE/auth_caller" 2>/dev/null); cname=${caller%%\[*}
        # Đợi xem có phải từ sshd/sudo không (dòng PAM tới ngay sau); nếu không → màn hình khoá / hộp thoại xác thực
        ( sleep 3
          m=$(stat -f %m "$STATE/auth_marker" 2>/dev/null || echo 0)
          [ $(( $(date +%s) - m )) -gt 5 ] || exit 0
          # Helper Endpoint Security đang chạy → nó báo (biết chính xác tiến trình gọi), ở đây chỉ ghi log
          es_alive && { log "Xác thực thất bại: $u qua ${caller:-?} (helper ES xử lý cảnh báo)"; exit 0; }
          case $cname in
            # Dịch vụ nền của Apple (Apple Account, iCloud Keychain/CDP, FileVault) tự kiểm tra mật khẩu đã lưu
            # sau khi bật máy/đăng nhập — không phải người gõ, chỉ ghi log
            akd|appleaccountd|cdpd|filevaultd)
              log "Dịch vụ hệ thống $caller kiểm tra mật khẩu của $u thất bại (không phải người nhập, không cảnh báo)"
              exit 0 ;;
            loginwindow) where="màn hình khoá / đăng nhập" ;;
            authorizationhost|SecurityAgent|SecurityPrivacyExtension) where="hộp thoại xác thực (quyền admin / Cài đặt)" ;;
            "") where="không rõ tiến trình" ;;
            *) where="tiến trình lạ" ;;
          esac
          if throttle "od_${u}_$cname" 30; then
            alert "🔐 Nhập sai mật khẩu
User: $u
Nguồn: $where
Tiến trình: ${caller:-?}
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
      *"a password is required"*)
        log "sudo -n bị từ chối (chưa nhập mật khẩu): $(printf '%s' "$line" | sed 's/.*sudo\[[^]]*\] *//')" ;;
      *"NOT in sudoers"*|*"command not allowed"*|*"not allowed to run"*)
        msg=$(printf '%s' "$line" | sed 's/.*sudo\[[^]]*\] *//')
        alert "⛔️ sudo bị TỪ CHỐI (user không có quyền)
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
resolve_trusted

# ---------------------------------------------------------------- 3. kết nối truy cập từ xa (mỗi 2 giây)

check_remote() {
  t=$1
  cur=$(netstat -an -p tcp | awk '$6=="ESTABLISHED" { n=split($4,a,"."); print a[n]" "$5 }' |
        awk -v re="$REMOTE_PORTS_RE" '$1 ~ re' | sort -u)
  diff_state remote_conns "$cur" | while read -r sign p r; do
    ip=${r%.*}; ip=${ip#::ffff:}; key=$(printf '%s_%s' "$p" "$r")
    if [ "$sign" = "+" ]; then
      echo "$t" > "$STATE/conn/$key"
      msg="🚨 Kết nối $(port_name "$p")
IP: $ip:${r##*.}
Lúc: $(now)"
      case $ip in
        127.*|::1|localhost) info "$msg
(từ chính máy này)" ;;
        *) if throttle "conn_${p}_$ip" 300; then ( alert "$msg
$(ip_info "$ip")" ) &
           else log "$msg (lặp lại trong 5 phút, không gửi)"; fi ;;
      esac
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
  diff_state persistence "$items" nonempty | while read -r sign path; do
    if [ "$sign" = "+" ]; then
      prog=$(plutil -extract Program raw -o - "$path" 2>/dev/null || plutil -extract ProgramArguments.0 raw -o - "$path" 2>/dev/null)
      alert "🧩 Có chương trình tự khởi động mới
File: $path
Chạy: ${prog:-?}
Chữ ký: $(sig_of "$prog")"
    else info "🧩 Đã gỡ chương trình tự khởi động
File: $path"; fi
  done

  # Tài khoản user (UID >= 500) và nhóm admin
  users=$(dscl . -list /Users UniqueID | awk '$2 >= 500 {print $1}')
  diff_state users "$users" nonempty | while read -r sign u; do
    [ "$sign" = "+" ] && alert "👥 Có tài khoản user mới: $u" || alert "👥 Đã xoá tài khoản user: $u"
  done
  admins=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | cut -d: -f2- | tr ' ' '\n')
  diff_state admins "$admins" nonempty | while read -r sign u; do
    [ "$sign" = "+" ] && alert "👑 $u vừa được cấp quyền ADMIN" || info "👑 $u bị gỡ quyền admin"
  done

  # Firewall & Gatekeeper
  fw=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null |
       awk '/enabled/ { print "BẬT" } /disabled/ { print "TẮT" }')   # lệnh lỗi → rỗng → bỏ qua
  diff_state firewall "$fw" nonempty | while read -r sign v; do
    [ "$sign" = "+" ] && { [ "$v" = "TẮT" ] && alert "🧱 Firewall vừa bị TẮT" || info "🧱 Firewall đã bật"; }
  done
  gk=$(spctl --status 2>/dev/null | awk '/enabled/ { print "BẬT" } /disabled/ { print "TẮT" }')
  diff_state gatekeeper "$gk" nonempty | while read -r sign v; do
    [ "$sign" = "+" ] && { [ "$v" = "TẮT" ] && alert "🛂 Gatekeeper vừa bị TẮT (cho chạy app không rõ nguồn gốc)" || info "🛂 Gatekeeper đã bật"; }
  done

  # App MacSentry phải luôn chạy khi có người đăng nhập (vắng ~30s liên tục → có thể đã bị gỡ)
  console=$(stat -f %Su /dev/console)
  if [ "$console" != root ] && ! pgrep -x MacSentry >/dev/null; then
    n=$(( $(cat "$STATE/app_missing" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$STATE/app_missing"
    [ "$n" -ge 3 ] && throttle appmissing 600 && alert "⚠️ App MacSentry KHÔNG chạy (user đang đăng nhập: $console)
Có thể đã bị gỡ LaunchAgent hoặc xoá app"
  else echo 0 > "$STATE/app_missing"; fi

  # Dịch vụ truy cập từ xa bật/tắt (đang lắng nghe trên cổng của nó)
  services=$(netstat -an -p tcp | awk '$6=="LISTEN" { n=split($4,a,"."); print a[n] }' |
             awk -v re="$REMOTE_PORTS_RE" '$1 ~ re' | sort -u)
  diff_state services "$services" | while read -r sign p; do
    if [ "$sign" = "-" ]; then info "📡 Đã tắt $(port_name "$p") (cổng $p)"
    elif [ "$tick" -eq 0 ]; then alert "📡 $(port_name "$p") (cổng $p) đang BẬT — máy nhận kết nối từ xa
(phát hiện lúc macsentryd khởi động)"
    else alert "📡 Vừa BẬT $(port_name "$p") (cổng $p) — máy nhận kết nối từ xa"; fi
  done
}

# Nghi reverse shell (mỗi 4 giây): shell / netcat giữ kết nối TCP ra ngoài.
# Ghi chi tiết tiến trình NGAY (tiến trình có thể kết thúc sau vài giây), tra IP trong tiến trình nền.
check_revshell() {
  rs=$(lsof -nP -iTCP -sTCP:ESTABLISHED -F pcn 2>/dev/null | awk '/^p/ { p = substr($0, 2) } /^c/ { c = substr($0, 2) } /^n/ {
         split(substr($0, 2), a, "->"); r = a[2]; if (r == "" || r ~ /^(127\.|\[::1\]|localhost)/) next
         if (c ~ /^(bash|sh|zsh|dash|ksh|tcsh|csh|fish|nc|ncat|netcat|socat|telnet|perl|perl5.*|ruby|php|osascript|tclsh|expect|lua)$/) print c, p, r }' | sort -u)
  diff_state revshell "$rs" | while read -r sign c p r; do
    [ "$sign" = "+" ] || continue
    detail=$(proc_info "$p")
    ip=${r%:*}; ip=${ip#[}; ip=${ip%]}
    tn=$(trusted_name "$r")
    if [ -n "$tn" ]; then
      log "☑️ $c (pid $p) -> $r — máy chủ tin cậy $tn, không cảnh báo. $detail"
      continue
    fi
    ( alert "☠️ Nghi REVERSE SHELL: $c (pid $p) -> $r
$(ip_info "$ip")
$detail
— Nếu đích là máy chủ quen (git, công ty...) và tiến trình cha là IDE/công cụ của bạn → báo giả, thêm vào /etc/macsentry.trusted.
— Nếu không nhận ra: ngắt mạng và kiểm tra ngay." ) &
  done
}

# Cổng mới mở ra mạng (mỗi 30 giây). Chỉ báo lần đầu thấy mỗi cặp (chương trình, cổng) để tránh ồn.
# Cổng tạm (>= 49152, hệ điều hành cấp ngẫu nhiên — vd remoted, rapportd) tính chung: mỗi chương trình báo 1 lần.
check_listen() {
  cur=$(lsof +c 0 -nP -iTCP -sTCP:LISTEN -F pcn 2>/dev/null |
        awk '/^p/ { p=substr($0,2) } /^c/ { c=substr($0,2) } /^n/ { name=substr($0,2); if (name ~ /^(127\.|\[::1\]|localhost)/) next
                                           n=split(name,a,":"); print c"|"a[n]"|"p }' | sort -t'|' -k1,2 -u)
  seen="$STATE/listen_seen"
  if [ ! -f "$seen" ]; then printf '%s\n' "$cur" | cut -d'|' -f1,2 > "$seen"; return; fi
  printf '%s\n' "$cur" | while IFS='|' read -r cmd port pid; do
    [ -n "$cmd" ] || continue
    if [ "$port" -ge 49152 ] 2>/dev/null; then
      # đã từng thấy chương trình này mở cổng tạm nào đó → bỏ qua
      awk -F'|' -v c="$cmd" '$1 == c && ($2 == "tạm" || $2 >= 49152) { f = 1 } END { exit !f }' "$seen" && continue
      echo "$cmd|tạm" >> "$seen"
      note="Cổng: $port (cổng tạm — lần sau chương trình này đổi cổng tạm sẽ không báo nữa)"
    else
      grep -qxF "$cmd|$port" "$seen" && continue
      echo "$cmd|$port" >> "$seen"
      note="Cổng: $port"
    fi
    info "🆕 Cổng mới mở ra mạng
Chương trình: $cmd
$note
$(proc_info "$pid")"
  done
}

# ---------------------------------------------------------------- 4b. chống cài cắm (mỗi 30-60 giây)

# File cấu hình nhạy cảm — hacker hay sửa để giữ quyền truy cập (kèm nội dung thay đổi)
SENSITIVE_FILES=${SENSITIVE_FILES:-"/Users/*/.ssh/authorized_keys /Users/*/.ssh/authorized_keys2 /var/root/.ssh/authorized_keys
  /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* /etc/sudoers /etc/sudoers.d/* /etc/pam.d/*
  /etc/crontab /usr/lib/cron/tabs/* /etc/hosts /etc/zshrc /etc/zprofile /etc/zshenv /etc/bashrc /etc/profile
  /etc/paths /etc/paths.d/* /etc/periodic.conf /etc/rc.common /etc/launchd.conf /etc/ssh/ssh_config
  /Users/*/.ssh/config /Users/*/.zshrc /Users/*/.zprofile /Users/*/.zshenv /Users/*/.zlogin
  /Users/*/.bashrc /Users/*/.bash_profile /Users/*/.profile /var/root/.zshrc /var/root/.profile"}

check_files() {
  mkdir -p "$STATE/files"
  list=$(ls -1d $SENSITIVE_FILES 2>/dev/null | sort -u)
  # Đổi danh sách file theo dõi → tăng FILES_V để lấy mốc lại, không báo nhầm hàng loạt "file MỚI"
  FILES_V=2
  [ "$(cat "$STATE/files_v" 2>/dev/null)" = "$FILES_V" ] || { rm -f "$STATE/filesums"; echo "$FILES_V" > "$STATE/files_v"; }
  first=0; [ -f "$STATE/filesums" ] || first=1
  # Băm ~30 file mỗi lần tốn ~0,4 giây → chỉ băm khi ctime / kích thước / danh sách file đổi
  stat_changed files "$list" || [ $first = 1 ] || return 0
  changes=$(hash_changes filesums "$list")
  if [ $first = 1 ]; then for f in $list; do cp "$f" "$(copy_of "$f")" 2>/dev/null; done; return; fi
  printf '%s\n' "$changes" | while read -r kind f; do
    [ -n "$f" ] || continue
    copy=$(copy_of "$f")
    case $kind in
      removed) alert "📝 File nhạy cảm bị XOÁ: $f"; rm -f "$copy" ;;
      new)     alert "📝 File nhạy cảm MỚI: $f
$(head -10 "$f" | mask_secrets | cut -c1-200)"; cp "$f" "$copy" ;;
      changed)
        # Shell rc / ssh config của user: bạn hay tự sửa → tin im lặng (vẫn kèm nội dung để soát)
        notify=alert
        case $f in /etc/pam.d/*|/etc/zshrc|/etc/zprofile|/etc/zshenv|/etc/bashrc|/etc/profile|/etc/ssh/sshd_config|/etc/ssh/ssh_config|/etc/paths)
          hint="
(file của macOS — nếu vừa cập nhật macOS thì thường là bình thường)" ;;
          /Users/*)
          notify=info; hint="
(file của user — nếu bạn không vừa sửa thì kiểm tra dòng mới: alias/lệnh lạ chạy mỗi lần mở terminal)" ;;
          *) hint="" ;; esac
        $notify "📝 File nhạy cảm bị SỬA: $f
$(diff "$copy" "$f" 2>/dev/null | grep '^[<>]' | head -15 | mask_secrets | cut -c1-200)
(< dòng cũ, > dòng mới)$hint"; cp "$f" "$copy" ;;
    esac
  done
}

check_persistence() {
  # Login Items / Background Items đăng ký qua SMAppService (loại "legacy" = plist, đã theo dõi ở check_system)
  # sfltool tốn ~3 giây → chỉ chạy khi file DB Background Items đổi (hoặc mỗi giờ một lần cho chắc)
  btm_sig="$(stat -f '%c %z %N' /private/var/db/com.apple.backgroundtaskmanagement/* 2>/dev/null) $(( $(date +%s) / 3600 ))"
  if [ "$btm_sig" != "$(cat "$STATE/btm_sig" 2>/dev/null)" ]; then
    echo "$btm_sig" > "$STATE/btm_sig"
    btm=$(sfltool dumpbtm 2>/dev/null | awk -F': ' '/^ *Type:/ { t = $2 } /^ *Identifier:/ {
            if (t !~ /^(developer|app|legacy)/) print t " | " $2 }' | sort -u)
    diff_state btm "$btm" nonempty | while read -r sign rest; do
      [ "$sign" = "+" ] && alert "🧩 Mục chạy nền / Login Item mới: $rest" || info "🧩 Đã gỡ mục chạy nền: $rest"
    done
  fi

  # Bỏ profile Screen Time (com.apple.ManagedSettings.*): macOS tự tạo/xoá khi đổi cài đặt Screen Time
  profs=$(profiles list -all 2>/dev/null | sed -n 's/.*profileIdentifier: //p' | grep -v '^com\.apple\.ManagedSettings\.')
  diff_state profiles "$profs" | while read -r sign p; do
    [ "$sign" = "+" ] && alert "📜 Có configuration profile MỚI: $p
(profile có thể ép proxy, chứng chỉ, quản lý máy từ xa)" || info "📜 Đã gỡ profile: $p"
  done

  sysext=$(systemextensionsctl list 2>/dev/null | awk -F'\t' 'NF >= 6 && $3 != "teamID" { sub(/ \(.*/, "", $4); print $4 }')
  diff_state sysext "$sysext" | while read -r sign e; do
    [ "$sign" = "+" ] && alert "🧷 System extension mới: $e" || info "🧷 System extension đã gỡ: $e"
  done

  proxy=$(scutil --proxy | awk '/Enable : 1|URLString|Proxy :|Port :/ { $1 = $1; print }')
  diff_state proxy "$proxy" | while read -r sign v; do
    [ "$sign" = "+" ] && alert "🕸 Cấu hình PROXY thay đổi: $v
(proxy lạ có thể dùng để nghe lén traffic)"
  done
  dns=$(scutil --dns | awk '/nameserver\[/ { print $3 }' | sort -u)
  diff_state dns "$dns" | while read -r sign v; do [ "$sign" = "+" ] && info "🧭 DNS server mới: $v"; done

  # Thư mục cài cắm ít gặp nhưng nguy hiểm: authorization plugin (chạy lúc đăng nhập, đọc được mật khẩu),
  # helper chạy bằng root, StartupItems, plugin Directory Services, kext, plugin âm thanh (nghe lén), periodic
  pdirs=$(ls -1d /Library/Security/SecurityAgentPlugins/* /Library/PrivilegedHelperTools/* /Library/StartupItems/* \
          /Library/DirectoryServices/PlugIns/* /Library/Extensions/* /Library/Audio/Plug-Ins/HAL/* \
          /etc/periodic/*/* /usr/local/etc/periodic/*/* 2>/dev/null)
  diff_state persist_dirs "$pdirs" | while read -r sign path; do
    if [ "$sign" = "+" ]; then
      case $path in
        /Library/Security/SecurityAgentPlugins/*) hint="(authorization plugin: chạy trong quá trình đăng nhập, có thể đọc mật khẩu)" ;;
        /Library/PrivilegedHelperTools/*) hint="(helper chạy bằng quyền root)" ;;
        *) hint="" ;;
      esac
      alert "🧩 Thành phần tự chạy MỚI: $path
Chữ ký: $(sig_of "$path")
$hint"
    else info "🧩 Đã gỡ: $path"; fi
  done

  # Login/Logout hook (cách cũ nhưng vẫn chạy bằng root mỗi lần đăng nhập)
  hooks=$(for d in /Library/Preferences/com.apple.loginwindow /var/root/Library/Preferences/com.apple.loginwindow; do
            for k in LoginHook LogoutHook; do v=$(defaults read "$d" "$k" 2>/dev/null) && echo "$k: $v"; done; done)
  diff_state hooks "$hooks" | while read -r sign v; do
    [ "$sign" = "+" ] && alert "🪝 Login/Logout hook MỚI: $v"
  done

  # Chứng chỉ Root CA được tin cậy thêm (dùng để giải mã/nghe lén HTTPS)
  certs=$( { security find-certificate -a -Z /Library/Keychains/System.keychain 2>/dev/null |
               awk '/^SHA-1 hash:/ { h = $3 } /"labl"/ { sub(/.*="/, ""); sub(/"$/, ""); print "System.keychain | " $0 " | " substr(h, 1, 12) }'
             security dump-trust-settings -d 2>/dev/null | sed -n 's/^Cert [0-9]*: /Tin cậy (admin) | /p'; } | sort -u)
  diff_state certs "$certs" nonempty | while read -r sign v; do
    [ "$sign" = "+" ] && alert "📜 Chứng chỉ MỚI được thêm / tin cậy: $v
(chứng chỉ gốc lạ cho phép nghe lén HTTPS — nếu không phải bạn cài (mkcert, Proxyman...) thì gỡ ngay)" || info "📜 Đã gỡ chứng chỉ: $v"
  done

  # Kernel extension bên thứ ba đang nạp
  kexts=$(kmutil showloaded --list-only 2>/dev/null | awk '{ print $6 }' | grep -v -E '^(com\.apple\.|$)')
  diff_state kexts "$kexts" | while read -r sign k; do
    [ "$sign" = "+" ] && alert "🧷 Kernel extension MỚI được nạp: $k" || info "🧷 Kernel extension đã gỡ: $k"
  done

  # Dịch vụ hệ thống bị tắt (launchctl disable) — kẻ tấn công có thể tắt dịch vụ bảo mật
  disabled=$(launchctl print-disabled system 2>/dev/null | awk -F'"' '/=> (disabled|true)/ { print $2 }')
  diff_state launchd_disabled "$disabled" | while read -r sign s; do
    [ "$sign" = "+" ] && alert "⛔️ Dịch vụ hệ thống vừa bị TẮT (launchctl disable): $s" || info "Dịch vụ được bật lại: $s"
  done

  # Extension trình duyệt (Chrome / Edge / Brave): extension độc có thể đọc mọi trang, cookie, mật khẩu đã nhập
  exts=$(for d in /Users/*/Library/Application\ Support/Google/Chrome /Users/*/Library/Application\ Support/Microsoft\ Edge \
                  /Users/*/Library/Application\ Support/BraveSoftware/Brave-Browser; do
           for e in "$d"/*/Extensions/*; do [ -d "$e" ] || continue
             m=$(ls -1d "$e"/*/manifest.json 2>/dev/null | tail -1)
             n=$(plutil -extract name raw -o - "$m" 2>/dev/null)
             if [ -z "$n" ] || [ "${n#__MSG_}" != "$n" ]; then n=?; fi
             echo "$(basename "$(dirname "$(dirname "$d/x")")")/$(basename "$d") | $(basename "$e") | $n"; done; done | sort -u)
  diff_state browser_ext "$exts" | while read -r sign v; do
    [ "$sign" = "+" ] && alert "🧩 Extension trình duyệt MỚI: $v" || info "🧩 Đã gỡ extension trình duyệt: $v"
  done

  apps=$(ls -1d /Applications/*.app /Users/*/Applications/*.app 2>/dev/null)
  diff_state apps "$apps" nonempty | while read -r sign a; do
    [ "$sign" = "+" ] && info "📦 App mới được cài: $a
Chữ ký: $(sig_of "$a")" || info "📦 App bị gỡ: $a"
  done
}

# ---------------------------------------------------------------- 4c. tư thế bảo mật & tự bảo vệ (mỗi 60 giây)

check_posture() {
  sip=$(csrutil status 2>/dev/null | grep -q 'enabled\.' && echo BẬT || echo TẮT)
  fv=$(fdesetup status 2>/dev/null | grep -q 'FileVault is On' && echo BẬT || echo TẮT)
  au=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null)
  # Quy ước: dòng kết thúc bằng "TẮT" hoặc chứa "⚠️" là trạng thái xấu → chuyển sang trạng thái đó thì có chuông
  alu=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null)
  guest=$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)
  console=$(stat -f %Su /dev/console)
  lock=""
  if [ "$console" != root ]; then
    lock=$(sudo -u "$console" sysadminctl -screenLock status 2>&1 | sed -n 's/.*screenLock delay is //p; s/.*screenLock is off.*/off/p' | head -1)
  fi
  posture="SIP: $sip
FileVault: $fv
Tự cập nhật bảo mật: $([ "$au" = 1 ] && echo BẬT || echo TẮT)
Tự đăng nhập không cần mật khẩu: $([ -n "$alu" ] && echo "BẬT ($alu) ⚠️" || echo "không")
Tài khoản Guest: $([ "$guest" = 1 ] && echo "BẬT ⚠️" || echo "không")
Remote Management (ARD): $(pgrep -x ARDAgent >/dev/null && echo "đang chạy ⚠️" || echo "không")
VNC cho phép mật khẩu kiểu cũ (≤8 ký tự): $([ "$(defaults read /Library/Preferences/com.apple.RemoteManagement VNCLegacyConnectionsEnabled 2>/dev/null)" = 1 ] && echo "BẬT ⚠️" || echo "không")
Screen Sharing cho phép mã hoá yếu (insecure DH): $([ "$(defaults read /Library/Preferences/com.apple.RemoteManagement allowInsecureDH 2>/dev/null)" = 1 ] && echo "BẬT ⚠️" || echo "không")
Find My Mac: $(nvram fmm-mobileme-token-FMM >/dev/null 2>&1 && echo BẬT || echo TẮT)
Quản lý thiết bị (MDM): $(profiles status -type enrollment 2>/dev/null | awk -F': ' '/MDM enrollment/ { print ($2 ~ /^No/ ? "không" : "ĐÃ ĐĂNG KÝ (" $2 ") ⚠️") }')
XProtect: $(defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist CFBundleShortVersionString 2>/dev/null || echo "? ⚠️")"
  case $lock in
    "") ;;
    immediate) posture="$posture
Khoá màn hình đòi mật khẩu: ngay lập tức" ;;
    off) posture="$posture
Khoá màn hình đòi mật khẩu: TẮT" ;;
    *) posture="$posture
Khoá màn hình đòi mật khẩu: sau $lock ⚠️" ;;
  esac
  echo "$posture" > "$STATE/posture_now"
  diff_state posture "$posture" | while read -r sign v; do
    [ "$sign" = "+" ] || continue
    case $v in *TẮT|*⚠️*) alert "🛡 Bảo mật bị hạ: $v" ;; *) info "🛡 Bảo mật: $v" ;; esac
  done

  # Dữ liệu nhận diện mã độc XProtect quá cũ → máy không nhận được cập nhật bảo mật
  xp=/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist
  age=$(( ($(date +%s) - $(stat -f %m "$xp" 2>/dev/null || date +%s)) / 86400 ))
  [ "$age" -gt 45 ] && throttle xprotect_old 86400 && alert "🦠 XProtect chưa cập nhật $age ngày — kiểm tra Software Update / kết nối mạng"

  # Helper Endpoint Security (eslogger) phải đang chạy nếu đã cài
  if [ -f /Library/LaunchDaemons/io.github.vuminhhoa.macsentry.es.plist ] && ! es_alive && [ "$tick" -gt 60 ]; then
    throttle es_dead 21600 && alert "⚠️ Giám sát Endpoint Security KHÔNG hoạt động
$(cat "$STATE/es_status" 2>/dev/null || echo "Helper macsentry-es không chạy")
→ Cấp Full Disk Access cho /usr/local/libexec/macsentry-es (Cài đặt → Quyền riêng tư & Bảo mật → Truy cập toàn bộ ổ đĩa)"
  fi

  # Bot của app và của daemon dùng chung token → phần mềm chạy bằng user đọc được token của app là xoá được
  # cả cảnh báo của daemon (bot xoá được tin chính nó gửi trong 48 giờ)
  for f in /Users/*/Library/Application\ Support/MacSentry/telegram.json; do
    [ -f "$f" ] || continue
    [ "$(plutil -extract botToken raw -o - "$f" 2>/dev/null)" = "$TOKEN" ] && throttle sametoken 604800 &&
      info "🔑 App và daemon đang dùng CHUNG bot Telegram. Nên tạo bot riêng cho daemon rồi chạy: sudo ~/MacSentry/daemon/install.sh --reconfigure"
  done

  # File của chính MacSentry bị sửa/xoá (nếu không phải bạn vừa cập nhật → có thể bị can thiệp)
  self=$(ls -1d /usr/local/libexec/macsentryd /Library/LaunchDaemons/io.github.vuminhhoa.macsentry.daemon.plist /etc/macsentry.conf "$TRUSTED" \
         /usr/local/libexec/macsentry-es /Library/LaunchDaemons/io.github.vuminhhoa.macsentry.es.plist \
         /Users/*/Applications/MacSentry.app/Contents/MacOS/MacSentry 2>/dev/null)
  stat_changed self "$self" && hash_changes selfsums "$self" | while read -r kind f; do
    [ -n "$f" ] || continue
    case $kind in
      removed) alert "🧬 File của MacSentry bị XOÁ: $f" ;;
      *) alert "🧬 File của MacSentry thay đổi: $f
(nếu bạn không vừa cập nhật MacSentry → có thể bị can thiệp)" ;;
    esac
  done
}

# ---------------------------------------------------------------- 4d. app điều khiển từ xa & tunnel (mỗi 10 giây)
# TeamViewer/AnyDesk/RustDesk... kết nối RA máy chủ trung gian nên không lộ qua cổng lắng nghe như SSH/VNC
# → theo dõi tiến trình + log phiên của chúng. ngrok/cloudflared/frp... mở đường hầm từ Internet vào máy.

RT_RE='^(TeamViewer.*|AnyDesk.*|RustDesk.*|rustdesk.*|remoting_me2me_host|ScreenConnect.*|ConnectWise.*|Splashtop.*|SRStreamer|SRService|LogMeIn.*|Parsec.*|UltraViewer.*|ZohoAssist.*|Zoho Assist.*|AeroAdmin.*|Supremo.*|DWAgent.*|nxserver.*|nxnode.*|NoMachine.*|ngrok|cloudflared|frpc|chisel|bore|tmate|Jump Desktop Connect.*)$'

check_remote_tools() {
  procs=$(ps -axo pid=,comm= | awk '{ p = $1; $1 = ""; sub(/^ /, ""); n = split($0, a, "/"); print a[n] "|" p "|" $0 }' |
          awk -F'|' -v re="$RT_RE" '$1 ~ re' | sort -t'|' -k1,1 -u)
  names=$(printf '%s\n' "$procs" | cut -d'|' -f1,3)
  diff_state remote_tools "$names" | while read -r sign rest; do
    n=${rest%%|*}
    if [ "$sign" = "+" ]; then
      pid=$(printf '%s\n' "$procs" | awk -F'|' -v n="$n" '$1 == n { print $2; exit }')
      case $n in
        TeamViewer_Desktop*) what="TeamViewer_Desktop thường chỉ chạy khi CÓ NGƯỜI ĐANG ĐIỀU KHIỂN máy qua TeamViewer" ;;
        ngrok|cloudflared|frpc|chisel|bore|tmate) what="Công cụ mở đường hầm từ Internet vào máy" ;;
        *) what="App điều khiển máy từ xa vừa chạy" ;;
      esac
      alert "🖥 $what: $n
$(proc_info "$pid")"
    else info "🖥 Đã thoát: $n"; fi
  done

  # Log phiên kết nối đến (định dạng log không công khai → bắt theo từ khoá phổ biến, đọc kèm nguyên dòng log)
  for f in /Library/Logs/TeamViewer/*.log /Users/*/Library/Logs/TeamViewer/*.log \
           /Users/*/.anydesk/*.trace /Library/Application\ Support/AnyDesk/*.trace /var/log/anydesk*.trace \
           /Users/*/Library/Logs/RustDesk/server/*.log /Users/*/Library/Logs/RustDesk/*.log; do
    [ -f "$f" ] || continue
    key=$(printf '%s' "$f" | cksum | cut -d' ' -f1)
    hits=$(tail_new "rt_$key" "$f" | grep -a -i -E 'incoming session|accepting from|connection incoming|incoming connection|new connection from|session started|authenticated|remote control (started|session)|login from' | tail -5 | cut -c1-250)
    [ -n "$hits" ] && throttle "rtlog_$key" 60 && alert "🚨 Có PHIÊN KẾT NỐI ĐẾN qua app điều khiển từ xa
Log: $f
$hits"
  done
}

# ---------------------------------------------------------------- 4e. Wazuh agent (mỗi 30 giây)
# Wazuh chạy bằng root và nhận lệnh từ máy chủ quản lý (manager): theo dõi agent còn chạy, kết nối tới đâu,
# cấu hình có bị đổi (kể cả cấu hình manager đẩy xuống), manager có chạy lệnh / active response trên máy không.

WZ=/Library/Ossec
check_wazuh() {
  [ -d "$WZ" ] || return 0
  first=0; [ -f "$STATE/wazuh_posture" ] || first=1

  # Tiến trình: dừng tiến trình nào cũng báo (tắt EDR là bước đầu của kẻ tấn công)
  run=$(for p in wazuh-agentd wazuh-execd wazuh-syscheckd wazuh-logcollector wazuh-modulesd; do pgrep -x "$p" >/dev/null && echo "$p"; done)
  diff_state wazuh_procs "$run" | while read -r sign p; do
    [ "$sign" = "-" ] && alert "⚠️ Wazuh: tiến trình $p vừa DỪNG" || info "Wazuh: $p chạy lại"
  done

  # Kết nối tới manager (2 lần liên tiếp mất kết nối mới báo, tránh báo khi đổi mạng chớp nhoáng)
  st=$(sed -n "s/^status='\(.*\)'/\1/p" "$WZ/var/run/wazuh-agentd.state" 2>/dev/null)
  if [ -n "$st" ]; then
    prev=$(cat "$STATE/wazuh_status" 2>/dev/null); echo "$st" > "$STATE/wazuh_status"
    if [ "$st" = disconnected ] && [ "$prev" = disconnected ] && [ "$(cat "$STATE/wazuh_status_sent" 2>/dev/null)" != disconnected ]; then
      echo disconnected > "$STATE/wazuh_status_sent"
      route -n get default >/dev/null 2>&1 && alert "⚠️ Wazuh agent MẤT KẾT NỐI tới manager (máy vẫn có mạng)" ||
        log "Wazuh mất kết nối (máy không có mạng)"
    elif [ "$st" = connected ] && [ "$(cat "$STATE/wazuh_status_sent" 2>/dev/null)" = disconnected ]; then
      echo connected > "$STATE/wazuh_status_sent"; info "Wazuh agent đã kết nối lại manager"
    fi
  fi

  # Tư thế: manager là ai, manager có được chạy lệnh từ xa / active response không, phiên bản
  conf="$WZ/etc/ossec.conf"; lio="$WZ/etc/local_internal_options.conf"
  mgr=$(sed -n 's:.*<address>\(.*\)</address>.*:\1:p' "$conf" 2>/dev/null | tr '\n' ' ')
  rcmd=$(grep -h -E '^[[:space:]]*(logcollector|wazuh_command|sca)\.remote_commands[[:space:]]*=[[:space:]]*1' "$lio" 2>/dev/null | tr -d ' ' | tr '\n' ' ')
  ar=$(awk '/<active-response>/ { a = 1 } a && /<disabled>yes<\/disabled>/ { d = 1 } /<\/active-response>/ { a = 0 } END { print d ? "TẮT" : "BẬT" }' "$conf" 2>/dev/null)
  ver=$(sed -n 's/^WAZUH_VERSION="\{0,1\}\([^"]*\)"\{0,1\}/\1/p' "$WZ/etc/ossec-init.conf" 2>/dev/null)
  [ -n "$ver" ] || ver=$("$WZ/bin/wazuh-control" info -v 2>/dev/null)
  wp="Wazuh manager: ${mgr:-?}
Wazuh cho manager chạy lệnh từ xa: $([ -n "$rcmd" ] && echo "BẬT ($rcmd) ⚠️" || echo "không")
Wazuh active response (manager chạy script trên máy): $ar
Wazuh phiên bản: ${ver:-?}"
  echo "$wp" > "$STATE/wazuh_now"
  if [ $first = 1 ]; then
    printf '%s\n' "$wp" | sed '/^$/d' | sort > "$STATE/wazuh_posture"
    info "🐺 Bắt đầu giám sát Wazuh agent
$wp
Tiến trình đang chạy: $(echo $run)"
  else
    diff_state wazuh_posture "$wp" | while read -r sign v; do
      [ "$sign" = "+" ] || continue
      case $v in "Wazuh manager:"*) alert "🐺 Wazuh ĐỔI máy chủ quản lý → $v" ;;
                 *⚠️*) alert "🐺 $v" ;; *) info "🐺 $v" ;; esac
    done
  fi

  # File cấu hình (agent.conf = cấu hình manager đẩy xuống) — kèm nội dung thay đổi; client.keys chỉ báo, không gửi nội dung
  mkdir -p "$STATE/files"
  wfiles=$(ls -1d "$conf" "$lio" "$WZ/etc/internal_options.conf" "$WZ/etc/shared/agent.conf" "$WZ/etc/client.keys" \
           /Library/LaunchDaemons/com.wazuh.agent.plist /Library/StartupItems/WAZUH/* 2>/dev/null)
  stat_changed wazuh_cfg "$wfiles" && hash_changes wazuh_cfg "$wfiles" | while read -r kind f; do
    [ -n "$f" ] || continue
    copy=$(copy_of "$f")
    case $kind:$f in
      *:*/client.keys) alert "🐺 Khoá đăng ký Wazuh (client.keys) $kind — agent có thể đã được đăng ký lại với manager khác" ;;
      removed:*) alert "🐺 File cấu hình Wazuh bị XOÁ: $f" ;;
      new:*) info "🐺 File cấu hình Wazuh mới: $f
$(head -15 "$f" | mask_secrets | cut -c1-200)" ;;
      changed:*) alert "🐺 Cấu hình Wazuh THAY ĐỔI: $f
$(diff "$copy" "$f" 2>/dev/null | grep '^[<>]' | head -20 | mask_secrets | cut -c1-200)
(< dòng cũ, > dòng mới)" ;;
    esac
    case $f in */client.keys) ;; *) cp "$f" "$copy" 2>/dev/null ;; esac
  done
  # Lần đầu: lưu bản sao để lần sau có nội dung so sánh
  for f in $wfiles; do case $f in */client.keys) ;; *) [ -f "$(copy_of "$f")" ] || cp "$f" "$(copy_of "$f")" 2>/dev/null ;; esac; done

  # File thực thi của Wazuh và script active response bị thay (cập nhật Wazuh hợp lệ cũng báo, kèm phiên bản)
  wbins=$(ls -1d "$WZ"/bin/* "$WZ"/active-response/bin/* 2>/dev/null)
  stat_changed wazuh_bin "$wbins" && hash_changes wazuh_bin "$wbins" | while read -r kind f; do
    [ -n "$f" ] || continue
    case $f in
      */active-response/bin/*) alert "🐺 Script active response của Wazuh $kind: $f
(script này chạy bằng root khi manager ra lệnh)" ;;
      *) throttle wazuh_bin 600 && info "🐺 File thực thi Wazuh $kind: $f (phiên bản: ${ver:-?})
(thường do cập nhật Wazuh; nhiều file đổi cùng lúc chỉ báo 1 lần)" ;;
    esac
  done

  # Manager vừa chạy active response trên máy
  ar_new=$(tail_new wazuh_ar "$WZ/logs/active-responses.log" | tail -10 | cut -c1-250)
  [ -n "$ar_new" ] && alert "⚡️ Wazuh manager vừa chạy ACTIVE RESPONSE trên máy (bằng root)
$ar_new"

  # Log của agent: đổi cấu hình từ manager, nâng cấp từ xa, lệnh từ xa, lỗi nghiêm trọng
  ol=$(tail_new wazuh_ossec "$WZ/logs/ossec.log" | grep -a -E 'CRITICAL|restarting due to|[Uu]pgrade|WPK|[Rr]emote command|wazuh-modulesd:command|logcollector.*command' | tail -10 | cut -c1-250)
  [ -n "$ol" ] && info "🐺 Wazuh agent log:
$ol"
}

# ---------------------------------------------------------------- 4f. agent quan trọng nói chung (mỗi 30 giây)
# Danh mục sản phẩm bảo mật / quản lý / VPN / điều khiển từ xa. Agent nào có cài (thư mục cài tồn tại) thì theo dõi:
#   - tiến trình đang chạy mà DỪNG → cảnh báo (tắt EDR/firewall/VPN là bước đầu của kẻ tấn công)
#   - file cấu hình thay đổi → cảnh báo kèm nội dung (plist nhị phân được đổi sang dạng chữ)
# Thêm agent riêng: /etc/macsentry.agents, cùng định dạng: Tên | tiến trình,cách,nhau,dấu,phẩy | thư mục cài | file cấu hình (glob)
# (Wazuh đã có kiểm tra chuyên sâu riêng ở check_wazuh nên không nằm ở đây)
AGENT_CATALOG='CrowdStrike Falcon|falcond,com.crowdstrike.falcon.Agent|/Applications/Falcon.app|/Library/Application Support/CrowdStrike/Falcon/falconctl.plist
SentinelOne|sentineld,sentineld_helper,sentineld_shell|/Library/Sentinel|/Library/Sentinel/sentinel-agent.bundle/Contents/Resources/config/*.json
Microsoft Defender|wdavdaemon,wdavdaemon_enterprise,wdavdaemon_unprivileged|/Applications/Microsoft Defender.app|/Library/Managed Preferences/com.microsoft.wdav.plist /Library/Application Support/Microsoft/Defender/wdavcfg
Sophos Endpoint|SophosScanD,SophosServiceManager,SophosAntiVirus,SophosMcsAgentD|/Library/Sophos Anti-Virus|
Sophos Connect VPN|scvpn,charon|/Library/Sophos Connect|
ESET|esets_daemon,esets_proxy|/Applications/ESET Endpoint Security.app|
Kaspersky|kav,klnagent|/Library/Application Support/Kaspersky Lab|
Malwarebytes|RTProtectionDaemon,Malwarebytes|/Library/Application Support/Malwarebytes|
Santa|santad,santasyncservice,com.northpolesec.santa.daemon,com.google.santa.daemon|/Applications/Santa.app|/var/db/santa/config.plist /Library/Managed Preferences/com.northpolesec.santa.plist /Library/Managed Preferences/com.google.santa.plist
Jamf|jamf,JamfDaemon,JamfAgent|/usr/local/jamf|/Library/Preferences/com.jamfsoftware.jamf.plist
Jamf Protect|JamfProtect,com.jamf.protect.daemon|/Applications/JamfProtect.app|
Kandji|kandji-daemon,Kandji Agent|/Library/Kandji|
Microsoft Intune|IntuneMdmDaemon,IntuneMdmAgent|/Library/Intune|
Little Snitch|at.obdev.littlesnitch.networkextension,Little Snitch Daemon,Little Snitch Agent|/Applications/Little Snitch.app|
LuLu|com.objective-see.lulu.extension,LuLu|/Applications/LuLu.app|
BlockBlock|BlockBlock,BlockBlock Helper|/Applications/BlockBlock Helper.app|
Tailscale|io.tailscale.ipn.macsys.network-extension,io.tailscale.ipn.macos.network-extension,Tailscale,tailscaled|/Applications/Tailscale.app|
Cloudflare WARP|CloudflareWARP|/Applications/Cloudflare WARP.app|/Library/Managed Preferences/com.cloudflare.warp.plist /Library/Application Support/Cloudflare/mdm.xml
OpenVPN Connect|ovpnagent,ovpnhelper|/Library/Frameworks/OpenVPNConnect.framework|
Tunnelblick|tunnelblickd|/Library/Application Support/Tunnelblick|
TeamViewer (dịch vụ)|TeamViewer_Service|/Applications/TeamViewer.app|/Library/Preferences/com.teamviewer.teamviewer.preferences.plist /Library/Preferences/com.teamviewer.TeamViewer.plist
AnyDesk (dịch vụ)|AnyDesk|/Applications/AnyDesk.app|/Library/Application Support/AnyDesk/system.conf /etc/anydesk/system.conf'

check_agents() {
  allprocs=$(ps -axo comm= | sed 's|.*/||' | sort -u)
  { printf '%s\n' "$AGENT_CATALOG"; sed 's/#.*//' /etc/macsentry.agents 2>/dev/null; } |
  while IFS='|' read -r name procs dir cfgs; do
    name=$(echo $name); dir=$(echo $dir)
    [ -n "$name" ] && [ -e "$dir" ] || continue
    printf '%s' "$procs" | tr ',' '\n' | while read -r p; do
      p=$(echo $p); [ -n "$p" ] && printf '%s\n' "$allprocs" | grep -qxF "$p" && echo "$name|$p"
    done
    # File cấu hình (cách nhau bởi " /", đường dẫn được có dấu cách): in "cfg|đường dẫn" để xử lý chung bên dưới
    printf '%s' "$cfgs" | awk '{ n = split($0, a, / +\//); for (i = 1; i <= n; i++) { s = a[i]; gsub(/^ +| +$/, "", s)
                                   if (s == "") continue; if (i > 1) s = "/" s; print s } }' |
    while IFS= read -r g; do
      ( IFS='
'; for f in $g; do [ -f "$f" ] && echo "cfg|$f"; done )
    done
  done > "$STATE/agents_scan"

  # Tiến trình của agent: mất đi → cảnh báo, chạy lại → tin im lặng
  diff_state agent_procs "$(grep -v '^cfg|' "$STATE/agents_scan")" | while IFS='|' read -r sp p; do
    sign=${sp%% *}; name=${sp#* }
    [ "$sign" = "-" ] && alert "⚠️ Agent $name: tiến trình $p vừa DỪNG
(nếu bạn không tắt/gỡ agent này → có thể có người cố tắt bảo vệ/giám sát)" || info "Agent $name: $p đang chạy"
  done

  # Cấu hình agent: so bản dạng chữ (plist nhị phân → plutil -p)
  mkdir -p "$STATE/files"
  cfgl=$(sed -n 's/^cfg|//p' "$STATE/agents_scan" | sort -u)
  stat_changed agent_cfg "$cfgl" && hash_changes agent_cfg "$cfgl" | while read -r kind f; do
    [ -n "$f" ] || continue
    copy=$(copy_of "$f"); new=$(plutil -p "$f" 2>/dev/null || cat "$f")
    case $kind in
      removed) alert "⚙️ File cấu hình agent bị XOÁ: $f" ;;
      new) info "⚙️ File cấu hình agent mới: $f" ;;
      changed) alert "⚙️ Cấu hình agent THAY ĐỔI: $f
$(printf '%s\n' "$new" | diff "$copy" - 2>/dev/null | grep '^[<>]' | head -20 | mask_secrets | cut -c1-200)
(< cũ, > mới)" ;;
    esac
    [ "$kind" = removed ] && rm -f "$copy" || printf '%s\n' "$new" > "$copy"
  done
  printf '%s\n' "$cfgl" | while IFS= read -r f; do
    [ -n "$f" ] && [ ! -f "$(copy_of "$f")" ] && { plutil -p "$f" 2>/dev/null || cat "$f"; } > "$(copy_of "$f")" 2>/dev/null
  done
}

# Mọi LaunchDaemon/LaunchAgent: nội dung plist bị sửa, hoặc file chạy bị thay bằng file có CHỮ KÝ KHÁC (mỗi ~5 phút)
check_daemon_integrity() {
  mkdir -p "$STATE/files" "$STATE/signers"
  plists=$(ls -1d /Library/LaunchDaemons/*.plist /Library/LaunchAgents/*.plist /Users/*/Library/LaunchAgents/*.plist 2>/dev/null)
  stat_changed plists "$plists" && hash_changes plist_sums "$plists" | while read -r kind f; do
    [ "$kind" = changed ] || continue
    copy=$(copy_of "$f"); new=$(plutil -p "$f" 2>/dev/null)
    d=$(printf '%s\n' "$new" | diff "$copy" - 2>/dev/null | grep '^[<>]' | head -15 | mask_secrets | cut -c1-200)
    case $f in /Users/*) n=info ;; *) n=alert ;; esac   # LaunchAgent của user hay bị app tự cập nhật
    $n "🧩 Cấu hình tự khởi động bị SỬA: $f
${d:-(không đọc được nội dung cũ)}
(< cũ, > mới)"
    printf '%s\n' "$new" > "$copy"
  done
  for f in $plists; do [ -f "$(copy_of "$f")" ] || plutil -p "$f" > "$(copy_of "$f")" 2>/dev/null; done

  for f in $(ls -1d /Library/LaunchDaemons/*.plist /Library/LaunchAgents/*.plist 2>/dev/null); do
    label=$(plutil -extract Label raw -o - "$f" 2>/dev/null) || continue
    prog=$(plutil -extract Program raw -o - "$f" 2>/dev/null || plutil -extract ProgramArguments.0 raw -o - "$f" 2>/dev/null)
    [ -n "$prog" ] || continue
    sf="$STATE/signers/$label"
    # codesign chậm → chỉ kiểm lại khi file chạy đổi ctime / kích thước
    key=$(stat -f '%c %z' "$prog" 2>/dev/null)
    [ -n "$key" ] && [ "$key" = "$(cat "$sf.key" 2>/dev/null)" ] && [ -f "$sf" ] && continue
    echo "$key" > "$sf.key"
    sig=$(sig_of "$prog")
    old=$(cat "$sf" 2>/dev/null)
    if [ -n "$old" ] && [ "$old" != "$sig" ]; then
      alert "☠️ File chạy của dịch vụ $label đổi CHỮ KÝ
File: $prog
Trước: $old
Bây giờ: $sig
(cập nhật hợp lệ thường giữ nguyên nhà phát hành — đổi nhà phát hành / mất chữ ký là dấu hiệu bị tráo file)"
    fi
    printf '%s' "$sig" > "$sf"
  done
}

# Báo cáo mỗi sáng (sau 8h). Không thấy báo cáo trong ngày → daemon/máy có vấn đề.
daily_report() {
  today=$(date +%Y%m%d)
  [ "$(date +%H)" -ge 8 ] || return
  [ "$(cat "$STATE/last_report" 2>/dev/null)" = "$today" ] && return
  echo "$today" > "$STATE/last_report"
  start=$(cat "$STATE/report_line" 2>/dev/null || echo 0); total=$(wc -l < "$LOG" | tr -d ' ')
  echo "$total" > "$STATE/report_line"
  summary=$(tail -n +"$((start + 1))" "$LOG" | awk '{ print $3 }' | sort | uniq -c | sort -rn |
            awk '{ printf "%s×%s  ", $2, $1 }')
  info "📊 Báo cáo hằng ngày
Máy bật từ: $(date -r "$boot" '+%d/%m/%Y %H:%M')
Sự kiện từ báo cáo trước: ${summary:-không có}
Kết nối từ xa đang mở: $(cat "$STATE/remote_conns" 2>/dev/null | grep -c .)
$(cat "$STATE/posture_now" 2>/dev/null)
Firewall: $(cat "$STATE/firewall" 2>/dev/null) | Gatekeeper: $(cat "$STATE/gatekeeper" 2>/dev/null)
Endpoint Security: $(es_alive && echo "đang chạy" || echo "KHÔNG chạy")
Agent đang chạy: $(grep -v '^cfg|' "$STATE/agents_scan" 2>/dev/null | cut -d'|' -f1 | sort -u | tr '\n' ',' | sed 's/,$//; s/,/, /g')
$(cat "$STATE/wazuh_now" 2>/dev/null)
(Ngày nào không thấy báo cáo này → kiểm tra máy)"
}

# ---------------------------------------------------------------- 5. phần cứng & mạng (mỗi 10 giây)

check_hardware() {
  usb=$(ioreg -p IOUSB -w0 | sed -n 's/.*+-o \(.*\)@[0-9a-f]*  <class.*/\1/p' | grep -v -E '^(Root|AppleT[0-9]+USBXHCI|USB[0-9.]* (Gen[0-9]+ )?Hub)$')
  [ -f "$STATE/usb_known" ] || printf '%s\n' "$usb" > "$STATE/usb_known"
  diff_state usb "$usb" | while read -r sign name; do
    if [ "$sign" = "-" ]; then info "🔌 Đã rút thiết bị USB: $name"
    elif grep -qxF "$name" "$STATE/usb_known"; then info "🔌 Cắm lại thiết bị USB quen: $name"
    else echo "$name" >> "$STATE/usb_known"; alert "🔌 Vừa cắm thiết bị USB MỚI (chưa từng thấy): $name"; fi
  done

  vols=$(ls -1 /Volumes 2>/dev/null | grep -v -E '^(Macintosh HD|Recovery|Preboot|VM|Data)$')
  [ -f "$STATE/volumes_known" ] || printf '%s\n' "$vols" > "$STATE/volumes_known"
  diff_state volumes "$vols" | while read -r sign name; do
    if [ "$sign" = "-" ]; then info "💾 Đã tháo ổ đĩa: $name"
    elif grep -qxF "$name" "$STATE/volumes_known"; then info "💾 Gắn lại ổ đĩa quen: $name"
    else echo "$name" >> "$STATE/volumes_known"; alert "💾 Vừa gắn ổ đĩa MỚI (chưa từng thấy): $name"; fi
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

tick=0
while :; do
  t=$(date +%s)

  check_remote "$t"
  check_spool
  [ $((tick % 2)) -eq 0 ] && check_revshell
  [ $((tick % 5)) -eq 0 ] && { check_system; check_hardware; check_remote_tools; }
  [ $((tick % 15)) -eq 0 ] && { check_listen; check_files; check_wazuh; check_agents; }
  [ $((tick % 30)) -eq 0 ] && { resolve_trusted; check_persistence; check_posture; daily_report
    # Dead-man switch: dịch vụ ngoài (vd healthchecks.io) báo cho bạn khi KHÔNG nhận được ping nữa
    # (daemon bị bootout / kill hẳn / máy bị tắt nguồn — những lúc daemon không tự báo được)
    [ -n "$HEARTBEAT_URL" ] && curl -fsS -m 10 -o /dev/null "$HEARTBEAT_URL" >/dev/null 2>&1 & }
  [ $((tick % 150)) -eq 0 ] && check_daemon_integrity
  tick=$((tick + 1))

  before=$(date +%s)
  sleep 2 & wait $!   # wait để trap TERM chạy ngay, không đợi hết sleep
  # "sleep 2" kéo dài > 60s → máy đã ngủ trong lúc đó (đo riêng lệnh sleep, không tính các check chạy chậm)
  slept=$(( $(date +%s) - before ))
  if [ "$slept" -gt 60 ]; then
    info "☀️ Máy thức dậy
Lúc: $(now)
Đã ngủ khoảng: $(dur "$slept")"
  fi
done
