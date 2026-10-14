# shellcheck shell=bash
# macsentryd — chi tiết giúp phân biệt cảnh báo thật / giả: chữ ký số, tiến trình, IP, máy chủ tin cậy.
# Được macsentryd nạp bằng `.` (dùng chung biến/hàm), không chạy riêng.

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
