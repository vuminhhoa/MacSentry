# shellcheck shell=bash
# macsentryd — tự khởi động mới, dịch vụ từ xa, tài khoản/firewall/Gatekeeper, reverse shell, cổng mới.
# Được macsentryd nạp bằng `.` (dùng chung biến/hàm), không chạy riêng.

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

# Tài khoản, firewall, Gatekeeper: hiếm khi đổi và lệnh tốn hơn → mỗi 60 giây (thay vì 10 giây)
check_accounts() {
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

}

# Nghi reverse shell (mỗi 4 giây): shell / netcat giữ kết nối TCP ra ngoài.
# Ghi chi tiết tiến trình NGAY (tiến trình có thể kết thúc sau vài giây), tra IP trong tiến trình nền.
REVSHELL_LSOF_C=$(for c in bash sh zsh dash ksh tcsh csh fish nc ncat netcat socat telnet perl ruby php osascript tclsh expect lua; do
                   printf -- '-c %s ' "$c"; done)
check_revshell() {
  rs=$(lsof -nP -a -iTCP -sTCP:ESTABLISHED $REVSHELL_LSOF_C -F pcn 2>/dev/null | awk '/^p/ { p = substr($0, 2) } /^c/ { c = substr($0, 2) } /^n/ {
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
