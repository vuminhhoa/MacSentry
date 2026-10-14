# shellcheck shell=bash
# macsentryd — kết nối truy cập từ xa (SSH, VNC, ARD, SMB, AFP) + chia sẻ trạng thái cho app.
# Được macsentryd nạp bằng `.` (dùng chung biến/hàm), không chạy riêng.

check_remote() {
  t=$1
  cur=$(netstat -an -p tcp | awk -v re="$REMOTE_PORTS_RE" '$6=="ESTABLISHED" { n=split($4,a,"."); if (a[n] ~ re) print a[n]" "$5 }' | sort -u)
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

  # Chia sẻ kết quả cho app MacSentry (chạy bằng user) → app không phải tự chạy netstat/who mỗi 2 giây.
  # Chỉ ghi khi có thay đổi; định dạng mỗi dòng: "conn <cổng> <địa chỉ.cổng xa>" hoặc "who <user> <tty> <(host)>"
  pub="$cur
--
$logins"
  if [ "$pub" != "$PUB_LAST" ]; then
    { printf '%s\n' "$cur" | sed '/^$/d; s/^/conn /'; printf '%s\n' "$logins" | sed '/^$/d; s/^/who /'; } > "$PUB_DIR/remote.tmp" &&
      mv -f "$PUB_DIR/remote.tmp" "$PUB_DIR/remote"
    PUB_LAST=$pub
  fi
}
