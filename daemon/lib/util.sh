# shellcheck shell=bash
# macsentryd — tiện ích chung: ghi log, gửi Telegram, chống spam, so sánh trạng thái, băm file.
# Được macsentryd nạp bằng `.` (dùng chung biến/hàm), không chạy riêng.

# Thời điểm hiện tại không cần fork `date`: $SECONDS của shell tăng theo đồng hồ thật (kể cả lúc máy ngủ)
BASE_T=$(( $(date +%s) - SECONDS ))

now() { date '+%d/%m/%Y %H:%M:%S'; }
log() { printf '%s %s\n' "$(now)" "$(printf '%s' "$*" | tr '\n' ' ')" >> "$LOG"; }
# Nội dung tin hợp lệ với Telegram: tối đa 4096 ký tự → cắt ở 3900 byte (luôn ≤ 3900 ký tự), rồi bỏ byte UTF-8
# hỏng (do cắt giữa ký tự, hoặc `cut -c` cắt theo byte ở locale C) — tin lỗi bị Telegram trả 400 và mất hẳn
tg_text() {
  local t="🛡 $HOST
$1"
  [ ${#t} -gt 3900 ] && t="$(printf '%s' "$t" | head -c 3900)
…(đã cắt bớt, xem đủ trong /var/log/macsentry.log)"
  printf '%s' "$t" | iconv -c -f UTF-8 -t UTF-8 2>/dev/null
}
post() { # $1 = nội dung, $2 = timeout giây, $3 = im lặng (true/false); in ra mã HTTP
  [ -n "$DRYRUN" ] && { echo 200; return; }   # chạy thử: không gửi thật
  # URL chứa token đưa qua stdin (-K -), KHÔNG để trên dòng lệnh: user thường xem được tham số của tiến trình
  # root bằng `ps` → phần mềm độc chạy bằng user sẽ lấy được token của daemon
  printf 'url = "https://api.telegram.org/bot%s/sendMessage"\n' "$TOKEN" |
  curl -s -m "$2" -o /dev/null -w '%{http_code}' -K - \
    --data-urlencode "chat_id=$CHAT" --data-urlencode "disable_notification=${3:-false}" \
    --data-urlencode "text=$(tg_text "$1")"
}
# Gửi nền, thử lại tới ~5 phút (lúc mới bật/thức máy có thể chưa có mạng). Chỉ thử lại khi lỗi tạm thời
# (mạng = 000, quá tải 429, máy chủ 5xx); lỗi 4xx khác gửi lại cũng vô ích → ghi log ngay.
send() { # $1 = nội dung, $2 = im lặng
  log "$1"
  ( i=0; while [ $i -lt 30 ]; do
      c=$(post "$1" 10 "${2:-false}")
      case $c in 200) exit 0 ;; 000|429|5??) ;; *) log "Gửi Telegram thất bại (HTTP $c)"; exit 1 ;; esac
      i=$((i+1)); sleep 10
    done
    log "Gửi Telegram thất bại (hết lượt thử lại)" ) &
}
alert() { send "$1" false; }   # có chuông
info() { send "$1" true; }     # im lặng
# Gửi ngay và chờ (dùng khi sắp tắt máy)
send_now() { log "$1"; post "$1" 5 false >/dev/null; }

# Chống spam: trả về 0 nếu khoá $1 chưa gửi trong $2 giây gần đây
throttle() {
  local f t l k
  # Tên file từ khoá bằng phép thay thế của shell (không fork cksum)
  k=$1; k=${k//[^A-Za-z0-9._-]/_}; f="$STATE/throttle/${k:0:150}"
  t=$((BASE_T + SECONDS)); l=0
  [ -f "$f" ] && read -r l < "$f"
  [ $((t - ${l:-0})) -ge "$2" ] || return 1
  echo "$t" > "$f"
}

# Dọn file chống spam cũ (mỗi khoá một file, khoá có thể chứa cả dòng lệnh → không dọn thì tăng mãi).
# Khoá giữ lâu nhất là 7 ngày (sametoken) → xoá file không đụng tới hơn 8 ngày. Mỗi ngày một lần.
cleanup_state() {
  throttle cleanup_state 86400 || return 0
  find "$STATE/throttle" -type f -mtime +8 -delete 2>/dev/null
}

# Helper Endpoint Security (macsentry-es) còn sống: nó chạm file này mỗi phút khi eslogger đang chạy được
es_alive() { local f="$STATE/es_alive"; [ -f "$f" ] && [ $(( BASE_T + SECONDS - $(stat -f %m "$f") )) -lt 180 ]; }

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
  f="$STATE/tail_$1"
  # File chưa có: mốc 0 → khi file xuất hiện (vd active-responses.log ở lần active response ĐẦU TIÊN) đọc từ đầu
  size=$(stat -f %z "$2" 2>/dev/null) || { [ -f "$f" ] || echo 0 > "$f"; return 0; }
  off=$(cat "$f" 2>/dev/null); echo "$size" > "$f"
  # Chưa có mốc: lần chạy đầu của daemon → chỉ ghi mốc (không gửi lại nội dung cũ); file mới xuất hiện SAU
  # lần quét đầu (gọi kèm $3 = "new-ok", vd log của app điều khiển từ xa vừa cài) → đọc từ đầu
  if [ -z "$off" ]; then [ "$3" = new-ok ] || return 0; off=0; fi
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
  local f new old
  f="$STATE/$1"
  # $3 = "nonempty": danh sách không bao giờ rỗng thật (user, app, ...) → rỗng nghĩa là lệnh lỗi, bỏ qua lần này
  if [ "$3" = nonempty ]; then case $2 in *[![:space:]]*) ;; *) return ;; esac; fi
  new=$(sort <<LIST
$2
LIST
)
  while [ "${new#
}" != "$new" ]; do new=${new#
}; done   # bỏ dòng trống (sau sort chúng nằm đầu)
  if [ ! -f "$f" ]; then
    if [ -n "$new" ]; then printf '%s\n' "$new" > "$f"; else : > "$f"; fi
    return
  fi
  # Đường tắt — trường hợp phổ biến nhất là KHÔNG đổi: đọc file bằng builtin, không fork comm/sed/mv
  old=""; IFS= read -r -d '' old < "$f"; old=${old%
}
  [ "$new" = "$old" ] && return
  if [ -n "$new" ]; then printf '%s\n' "$new" > "$f.new"; else : > "$f.new"; fi
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
