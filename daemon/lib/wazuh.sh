# shellcheck shell=bash
# macsentryd — Wazuh agent: tiến trình, kết nối manager, cấu hình, active response.
# Được macsentryd nạp bằng `.` (dùng chung biến/hàm), không chạy riêng.

# Wazuh chạy bằng root và nhận lệnh từ máy chủ quản lý (manager): theo dõi agent còn chạy, kết nối tới đâu,
# cấu hình có bị đổi (kể cả cấu hình manager đẩy xuống), manager có chạy lệnh / active response trên máy không.

WZ=/Library/Ossec
check_wazuh() {
  [ -d "$WZ" ] || return 0
  first=0; [ -f "$STATE/wazuh_posture" ] || first=1

  # Tiến trình: dừng tiến trình nào cũng báo (tắt EDR là bước đầu của kẻ tấn công)
  run=$(ps -axo comm= | sed 's|.*/||' | grep -x -E 'wazuh-(agentd|execd|syscheckd|logcollector|modulesd)' | sort -u)
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
  # Tính lại chỉ khi cấu hình / bản cài đổi (wazuh-control info là cả một script shell — không chạy mỗi 30 giây)
  if [ $first = 1 ] || stat_changed wazuh_posture_src "$conf
$lio
$WZ/bin/wazuh-control"; then
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
  [ -n "$ver" ] || ver=$(sed -n 's/^Wazuh phiên bản: //p' "$STATE/wazuh_now" 2>/dev/null)   # khi không tính lại tư thế ở trên
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
