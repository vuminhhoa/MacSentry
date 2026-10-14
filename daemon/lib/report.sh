# shellcheck shell=bash
# macsentryd — báo cáo tóm tắt hằng ngày.
# Được macsentryd nạp bằng `.` (dùng chung biến/hàm), không chạy riêng.

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
