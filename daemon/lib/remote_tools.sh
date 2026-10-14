# shellcheck shell=bash
# macsentryd — app điều khiển từ xa (TeamViewer, AnyDesk...) và tunnel (ngrok, cloudflared...).
# Được macsentryd nạp bằng `.` (dùng chung biến/hàm), không chạy riêng.

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
  rtlogs=$(ls -1d /Library/Logs/TeamViewer/*.log /Users/*/Library/Logs/TeamViewer/*.log \
           /Users/*/.anydesk/*.trace /Library/Application\ Support/AnyDesk/*.trace /var/log/anydesk*.trace \
           /Users/*/Library/Logs/RustDesk/server/*.log /Users/*/Library/Logs/RustDesk/*.log 2>/dev/null)
  # Lần quét đầu: chỉ ghi mốc cuối các log đang có; về sau file log MỚI (app vừa cài) được đọc từ đầu
  rt_new=new-ok; [ -f "$STATE/rt_logs_init" ] || { rt_new=; touch "$STATE/rt_logs_init"; }
  stat_changed rt_logs "$rtlogs" || return 0   # không file log nào đổi → không có phiên mới
  printf '%s\n' "$rtlogs" | while IFS= read -r f; do
    [ -f "$f" ] || continue
    key=${f//[^A-Za-z0-9._-]/_}; key=${key: -120}
    hits=$(tail_new "rt_$key" "$f" $rt_new | grep -a -i -E 'incoming session|accepting from|connection incoming|incoming connection|new connection from|session started|authenticated|remote control (started|session)|login from' | tail -5 | cut -c1-250)
    [ -n "$hits" ] && throttle "rtlog_$key" 60 && alert "🚨 Có PHIÊN KẾT NỐI ĐẾN qua app điều khiển từ xa
Log: $f
$hits"
  done
}
