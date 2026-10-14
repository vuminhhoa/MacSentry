# shellcheck shell=bash
# macsentryd — phần cứng & mạng: USB, ổ đĩa ngoài, pin, đổi mạng, ổ đầy.
# Được macsentryd nạp bằng `.` (dùng chung biến/hàm), không chạy riêng.

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

  # Nguồn điện / pin (máy không có pin như Mac mini: bỏ qua hẳn, không chạy pmset)
  if [ "$HAS_BATTERY" = 1 ]; then
    batt=$(pmset -g batt)
    src=$(printf '%s' "$batt" | sed -n "s/.*'\(.*\)'.*/\1/p" | head -1)
    pct=$(printf '%s' "$batt" | grep -o '[0-9]*%' | head -1 | tr -d %)
    diff_state power "$src" | while read -r sign v; do
      [ "$sign" = "+" ] && { [ "$v" = "Battery Power" ] && alert "🔋 Vừa RÚT SẠC (đang chạy pin $pct%)" || info "🔌 Đã cắm sạc ($pct%)"; }
    done
    if [ "${pct:-100}" -le 15 ] && [ "$src" = "Battery Power" ]; then throttle battlow 3600 && alert "🪫 Pin yếu: $pct%"; fi
  fi

}
HAS_BATTERY=$(pmset -g batt 2>/dev/null | grep -q InternalBattery && echo 1 || echo 0)

# Mạng + ổ đĩa: mỗi 30 giây
check_hardware_slow() {
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
