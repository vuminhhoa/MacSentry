# shellcheck shell=bash
# macsentryd — tư thế bảo mật (SIP, FileVault, khoá màn hình...) và tự bảo vệ file của MacSentry.
# Được macsentryd nạp bằng `.` (dùng chung biến/hàm), không chạy riêng.

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
    touch "$STATE/expect_sudo"   # báo trước cho helper ES: lệnh sudo ngay sau đây là của MacSentry, không báo
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

}

# File của chính MacSentry bị sửa/xoá — mỗi 60 giây (tư thế bảo mật ở trên chỉ mỗi 5 phút)
check_self() {
  # File của chính MacSentry bị sửa/xoá (nếu không phải bạn vừa cập nhật → có thể bị can thiệp)
  self=$(ls -1d /usr/local/libexec/macsentryd /usr/local/libexec/macsentry/*.sh /Library/LaunchDaemons/io.github.vuminhhoa.macsentry.daemon.plist /etc/macsentry.conf "$TRUSTED" \
         /usr/local/libexec/macsentry-es /Library/LaunchDaemons/io.github.vuminhhoa.macsentry.es.plist \
         /Users/*/Applications/MacSentry.app/Contents/MacOS/MacSentry 2>/dev/null)
  stat_changed self "$self" && hash_changes selfsums "$self" | while read -r kind f; do
    [ -n "$f" ] || continue
    case $kind in
      removed) alert "🧬 File của MacSentry bị XOÁ: $f" ;;
      # File mới chỉ xuất hiện khi cài / cập nhật (daemon chỉ nạp danh sách module cố định, file lạ không được chạy)
      new) info "🧬 File mới của MacSentry: $f" ;;
      *) alert "🧬 File của MacSentry thay đổi: $f
(nếu bạn không vừa cập nhật MacSentry → có thể bị can thiệp)" ;;
    esac
  done
}
