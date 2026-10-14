# shellcheck shell=bash
# macsentryd — xác thực qua `log stream` (dự phòng khi helper Endpoint Security không chạy).
# Được macsentryd nạp bằng `.` (dùng chung biến/hàm), không chạy riêng.

user_of_uuid() { dscl . -search /Users GeneratedUID "$1" 2>/dev/null | awk 'NR==1{print $1}'; }

# Dừng một tiến trình cùng mọi tiến trình con cháu (kill thường chỉ tới tiến trình con trực tiếp)
kill_tree() {
  local c
  for c in $(pgrep -P "$1" 2>/dev/null); do kill_tree "$c"; done
  kill "$1" 2>/dev/null
}

# `log stream` tốn ~5% một nhân → chỉ là đường DỰ PHÒNG khi helper Endpoint Security không chạy
# (helper đã có sự kiện authentication / sudo / su / openssh_login, chính xác hơn).
auth_watch() {
  local sp
  while kill -0 "$MAIN_PID" 2>/dev/null; do
    if es_alive; then sleep 30; continue; fi
    auth_stream & sp=$!
    while kill -0 "$sp" 2>/dev/null && ! es_alive && kill -0 "$MAIN_PID" 2>/dev/null; do sleep 15; done
    kill_tree "$sp"   # dừng cả log stream lẫn vòng đọc
    sleep 5
  done
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
