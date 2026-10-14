# shellcheck shell=bash
# macsentryd — chống cài cắm: file nhạy cảm, Login Items, profile, cert, kext, extension trình duyệt....
# Được macsentryd nạp bằng `.` (dùng chung biến/hàm), không chạy riêng.

# File cấu hình nhạy cảm — hacker hay sửa để giữ quyền truy cập (kèm nội dung thay đổi)
SENSITIVE_FILES=${SENSITIVE_FILES:-"/Users/*/.ssh/authorized_keys /Users/*/.ssh/authorized_keys2 /var/root/.ssh/authorized_keys
  /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* /etc/sudoers /etc/sudoers.d/* /etc/pam.d/*
  /etc/crontab /usr/lib/cron/tabs/* /etc/hosts /etc/zshrc /etc/zprofile /etc/zshenv /etc/bashrc /etc/profile
  /etc/paths /etc/paths.d/* /etc/periodic.conf /etc/rc.common /etc/launchd.conf /etc/ssh/ssh_config
  /Users/*/.ssh/config /Users/*/.zshrc /Users/*/.zprofile /Users/*/.zshenv /Users/*/.zlogin
  /Users/*/.bashrc /Users/*/.bash_profile /Users/*/.profile /var/root/.zshrc /var/root/.profile"}

check_files() {
  mkdir -p "$STATE/files"
  list=$(ls -1d $SENSITIVE_FILES 2>/dev/null | sort -u)
  # Đổi danh sách file theo dõi → tăng FILES_V để lấy mốc lại, không báo nhầm hàng loạt "file MỚI"
  FILES_V=2
  [ "$(cat "$STATE/files_v" 2>/dev/null)" = "$FILES_V" ] || { rm -f "$STATE/filesums"; echo "$FILES_V" > "$STATE/files_v"; }
  first=0; [ -f "$STATE/filesums" ] || first=1
  # Băm ~30 file mỗi lần tốn ~0,4 giây → chỉ băm khi ctime / kích thước / danh sách file đổi
  stat_changed files "$list" || [ $first = 1 ] || return 0
  changes=$(hash_changes filesums "$list")
  if [ $first = 1 ]; then for f in $list; do cp "$f" "$(copy_of "$f")" 2>/dev/null; done; return; fi
  printf '%s\n' "$changes" | while read -r kind f; do
    [ -n "$f" ] || continue
    copy=$(copy_of "$f")
    case $kind in
      removed) alert "📝 File nhạy cảm bị XOÁ: $f"; rm -f "$copy" ;;
      new)     alert "📝 File nhạy cảm MỚI: $f
$(head -10 "$f" | mask_secrets | cut -c1-200)"; cp "$f" "$copy" ;;
      changed)
        # Shell rc / ssh config của user: bạn hay tự sửa → tin im lặng (vẫn kèm nội dung để soát)
        notify=alert
        case $f in /etc/pam.d/*|/etc/zshrc|/etc/zprofile|/etc/zshenv|/etc/bashrc|/etc/profile|/etc/ssh/sshd_config|/etc/ssh/ssh_config|/etc/paths)
          hint="
(file của macOS — nếu vừa cập nhật macOS thì thường là bình thường)" ;;
          /Users/*)
          notify=info; hint="
(file của user — nếu bạn không vừa sửa thì kiểm tra dòng mới: alias/lệnh lạ chạy mỗi lần mở terminal)" ;;
          *) hint="" ;; esac
        $notify "📝 File nhạy cảm bị SỬA: $f
$(diff "$copy" "$f" 2>/dev/null | grep '^[<>]' | head -15 | mask_secrets | cut -c1-200)
(< dòng cũ, > dòng mới)$hint"; cp "$f" "$copy" ;;
    esac
  done
}

check_persistence() {
  # Login Items / Background Items đăng ký qua SMAppService (loại "legacy" = plist, đã theo dõi ở check_system)
  # sfltool tốn ~3–5 giây → chỉ chạy khi file DB Background Items đổi (hoặc mỗi giờ một lần cho chắc), và chạy
  # NỀN (không chặn vòng lặp chính: kết nối từ xa, hàng đợi tin) — kết quả được so ở lượt 60 giây kế tiếp
  btm_sig="$(stat -f '%c %z %N' /private/var/db/com.apple.backgroundtaskmanagement/* 2>/dev/null) $(( $(date +%s) / 3600 ))"
  if [ -f "$STATE/btm_scan" ]; then
    btm=$(cat "$STATE/btm_scan"); rm -f "$STATE/btm_scan"
    diff_state btm "$btm" nonempty | while read -r sign rest; do
      [ "$sign" = "+" ] && alert "🧩 Mục chạy nền / Login Item mới: $rest" || info "🧩 Đã gỡ mục chạy nền: $rest"
    done
  fi
  if [ "$btm_sig" != "$(cat "$STATE/btm_sig" 2>/dev/null)" ]; then
    echo "$btm_sig" > "$STATE/btm_sig"
    ( sfltool dumpbtm 2>/dev/null | awk -F': ' '/^ *Type:/ { t = $2 } /^ *Identifier:/ {
        if (t !~ /^(developer|app|legacy)/) print t " | " $2 }' | sort -u > "$STATE/btm_scan.tmp" &&
      mv -f "$STATE/btm_scan.tmp" "$STATE/btm_scan" ) &
  fi

  # Bỏ profile Screen Time (com.apple.ManagedSettings.*): macOS tự tạo/xoá khi đổi cài đặt Screen Time
  profs=$(profiles list -all 2>/dev/null | sed -n 's/.*profileIdentifier: //p' | grep -v '^com\.apple\.ManagedSettings\.')
  diff_state profiles "$profs" | while read -r sign p; do
    [ "$sign" = "+" ] && alert "📜 Có configuration profile MỚI: $p
(profile có thể ép proxy, chứng chỉ, quản lý máy từ xa)" || info "📜 Đã gỡ profile: $p"
  done

  sysext=$(systemextensionsctl list 2>/dev/null | awk -F'\t' 'NF >= 6 && $3 != "teamID" { sub(/ \(.*/, "", $4); print $4 }')
  diff_state sysext "$sysext" | while read -r sign e; do
    [ "$sign" = "+" ] && alert "🧷 System extension mới: $e" || info "🧷 System extension đã gỡ: $e"
  done

  proxy=$(scutil --proxy | awk '/Enable : 1|URLString|Proxy :|Port :/ { $1 = $1; print }')
  diff_state proxy "$proxy" | while read -r sign v; do
    [ "$sign" = "+" ] && alert "🕸 Cấu hình PROXY thay đổi: $v
(proxy lạ có thể dùng để nghe lén traffic)"
  done
  dns=$(scutil --dns | awk '/nameserver\[/ { print $3 }' | sort -u)
  diff_state dns "$dns" | while read -r sign v; do [ "$sign" = "+" ] && info "🧭 DNS server mới: $v"; done

  # Thư mục cài cắm ít gặp nhưng nguy hiểm: authorization plugin (chạy lúc đăng nhập, đọc được mật khẩu),
  # helper chạy bằng root, StartupItems, plugin Directory Services, kext, plugin âm thanh (nghe lén), periodic
  pdirs=$(ls -1d /Library/Security/SecurityAgentPlugins/* /Library/PrivilegedHelperTools/* /Library/StartupItems/* \
          /Library/DirectoryServices/PlugIns/* /Library/Extensions/* /Library/Audio/Plug-Ins/HAL/* \
          /etc/periodic/*/* /usr/local/etc/periodic/*/* 2>/dev/null)
  diff_state persist_dirs "$pdirs" | while read -r sign path; do
    if [ "$sign" = "+" ]; then
      case $path in
        /Library/Security/SecurityAgentPlugins/*) hint="(authorization plugin: chạy trong quá trình đăng nhập, có thể đọc mật khẩu)" ;;
        /Library/PrivilegedHelperTools/*) hint="(helper chạy bằng quyền root)" ;;
        *) hint="" ;;
      esac
      alert "🧩 Thành phần tự chạy MỚI: $path
Chữ ký: $(sig_of "$path")
$hint"
    else info "🧩 Đã gỡ: $path"; fi
  done

  # Login/Logout hook (cách cũ nhưng vẫn chạy bằng root mỗi lần đăng nhập)
  hooks=$(for d in /Library/Preferences/com.apple.loginwindow /var/root/Library/Preferences/com.apple.loginwindow; do
            for k in LoginHook LogoutHook; do v=$(defaults read "$d" "$k" 2>/dev/null) && echo "$k: $v"; done; done)
  diff_state hooks "$hooks" | while read -r sign v; do
    [ "$sign" = "+" ] && alert "🪝 Login/Logout hook MỚI: $v"
  done

  # Chứng chỉ Root CA được tin cậy thêm (dùng để giải mã/nghe lén HTTPS)
  certs=$( { security find-certificate -a -Z /Library/Keychains/System.keychain 2>/dev/null |
               awk '/^SHA-1 hash:/ { h = $3 } /"labl"/ { sub(/.*="/, ""); sub(/"$/, ""); print "System.keychain | " $0 " | " substr(h, 1, 12) }'
             security dump-trust-settings -d 2>/dev/null | sed -n 's/^Cert [0-9]*: /Tin cậy (admin) | /p'; } | sort -u)
  diff_state certs "$certs" nonempty | while read -r sign v; do
    [ "$sign" = "+" ] && alert "📜 Chứng chỉ MỚI được thêm / tin cậy: $v
(chứng chỉ gốc lạ cho phép nghe lén HTTPS — nếu không phải bạn cài (mkcert, Proxyman...) thì gỡ ngay)" || info "📜 Đã gỡ chứng chỉ: $v"
  done

  # Kernel extension bên thứ ba đang nạp
  if ! es_alive || throttle kmutil_scan 1800; then
  kexts=$(kmutil showloaded --list-only 2>/dev/null | awk '{ print $6 }' | grep -v -E '^(com\.apple\.|$)')
  diff_state kexts "$kexts" | while read -r sign k; do
    [ "$sign" = "+" ] && alert "🧷 Kernel extension MỚI được nạp: $k" || info "🧷 Kernel extension đã gỡ: $k"
  done
  fi

  # Dịch vụ hệ thống bị tắt (launchctl disable) — kẻ tấn công có thể tắt dịch vụ bảo mật
  disabled=$(launchctl print-disabled system 2>/dev/null | awk -F'"' '/=> (disabled|true)/ { print $2 }')
  diff_state launchd_disabled "$disabled" | while read -r sign s; do
    [ "$sign" = "+" ] && alert "⛔️ Dịch vụ hệ thống vừa bị TẮT (launchctl disable): $s" || info "Dịch vụ được bật lại: $s"
  done

  # Extension trình duyệt (Chrome / Edge / Brave): extension độc có thể đọc mọi trang, cookie, mật khẩu đã nhập
  extdirs=$(ls -1d /Users/*/Library/Application\ Support/Google/Chrome/*/Extensions /Users/*/Library/Application\ Support/Microsoft\ Edge/*/Extensions \
             /Users/*/Library/Application\ Support/BraveSoftware/Brave-Browser/*/Extensions 2>/dev/null)
  stat_changed browser_ext_dirs "$extdirs" && {
  exts=$(for d in /Users/*/Library/Application\ Support/Google/Chrome /Users/*/Library/Application\ Support/Microsoft\ Edge \
                  /Users/*/Library/Application\ Support/BraveSoftware/Brave-Browser; do
           for e in "$d"/*/Extensions/*; do [ -d "$e" ] || continue
             m=$(ls -1d "$e"/*/manifest.json 2>/dev/null | tail -1)
             n=$(plutil -extract name raw -o - "$m" 2>/dev/null)
             if [ -z "$n" ] || [ "${n#__MSG_}" != "$n" ]; then n=?; fi
             echo "$(basename "$(dirname "$(dirname "$d/x")")")/$(basename "$d") | $(basename "$e") | $n"; done; done | sort -u)
  diff_state browser_ext "$exts" | while read -r sign v; do
    [ "$sign" = "+" ] && alert "🧩 Extension trình duyệt MỚI: $v" || info "🧩 Đã gỡ extension trình duyệt: $v"
  done
  }

  apps=$(ls -1d /Applications/*.app /Users/*/Applications/*.app 2>/dev/null)
  diff_state apps "$apps" nonempty | while read -r sign a; do
    [ "$sign" = "+" ] && info "📦 App mới được cài: $a
Chữ ký: $(sig_of "$a")" || info "📦 App bị gỡ: $a"
  done
}
