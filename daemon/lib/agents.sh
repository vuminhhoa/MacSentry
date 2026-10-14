# shellcheck shell=bash
# macsentryd — agent quan trọng nói chung (EDR, MDM, VPN...) và toàn vẹn mọi LaunchDaemon/Agent.
# Được macsentryd nạp bằng `.` (dùng chung biến/hàm), không chạy riêng.

# Danh mục sản phẩm bảo mật / quản lý / VPN / điều khiển từ xa. Agent nào có cài (thư mục cài tồn tại) thì theo dõi:
#   - tiến trình đang chạy mà DỪNG → cảnh báo (tắt EDR/firewall/VPN là bước đầu của kẻ tấn công)
#   - file cấu hình thay đổi → cảnh báo kèm nội dung (plist nhị phân được đổi sang dạng chữ)
# Thêm agent riêng: /etc/macsentry.agents, cùng định dạng: Tên | tiến trình,cách,nhau,dấu,phẩy | thư mục cài | file cấu hình (glob)
# (Wazuh đã có kiểm tra chuyên sâu riêng ở check_wazuh nên không nằm ở đây)
AGENT_CATALOG='CrowdStrike Falcon|falcond,com.crowdstrike.falcon.Agent|/Applications/Falcon.app|/Library/Application Support/CrowdStrike/Falcon/falconctl.plist
SentinelOne|sentineld,sentineld_helper,sentineld_shell|/Library/Sentinel|/Library/Sentinel/sentinel-agent.bundle/Contents/Resources/config/*.json
Microsoft Defender|wdavdaemon,wdavdaemon_enterprise,wdavdaemon_unprivileged|/Applications/Microsoft Defender.app|/Library/Managed Preferences/com.microsoft.wdav.plist /Library/Application Support/Microsoft/Defender/wdavcfg
Sophos Endpoint|SophosScanD,SophosServiceManager,SophosAntiVirus,SophosMcsAgentD|/Library/Sophos Anti-Virus|
Sophos Connect VPN|scvpn,charon|/Library/Sophos Connect|
ESET|esets_daemon,esets_proxy|/Applications/ESET Endpoint Security.app|
Kaspersky|kav,klnagent|/Library/Application Support/Kaspersky Lab|
Malwarebytes|RTProtectionDaemon,Malwarebytes|/Library/Application Support/Malwarebytes|
Santa|santad,santasyncservice,com.northpolesec.santa.daemon,com.google.santa.daemon|/Applications/Santa.app|/var/db/santa/config.plist /Library/Managed Preferences/com.northpolesec.santa.plist /Library/Managed Preferences/com.google.santa.plist
Jamf|jamf,JamfDaemon,JamfAgent|/usr/local/jamf|/Library/Preferences/com.jamfsoftware.jamf.plist
Jamf Protect|JamfProtect,com.jamf.protect.daemon|/Applications/JamfProtect.app|
Kandji|kandji-daemon,Kandji Agent|/Library/Kandji|
Microsoft Intune|IntuneMdmDaemon,IntuneMdmAgent|/Library/Intune|
Little Snitch|at.obdev.littlesnitch.networkextension,Little Snitch Daemon,Little Snitch Agent|/Applications/Little Snitch.app|
LuLu|com.objective-see.lulu.extension,LuLu|/Applications/LuLu.app|
BlockBlock|BlockBlock,BlockBlock Helper|/Applications/BlockBlock Helper.app|
Tailscale|io.tailscale.ipn.macsys.network-extension,io.tailscale.ipn.macos.network-extension,Tailscale,tailscaled|/Applications/Tailscale.app|
Cloudflare WARP|CloudflareWARP|/Applications/Cloudflare WARP.app|/Library/Managed Preferences/com.cloudflare.warp.plist /Library/Application Support/Cloudflare/mdm.xml
OpenVPN Connect|ovpnagent,ovpnhelper|/Library/Frameworks/OpenVPNConnect.framework|
Tunnelblick|tunnelblickd|/Library/Application Support/Tunnelblick|
TeamViewer (dịch vụ)|TeamViewer_Service|/Applications/TeamViewer.app|/Library/Preferences/com.teamviewer.teamviewer.preferences.plist /Library/Preferences/com.teamviewer.TeamViewer.plist
AnyDesk (dịch vụ)|AnyDesk|/Applications/AnyDesk.app|/Library/Application Support/AnyDesk/system.conf /etc/anydesk/system.conf'

check_agents() {
  allprocs=$(ps -axo comm= | sed 's|.*/||' | sort -u)
  { printf '%s\n' "$AGENT_CATALOG"; sed 's/#.*//' /etc/macsentry.agents 2>/dev/null; } |
  while IFS='|' read -r name procs dir cfgs; do
    name=${name#"${name%%[![:space:]]*}"}; name=${name%"${name##*[![:space:]]}"}
    dir=${dir#"${dir%%[![:space:]]*}"}; dir=${dir%"${dir##*[![:space:]]}"}
    [ -n "$name" ] && [ -e "$dir" ] || continue
    printf '%s' "$procs" | tr ',' '\n' | while read -r p; do
      p=${p#"${p%%[![:space:]]*}"}; p=${p%"${p##*[![:space:]]}"}
      [ -n "$p" ] && case "
$allprocs
" in *"
$p
"*) echo "$name|$p" ;; esac
    done
    # File cấu hình (cách nhau bởi " /", đường dẫn được có dấu cách): in "cfg|đường dẫn" để xử lý chung bên dưới
    printf '%s' "$cfgs" | awk '{ n = split($0, a, / +\//); for (i = 1; i <= n; i++) { s = a[i]; gsub(/^ +| +$/, "", s)
                                   if (s == "") continue; if (i > 1) s = "/" s; print s } }' |
    while IFS= read -r g; do
      ( IFS='
'; for f in $g; do [ -f "$f" ] && echo "cfg|$f"; done )
    done
  done > "$STATE/agents_scan"

  # Tiến trình của agent: mất đi → cảnh báo, chạy lại → tin im lặng
  diff_state agent_procs "$(grep -v '^cfg|' "$STATE/agents_scan")" | while IFS='|' read -r sp p; do
    sign=${sp%% *}; name=${sp#* }
    [ "$sign" = "-" ] && alert "⚠️ Agent $name: tiến trình $p vừa DỪNG
(nếu bạn không tắt/gỡ agent này → có thể có người cố tắt bảo vệ/giám sát)" || info "Agent $name: $p đang chạy"
  done

  # Cấu hình agent: so bản dạng chữ (plist nhị phân → plutil -p)
  mkdir -p "$STATE/files"
  cfgl=$(sed -n 's/^cfg|//p' "$STATE/agents_scan" | sort -u)
  stat_changed agent_cfg "$cfgl" && hash_changes agent_cfg "$cfgl" | while read -r kind f; do
    [ -n "$f" ] || continue
    copy=$(copy_of "$f"); new=$(plutil -p "$f" 2>/dev/null || cat "$f")
    case $kind in
      removed) alert "⚙️ File cấu hình agent bị XOÁ: $f" ;;
      new) info "⚙️ File cấu hình agent mới: $f" ;;
      changed) alert "⚙️ Cấu hình agent THAY ĐỔI: $f
$(printf '%s\n' "$new" | diff "$copy" - 2>/dev/null | grep '^[<>]' | head -20 | mask_secrets | cut -c1-200)
(< cũ, > mới)" ;;
    esac
    [ "$kind" = removed ] && rm -f "$copy" || printf '%s\n' "$new" > "$copy"
  done
  printf '%s\n' "$cfgl" | while IFS= read -r f; do
    [ -n "$f" ] && [ ! -f "$(copy_of "$f")" ] && { plutil -p "$f" 2>/dev/null || cat "$f"; } > "$(copy_of "$f")" 2>/dev/null
  done
}

# Mọi LaunchDaemon/LaunchAgent: nội dung plist bị sửa, hoặc file chạy bị thay bằng file có CHỮ KÝ KHÁC (mỗi ~5 phút)
check_daemon_integrity() {
  mkdir -p "$STATE/files" "$STATE/signers"
  plists=$(ls -1d /Library/LaunchDaemons/*.plist /Library/LaunchAgents/*.plist /Users/*/Library/LaunchAgents/*.plist 2>/dev/null)
  stat_changed plists "$plists" && hash_changes plist_sums "$plists" | while read -r kind f; do
    [ "$kind" = changed ] || continue
    copy=$(copy_of "$f"); new=$(plutil -p "$f" 2>/dev/null)
    d=$(printf '%s\n' "$new" | diff "$copy" - 2>/dev/null | grep '^[<>]' | head -15 | mask_secrets | cut -c1-200)
    case $f in /Users/*) n=info ;; *) n=alert ;; esac   # LaunchAgent của user hay bị app tự cập nhật
    $n "🧩 Cấu hình tự khởi động bị SỬA: $f
${d:-(không đọc được nội dung cũ)}
(< cũ, > mới)"
    printf '%s\n' "$new" > "$copy"
  done
  for f in $plists; do [ -f "$(copy_of "$f")" ] || plutil -p "$f" > "$(copy_of "$f")" 2>/dev/null; done

  for f in $(ls -1d /Library/LaunchDaemons/*.plist /Library/LaunchAgents/*.plist 2>/dev/null); do
    label=$(plutil -extract Label raw -o - "$f" 2>/dev/null) || continue
    prog=$(plutil -extract Program raw -o - "$f" 2>/dev/null || plutil -extract ProgramArguments.0 raw -o - "$f" 2>/dev/null)
    [ -n "$prog" ] || continue
    sf="$STATE/signers/$label"
    # codesign chậm → chỉ kiểm lại khi file chạy đổi ctime / kích thước
    key=$(stat -f '%c %z' "$prog" 2>/dev/null)
    [ -n "$key" ] && [ "$key" = "$(cat "$sf.key" 2>/dev/null)" ] && [ -f "$sf" ] && continue
    echo "$key" > "$sf.key"
    sig=$(sig_of "$prog")
    old=$(cat "$sf" 2>/dev/null)
    if [ -n "$old" ] && [ "$old" != "$sig" ]; then
      alert "☠️ File chạy của dịch vụ $label đổi CHỮ KÝ
File: $prog
Trước: $old
Bây giờ: $sig
(cập nhật hợp lệ thường giữ nguyên nhà phát hành — đổi nhà phát hành / mất chữ ký là dấu hiệu bị tráo file)"
    fi
    printf '%s' "$sig" > "$sf"
  done
}
