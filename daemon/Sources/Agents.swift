import Foundation

// MARK: - Agent quan trọng nói chung (EDR, MDM, VPN...)
// Agent nào có cài (thư mục cài tồn tại) thì theo dõi: tiến trình đang chạy mà DỪNG → cảnh báo (tắt EDR/firewall/VPN là
// bước đầu của kẻ tấn công); file cấu hình đổi → cảnh báo kèm nội dung (plist nhị phân đổi sang dạng chữ).
// Thêm agent riêng: /etc/macsentry.agents, cùng định dạng: Tên | tiến trình,cách,nhau,dấu,phẩy | thư mục cài | file cấu hình
// (Wazuh có kiểm tra chuyên sâu riêng ở Wazuh.swift nên không nằm ở đây)

let agentCatalog = """
CrowdStrike Falcon|falcond,com.crowdstrike.falcon.Agent|/Applications/Falcon.app|/Library/Application Support/CrowdStrike/Falcon/falconctl.plist
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
OverSight|OverSight|/Applications/OverSight.app|
Tailscale|io.tailscale.ipn.macsys.network-extension,io.tailscale.ipn.macos.network-extension,Tailscale,tailscaled|/Applications/Tailscale.app|
Cloudflare WARP|CloudflareWARP|/Applications/Cloudflare WARP.app|/Library/Managed Preferences/com.cloudflare.warp.plist /Library/Application Support/Cloudflare/mdm.xml
OpenVPN Connect|ovpnagent,ovpnhelper|/Library/Frameworks/OpenVPNConnect.framework|
Tunnelblick|tunnelblickd|/Library/Application Support/Tunnelblick|
TeamViewer (dịch vụ)|TeamViewer_Service|/Applications/TeamViewer.app|/Library/Preferences/com.teamviewer.teamviewer.preferences.plist /Library/Preferences/com.teamviewer.TeamViewer.plist
AnyDesk (dịch vụ)|AnyDesk|/Applications/AnyDesk.app|/Library/Application Support/AnyDesk/system.conf /etc/anydesk/system.conf
"""

var agentsRunning: [String] = []   // cho báo cáo hằng ngày

func checkAgents(_ procs: [Proc]) {
    let names = Set(procs.map(\.name) + procs.compactMap { procBSD($0.pid)?.name })
    var running: [String] = [], cfgs: [String] = []
    let custom = lines(readText("/etc/macsentry.agents")).map { String($0.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first ?? "") }
    for line in lines(agentCatalog) + custom {
        let f = line.split(separator: "|", omittingEmptySubsequences: false).map { $0.trimmingCharacters(in: .whitespaces) }
        guard f.count >= 3, !f[0].isEmpty, exists(f[2]) else { continue }
        for p in f[1].split(separator: ",").map({ $0.trimmingCharacters(in: .whitespaces) }) where !p.isEmpty && names.contains(p) {
            running.append("\(f[0])|\(p)")
        }
        // File cấu hình cách nhau bởi " /" (đường dẫn được có dấu cách)
        if f.count >= 4, !f[3].isEmpty {
            let pats = f[3].components(separatedBy: " /").enumerated().map { $0.offset == 0 ? $0.element : "/" + $0.element }
            cfgs += glob(pats.map { $0.trimmingCharacters(in: .whitespaces) })
        }
    }
    agentsRunning = Array(Set(running.map { String($0.split(separator: "|")[0]) })).sorted()

    // Tiến trình của agent: mất đi → cảnh báo, chạy lại → tin im lặng
    let d = diffState("agent_procs", running)
    for l in d.removed {
        let f = l.split(separator: "|", maxSplits: 1).map(String.init)
        alert("⚠️ Agent \(f[0]): tiến trình \(f.count > 1 ? f[1] : "?") vừa DỪNG\n(nếu bạn không tắt/gỡ agent này → có thể có người cố tắt bảo vệ/giám sát)")
    }
    for l in d.added {
        let f = l.split(separator: "|", maxSplits: 1).map(String.init)
        info("Agent \(f[0]): \(f.count > 1 ? f[1] : "?") đang chạy")
    }

    // Cấu hình agent: so bản dạng chữ
    try? FileManager.default.createDirectory(atPath: sp("files"), withIntermediateDirectories: true)
    let cfgl = Array(Set(cfgs)).sorted()
    if statChanged("agent_cfg", cfgl) {
        for (kind, f) in hashChanges("agent_cfg", cfgl) {
            let copy = copyOf(f), new = plistText(f)
            switch kind {
            case .removed: alert("⚙️ File cấu hình agent bị XOÁ: \(f)"); try? FileManager.default.removeItem(atPath: copy)
            case .new: info("⚙️ File cấu hình agent mới: \(f)"); writeText(copy, new)
            case .changed:
                alert("⚙️ Cấu hình agent THAY ĐỔI: \(f)\n\(lineDiff(readText(copy) ?? "", new, limit: 20))\n(< cũ, > mới)")
                writeText(copy, new)
            }
        }
    }
    for f in cfgl where !exists(copyOf(f)) { writeText(copyOf(f), plistText(f)) }
}
