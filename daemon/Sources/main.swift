// macsentryd — daemon cảnh báo an ninh chạy bằng root qua LaunchDaemon: chạy từ lúc bật máy (trước khi đăng nhập),
// user thường không tắt/sửa được. Gửi Telegram khi có:
//   - Bật / tắt máy, máy thức dậy, macsentryd bị kill -9
//   - Kết nối truy cập từ xa (SSH, Screen Sharing/VNC, Remote Desktop, SMB, AFP), đăng nhập SSH, dịch vụ từ xa bật/tắt,
//     cổng mới mở ra mạng, nghi reverse shell, app điều khiển từ xa / tunnel
//   - Chống cài cắm: LaunchAgent/Daemon, file nhạy cảm (kèm nội dung đổi), Login Items, profile, system extension,
//     proxy, DNS, Root CA, kext, login hook, extension trình duyệt, user/admin mới, app mới
//   - Tư thế bảo mật, file của chính MacSentry, Wazuh, agent EDR/MDM/VPN
//   - Phần cứng & mạng: USB, ổ đĩa ngoài, nguồn điện, đổi mạng, ổ đầy; báo cáo hằng ngày; heartbeat ra ngoài
//   - Tin của helper Endpoint Security (macsentry-es) qua $STATE/spool
// Cấu hình: /etc/macsentry.conf (TOKEN, CHAT, HEARTBEAT_URL, ES_EXEC, FIM), chỉ root đọc được.
//
// Thiết kế: thay đổi được báo bởi SỰ KIỆN của hệ thống (FSEvents, IOKit, DiskArbitration, SCDynamicStore, sự kiện
// Endpoint Security của helper); quét định kỳ chỉ còn là dự phòng và cho thứ không có sự kiện. Đọc dữ liệu qua API
// (libproc, utmpx, Security, IOKit...) thay vì fork lệnh rồi đọc chữ.
import Foundation
import SystemConfiguration

// MARK: - Chế độ kiểm tra: in dữ liệu các bộ đọc, không gửi gì (sudo /usr/local/libexec/macsentryd --check)

if CommandLine.arguments.contains("--check") {
    config = loadConfig() ?? Config()
    let procs = processes()
    let socks = tcpSockets(procs)
    let ns = netstat()
    print("Tiến trình: \(procs.count) | socket TCP (libproc): \(socks.count), LISTEN \(socks.filter(\.listen).count), ESTABLISHED \(socks.filter(\.established).count)")
    let rv = remoteView(ns, socks)
    print("netstat: \(ns.count) dòng | kết nối từ xa: \(rv.established.sorted()) | dịch vụ từ xa đang bật: \(rv.listening.sorted())")
    print("Đăng nhập từ xa (utmpx): \(remoteLogins())")
    print("Ứng viên reverse shell: \(tcpSockets(procs, names: isRevShellCandidate).filter { $0.established }.map { "\($0.name)(\($0.pid)) fd\($0.fd) -> \($0.rAddr):\($0.rPort)" })")
    print("USB: \(usbDevices())")
    print("Mạng: \(storeDict("State:/Network/Global/IPv4") ?? [:])")
    print("Proxy: \(dynStore.flatMap { SCDynamicStoreCopyProxies($0) } as? [String: Any] ?? [:])")
    print("LaunchAgent/Daemon: \(glob(launchDirs).count) | file nhạy cảm: \(glob(sensitivePatterns).count)")
    print("Chữ ký /usr/bin/ssh: \(signer("/usr/bin/ssh")) | MacSentry.app: \(signer(glob(["/Users/*/Applications/MacSentry.app"]).first))")
    print("System extension: \(((plist("/Library/SystemExtensions/db.plist")?["extensions"] as? [[String: Any]]) ?? []).compactMap { $0["identifier"] as? String })")
    print("Helper ES sống: \(esAlive()) | Full Disk Access (của tiến trình gọi --check, không phải daemon): \(hasFullDiskAccess())")
    if exists(wz) { checkWazuhProcsOnly(procs); print("Wazuh: tiến trình \(wazuhProcs.sorted()), kết nối \(wazuhConnected)"); print(fimSummary()) }
    exit(0)
}

func checkWazuhProcsOnly(_ procs: [Proc]) {
    wazuhProcs = Set(procs.map(\.name).filter { $0.hasPrefix("wazuh-") })
    wazuhConnected = lines(readText("\(wz)/var/run/wazuh-agentd.state")).contains { $0 == "status='connected'" }
}

// MARK: - Khởi động

guard let c = loadConfig() else { FileHandle.standardError.write(Data("macsentryd: không đọc được \(confPath)\n".utf8)); exit(1) }
config = c
for d in ["conn", "throttle", "spool", "files", "signers"] { try? FileManager.default.createDirectory(atPath: sp(d), withIntermediateDirectories: true) }
try? FileManager.default.createDirectory(atPath: pubDir, withIntermediateDirectories: true)
chmod(pubDir, 0o755)

// Chuyển từ bản shell: trạng thái cũ có định dạng khác → lấy mốc lại (lần quét đầu không báo), giữ các danh sách
// "đã từng thấy", dấu khởi động / dừng, khoá chống spam và giao tiếp với helper ES
let stateVersion = "swift1"
if readText(sp("daemon_v")) != stateVersion {
    let keep: Set<String> = ["lastboot", "clean_stop", "updating", "just_updated", "last_report", "usb_known", "volumes_known",
                             "listen_seen", "throttle", "spool", "es_alive", "es_status", "es_samples", "eslogger.err", "expect_sudo", "conn"]
    for f in (try? FileManager.default.contentsOfDirectory(atPath: stateDir)) ?? [] where !keep.contains(f) {
        try? FileManager.default.removeItem(atPath: sp(f))
    }
    for f in (try? FileManager.default.contentsOfDirectory(atPath: sp("conn"))) ?? [] { try? FileManager.default.removeItem(atPath: sp("conn/\(f)")) }
    for d in ["files", "signers"] { try? FileManager.default.createDirectory(atPath: sp(d), withIntermediateDirectories: true) }
    // Báo cáo hằng ngày đếm sự kiện từ vị trí này trong log (không đếm lại cả lịch sử)
    var st = stat()
    writeText(sp("report_off"), "\(stat(logPath, &st) == 0 ? st.st_size : 0)\n")
    writeText(sp("daemon_v"), stateVersion)
    log("macsentryd (Swift) lấy mốc trạng thái mới")
}

let boot = bootTime()
if readText(sp("lastboot"))?.trimmingCharacters(in: .whitespacesAndNewlines) != String(boot) {
    writeText(sp("lastboot"), "\(boot)\n")
    for f in (try? FileManager.default.contentsOfDirectory(atPath: sp("conn"))) ?? [] { try? FileManager.default.removeItem(atPath: sp("conn/\(f)")) }
    for f in ["remote_conns", "who"] { try? FileManager.default.removeItem(atPath: sp(f)) }
    alert("🟢 Máy vừa khởi động\nBật lúc: \(fmtDate(boot))")
} else if exists(sp("clean_stop")) {
    info("▶️ macsentryd chạy lại (máy bật từ \(fmtDate(boot)))")
} else {
    // Không có dấu dừng bình thường → bị kill -9 / crash rồi launchd chạy lại (SIGKILL không bắt được)
    alert("⚠️ macsentryd vừa bị dừng ĐỘT NGỘT (kill -9 hoặc lỗi) và đã được launchd chạy lại\nMáy bật từ: \(fmtDate(boot))\n(nếu không phải bạn → có thể có người cố tắt giám sát)")
}
try? FileManager.default.removeItem(atPath: sp("clean_stop"))

// launchd gửi SIGTERM khi tắt máy / khởi động lại (hoặc khi có người gỡ daemon bằng sudo)
var signalSources: [DispatchSourceSignal] = []
for sig in [SIGTERM, SIGINT] {
    signal(sig, SIG_IGN)
    let s = DispatchSource.makeSignalSource(signal: sig, queue: q)
    s.setEventHandler {
        writeText(sp("clean_stop"), "")
        stopAuthStream()
        if exists(sp("updating")) { try? FileManager.default.removeItem(atPath: sp("updating")); log("🔄 macsentryd dừng để cập nhật") }
        else { sendNow("🔴 Máy đang tắt / khởi động lại (hoặc macsentryd bị dừng)\nLúc: \(nowStr())") }
        exit(0)
    }
    s.resume()
    signalSources.append(s)
}

// MARK: - Vòng nhịp 2 giây (chỉ cho thứ không có sự kiện, và quét dự phòng)
//   2–4s  kết nối truy cập từ xa (netstat + utmpx)         4–10s  nghi reverse shell (libproc)
//   10s   app MacSentry còn chạy, dịch vụ từ xa, app điều khiển từ xa, LaunchAgent/Daemon (dự phòng FSEvents)
//   30s   cổng mới, file nhạy cảm, Wazuh, agent, ổ đầy     60s  tài khoản, cài cắm, tự bảo vệ, báo cáo, heartbeat,
//         USB / ổ đĩa / nguồn / mạng (dự phòng sự kiện)    5 phút  tư thế bảo mật, toàn vẹn LaunchDaemon

var tick = 0
var esUp = false
var lastRemote = RemoteView()

func heartbeat() {
    // Dead-man switch: dịch vụ ngoài (vd healthchecks.io) báo cho bạn khi KHÔNG nhận được ping nữa
    guard !dryRun, let u = URL(string: config.heartbeat), !config.heartbeat.isEmpty else { return }
    URLSession.shared.dataTask(with: URLRequest(url: u, timeoutInterval: 10)) { _, _, _ in }.resume()
}

func onTick() {
    var procsCache: [Proc]?
    func procs() -> [Proc] { if procsCache == nil { procsCache = processes() }; return procsCache! }

    if tick % 15 == 0 { esUp = esAlive(); manageAuthStream() }
    // Helper ES chạy → nó đã báo tức thì SSH / Screen Sharing / lệnh reverse shell, nên quét dự phòng thưa hơn
    if tick % (esUp ? 2 : 1) == 0 { lastRemote = remoteView(netstat(), tcpSockets(procs())); checkRemote(lastRemote) }
    if tick % 5 == 0 { checkSpool() }
    if tick % (esUp ? 5 : 2) == 0 { checkRevshell(procs()) }
    if tick % 150 == 0 { checkPosture(procs(), tick: tick); checkDaemonIntegrity() }   // trước báo cáo: báo cáo cần số liệu tư thế
    if tick % 5 == 0 {
        checkApp(procs()); checkServices(lastRemote, atStartup: tick == 0); checkRemoteTools(procs()); checkLaunchItems()
    }
    if tick % 15 == 0 { checkWazuh(procs()); checkListen(procs()); checkFiles(); checkAgents(procs()); checkDisk() }
    if tick % 30 == 0 {
        resolveTrusted(); checkAccounts(); checkPersistence(); checkSelf(); dailyReport(boot: boot); cleanupState(); heartbeat()
        checkUSB(); checkVolumes(); checkPower(); checkNetwork()
    }
    tick += 1
}

resolveTrusted()
startEventSources()
let timer = DispatchSource.makeTimerSource(queue: q)
timer.schedule(deadline: .now(), repeating: 2, leeway: .milliseconds(500))
timer.setEventHandler(handler: onTick)
timer.resume()

CFRunLoopRun()   // nguồn sự kiện IOKit gắn vào run loop chính
