import Foundation

// MARK: - Truy cập từ xa: kết nối SSH/VNC/ARD/SMB/AFP, đăng nhập SSH, dịch vụ bật/tắt, reverse shell, cổng mới,
// app điều khiển từ xa và tunnel

var pubLast = ""
func checkRemote(_ v: RemoteView) {
    let cur = v.established
    let d = diffState("remote_conns", Array(cur))
    let now = Int(Date().timeIntervalSince1970)
    for l in d.added + d.removed {
        let f = l.split(separator: " ").map(String.init)
        guard f.count == 2, let p = Int(f[0]), let dot = f[1].lastIndex(of: ".") else { continue }
        var ip = String(f[1][..<dot]); if ip.hasPrefix("::ffff:") { ip.removeFirst(7) }
        let rport = f[1][f[1].index(after: dot)...]
        let key = sp("conn/\(p)_\(f[1])")
        if d.added.contains(l) {
            writeText(key, "\(now)\n")
            let msg = "🚨 Kết nối \(portName(p))\nIP: \(ip):\(rport)\nLúc: \(nowStr())"
            if isLoopback(ip) || ip == "localhost" { info(msg + "\n(từ chính máy này)") }
            else if throttle("conn_\(p)_\(ip)", 300) { log(msg); alertWithIP(msg, ip) }
            else { log("\(msg) (lặp lại trong 5 phút, không gửi)") }
        } else {
            let start = readText(key).flatMap { Int($0.trimmingCharacters(in: .whitespacesAndNewlines)) } ?? now
            try? FileManager.default.removeItem(atPath: key)
            info("🔌 Kết thúc \(portName(p))\nIP: \(ip):\(rport)\nThời lượng: \(dur(now - start))")
        }
    }

    // Đăng nhập SSH thành công
    let logins = remoteLogins()
    for l in diffState("who", logins).added {
        let f = l.split(separator: " ", maxSplits: 2).map(String.init)
        guard f.count == 3 else { continue }
        alert("🔑 Đăng nhập SSH thành công\nUser: \(f[0])\nTừ: \(f[2].trimmingCharacters(in: CharacterSet(charactersIn: "()"))) (\(f[1]))")
    }

    // Chia sẻ cho app (chạy bằng user) → app không phải tự chạy netstat/who. Chỉ ghi khi đổi.
    // Mỗi dòng: "conn <cổng> <địa chỉ.cổng xa>" hoặc "who <user> <tty> (<host>)"
    let pub = cur.sorted().map { "conn \($0)\n" }.joined() + logins.map { "who \($0)\n" }.joined()
    if pub != pubLast {
        writeText("\(pubDir)/remote", pub)
        chmod("\(pubDir)/remote", 0o644)
        pubLast = pub
    }
}

/// Dịch vụ truy cập từ xa bật/tắt (đang lắng nghe trên cổng của nó)
func checkServices(_ v: RemoteView, atStartup: Bool) {
    let listening = Set(v.listening.map(String.init))
    let d = diffState("services", Array(listening))
    for p in d.removed.compactMap(Int.init) { info("📡 Đã tắt \(portName(p)) (cổng \(p))") }
    for p in d.added.compactMap(Int.init) {
        alert(atStartup ? "📡 \(portName(p)) (cổng \(p)) đang BẬT — máy nhận kết nối từ xa\n(phát hiện lúc macsentryd khởi động)"
                        : "📡 Vừa BẬT \(portName(p)) (cổng \(p)) — máy nhận kết nối từ xa")
    }
}

// MARK: - Reverse shell (dự phòng cho helper ES): shell / netcat... giữ kết nối TCP ra ngoài

let shellNames: Set<String> = ["bash", "sh", "zsh", "dash", "ksh", "tcsh", "csh", "fish", "nc", "ncat", "netcat", "socat",
                               "telnet", "perl", "ruby", "php", "osascript", "tclsh", "expect", "lua"]
/// python / node hợp lệ thường giữ kết nối ra ngoài (IDE, dev server...) → chỉ tính khi fd 0–2 LÀ socket
/// (dup2 socket vào stdin/stdout/stderr — dấu hiệu đặc trưng của reverse shell)
func isScriptRuntime(_ n: String) -> Bool { n == "node" || n.lowercased().hasPrefix("python") }
func isRevShellCandidate(_ n: String) -> Bool { shellNames.contains(n) || n.hasPrefix("perl5") || isScriptRuntime(n) }

func checkRevshell(_ procs: [Proc]) {
    let socks = tcpSockets(procs, names: isRevShellCandidate).filter {
        $0.established && !isLoopback($0.rAddr) && (!isScriptRuntime($0.name) || $0.fd <= 2)
    }
    var byKey: [String: Sock] = [:]
    for s in socks { byKey["\(s.name) \(s.pid) \(s.rAddr):\(s.rPort)"] = s }
    for k in diffState("revshell", Array(byKey.keys)).added {
        guard let s = byKey[k] else { continue }
        let detail = procDetail(s.pid)   // ghi NGAY: tiến trình có thể kết thúc sau vài giây
        if let tn = trustedName(s.rAddr, s.rPort) {
            log("☑️ \(s.name) (pid \(s.pid)) -> \(s.rAddr):\(s.rPort) — máy chủ tin cậy \(tn), không cảnh báo. \(detail)")
            continue
        }
        alertWithIP("☠️ Nghi REVERSE SHELL: \(s.name) (pid \(s.pid)) -> \(s.rAddr):\(s.rPort)", s.rAddr, tail: """

            \(detail)
            — Nếu đích là máy chủ quen (git, công ty...) và tiến trình cha là IDE/công cụ của bạn → báo giả, thêm vào /etc/macsentry.trusted.
            — Nếu không nhận ra: ngắt mạng và kiểm tra ngay.
            """)
    }
}

/// Cổng mới mở ra mạng. Chỉ báo lần đầu thấy mỗi cặp (chương trình, cổng). Cổng tạm (>= 49152, hệ điều hành
/// cấp ngẫu nhiên) tính chung: mỗi chương trình báo 1 lần.
func checkListen(_ procs: [Proc]) {
    let socks = tcpSockets(procs).filter { $0.listen && !isLoopback($0.lAddr) }
    let seenPath = sp("listen_seen")
    var seen = Set(lines(readText(seenPath)))
    let first = !exists(seenPath)
    var newSeen: [String] = []
    for s in Dictionary(socks.map { ("\($0.name)|\($0.lPort)", $0) }, uniquingKeysWith: { a, _ in a }).values.sorted(by: { $0.lPort < $1.lPort }) {
        let note: String
        if s.lPort >= 49152 {
            if seen.contains("\(s.name)|tạm") || seen.contains(where: { $0.hasPrefix("\(s.name)|") && (Int($0.split(separator: "|").last ?? "") ?? 0) >= 49152 }) { continue }
            seen.insert("\(s.name)|tạm"); newSeen.append("\(s.name)|tạm")
            note = "Cổng: \(s.lPort) (cổng tạm — lần sau chương trình này đổi cổng tạm sẽ không báo nữa)"
        } else {
            let k = "\(s.name)|\(s.lPort)"
            if seen.contains(k) { continue }
            seen.insert(k); newSeen.append(k)
            note = "Cổng: \(s.lPort)"
        }
        if !first { info("🆕 Cổng mới mở ra mạng\nChương trình: \(s.name)\n\(note)\n\(procDetail(s.pid))") }
    }
    if first || !newSeen.isEmpty { writeText(seenPath, seen.sorted().map { $0 + "\n" }.joined()) }
}

// MARK: - App điều khiển từ xa (TeamViewer, AnyDesk...) và tunnel (ngrok, cloudflared...)
// Chúng kết nối RA máy chủ trung gian nên không lộ qua cổng lắng nghe như SSH/VNC → theo dõi tiến trình + log phiên.

let remoteToolRe = try! NSRegularExpression(pattern: #"^(TeamViewer.*|AnyDesk.*|RustDesk.*|rustdesk.*|remoting_me2me_host|ScreenConnect.*|ConnectWise.*|Splashtop.*|SRStreamer|SRService|LogMeIn.*|Parsec.*|UltraViewer.*|ZohoAssist.*|Zoho Assist.*|AeroAdmin.*|Supremo.*|DWAgent.*|nxserver.*|nxnode.*|NoMachine.*|ngrok|cloudflared|frpc|chisel|bore|tmate|Jump Desktop Connect.*)$"#)
let tunnels: Set<String> = ["ngrok", "cloudflared", "frpc", "chisel", "bore", "tmate"]
let sessionRe = try! NSRegularExpression(pattern: #"incoming session|accepting from|connection incoming|incoming connection|new connection from|session started|authenticated|remote control (started|session)|login from"#, options: [.caseInsensitive])

func checkRemoteTools(_ procs: [Proc]) {
    var found: [String: Proc] = [:]
    for p in procs where remoteToolRe.firstMatch(in: p.name, range: NSRange(p.name.startIndex..., in: p.name)) != nil {
        if found[p.name] == nil { found[p.name] = p }
    }
    let d = diffState("remote_tools", found.values.map { "\($0.name)|\($0.path ?? $0.name)" })
    for l in d.added {
        let n = String(l.split(separator: "|").first ?? "")
        guard let p = found[n] else { continue }
        let what = n.hasPrefix("TeamViewer_Desktop") ? "TeamViewer_Desktop thường chỉ chạy khi CÓ NGƯỜI ĐANG ĐIỀU KHIỂN máy qua TeamViewer"
                 : tunnels.contains(n) ? "Công cụ mở đường hầm từ Internet vào máy" : "App điều khiển máy từ xa vừa chạy"
        alert("🖥 \(what): \(n)\n\(procDetail(p.pid))")
    }
    for l in d.removed { info("🖥 Đã thoát: \(l.split(separator: "|").first ?? "")") }

    // Log phiên kết nối đến (định dạng log không công khai → bắt theo từ khoá phổ biến, kèm nguyên dòng log)
    let logs = glob(["/Library/Logs/TeamViewer/*.log", "/Users/*/Library/Logs/TeamViewer/*.log", "/Users/*/.anydesk/*.trace",
                     "/Library/Application Support/AnyDesk/*.trace", "/var/log/anydesk*.trace",
                     "/Users/*/Library/Logs/RustDesk/server/*.log", "/Users/*/Library/Logs/RustDesk/*.log"])
    // Lần quét đầu: chỉ ghi mốc cuối các log đang có; về sau file log MỚI (app vừa cài) được đọc từ đầu
    let newOK = exists(sp("rt_logs_init"))
    if !newOK { writeText(sp("rt_logs_init"), "") }
    guard statChanged("rt_logs", logs) else { return }   // không file log nào đổi → không có phiên mới
    for f in logs {
        let key = String(f.map { $0.isLetter && $0.isASCII || $0.isNumber || "._-".contains($0) ? $0 : "_" }.suffix(120))
        let hits = lines(tailNew("rt_\(key)", f, newOK: newOK))
            .filter { sessionRe.firstMatch(in: $0, range: NSRange($0.startIndex..., in: $0)) != nil }
            .suffix(5).map { String($0.prefix(250)) }
        if !hits.isEmpty, throttle("rtlog_\(key)", 60) {
            alert("🚨 Có PHIÊN KẾT NỐI ĐẾN qua app điều khiển từ xa\nLog: \(f)\n\(hits.joined(separator: "\n"))")
        }
    }
}
