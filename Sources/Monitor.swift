import Foundation

// MARK: - Monitor (kết nối truy cập từ xa)

final class Monitor: ObservableObject {
    @Published var active: [RemoteConnection] = []
    @Published var history: [HistoryEntry] = Store.load(Store.historyURL, as: [HistoryEntry].self) ?? []
    @Published var trusted: Set<String> = Store.load(Store.trustedURL, as: Set<String>.self) ?? []

    var onChange: (() -> Void)?
    var onNewConnection: ((RemoteConnection, _ atStartup: Bool) -> Void)?
    var onUserLogin: ((RemoteConnection) -> Void)?
    var onSessionEnd: ((HistoryEntry) -> Void)?

    private var timer: Timer?
    private var openHistory: [String: UUID] = [:] // connection id -> history entry id

    /// AppDelegate.checkDaemons cập nhật mỗi 20 giây: macsentryd đang chạy → dùng kết quả quét của nó
    static var daemonRunning = Telegram.daemonInstalled && FileManager.default.fileExists(atPath: Store.daemonRemotePath)
    var helperStarted = false

    func start() {
        // Đóng các phiên còn "mở" từ lần chạy trước (app bị tắt giữa chừng)
        for i in history.indices where history[i].end == nil { history[i].end = Date() }
        saveHistory()
        if !Self.daemonRunning { startHelper() } else { Self.stopHelper() }   // dọn job netstat cũ nếu còn
        poll(initial: true)
        let t = Timer(timeInterval: 2, repeats: true) { [weak self] _ in self?.pollAsync() }
        t.tolerance = 0.5   // cho macOS gộp lần thức dậy với các timer khác (tiết kiệm CPU/pin)
        RunLoop.main.add(t, forMode: .common) // vẫn chạy khi đang mở menu / popup
        timer = t
    }

    private func run(_ path: String, _ args: [String]) -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { NSLog("MacSentry run error: \(error)"); return "" }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }

    /// Tách "addr.port" (định dạng netstat của macOS) thành (addr, port)
    private func splitAddr(_ s: String) -> (String, String)? {
        guard let dot = s.lastIndex(of: ".") else { return nil }
        return (String(s[..<dot]), String(s[s.index(after: dot)...]))
    }

    // macOS ẩn socket của tiến trình khác với netstat chạy từ binary không phải của hệ thống
    // (kể cả tiến trình con). Job do launchd chạy thì không bị ẩn, nên giao việc netstat cho một
    // job nền ghi ra file, app chỉ đọc file đó.
    static let helperLabel = "io.github.vuminhhoa.macsentry.netstat"
    static let snapshotURL = Store.dir.appendingPathComponent("netstat.txt")

    func startHelper() {
        helperStarted = true
        let script = "while :; do /usr/sbin/netstat -an -p tcp > \"$0.tmp\" && mv \"$0.tmp\" \"$0\"; sleep 2; done"
        _ = run("/bin/launchctl", ["remove", Self.helperLabel])
        _ = run("/bin/launchctl", ["submit", "-l", Self.helperLabel, "--", "/bin/sh", "-c", script, Self.snapshotURL.path])
    }

    static func stopHelper() {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        p.arguments = ["remove", helperLabel]
        try? p.run(); p.waitUntilExit()
    }

    /// Ảnh chụp netstat từ job nền nếu còn mới, nếu không thì gọi netstat trực tiếp
    private func netstatOutput() -> String {
        let url = Self.snapshotURL
        if let mtime = (try? FileManager.default.attributesOfItem(atPath: url.path))?[.modificationDate] as? Date,
           Date().timeIntervalSince(mtime) < 6,
           let s = try? String(contentsOf: url, encoding: .utf8) {
            return s
        }
        return run("/usr/sbin/netstat", ["-an", "-p", "tcp"])
    }

    /// Nguồn dữ liệu: file macsentryd chia sẻ (không tốn gì) nếu daemon đang chạy, nếu không thì tự chạy netstat + who.
    /// Trả về (dòng netstat dạng "<cổng cục bộ> <addr.port xa>", các dòng `who`)
    private func sources() -> (conns: [(String, String)], who: [String]) {
        if Self.daemonRunning, let pub = try? String(contentsOfFile: Store.daemonRemotePath, encoding: .utf8) {
            var conns: [(String, String)] = [], who: [String] = []
            for line in pub.split(separator: "\n") {
                let f = line.split(separator: " ", maxSplits: 1).map(String.init)
                guard f.count == 2 else { continue }
                if f[0] == "conn" {
                    let c = f[1].split(separator: " ").map(String.init)
                    if c.count == 2 { conns.append((c[0], c[1])) }
                } else if f[0] == "who" { who.append(f[1]) }
            }
            return (conns, who)
        }
        if !helperStarted { DispatchQueue.main.async { if !self.helperStarted { self.startHelper() } } }   // daemon dừng → tự quét
        var conns: [(String, String)] = []
        for line in netstatOutput().split(separator: "\n") {
            let cols = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard cols.count >= 6, cols[0].hasPrefix("tcp"), cols[5] == "ESTABLISHED",
                  let (_, lport) = splitAddr(cols[3]) else { continue }
            conns.append((lport, cols[4]))
        }
        return (conns, run("/usr/bin/who", []).split(separator: "\n").map(String.init))
    }

    func scan() -> [RemoteConnection] {
        let src = sources()
        // 1) Kết nối TCP ESTABLISHED tới cổng của các dịch vụ truy cập từ xa
        var result: [String: RemoteConnection] = [:]
        for (lport, remote) in src.conns {
            guard let service = remoteServices[lport], let (rip, rport) = splitAddr(remote) else { continue }
            var ip = rip
            if ip.hasPrefix("::ffff:") { ip = String(ip.dropFirst(7)) }
            let c = RemoteConnection(ip: ip, remotePort: rport, service: service, user: nil, firstSeen: Date())
            result[c.id] = c
        }
        // 2) Ghép tên user đã đăng nhập SSH từ `who` (bỏ các phiên tmux/screen, X11 — không phải SSH)
        var userByHost: [String: String] = [:]
        var whoSessions: [RemoteConnection] = []
        for s in src.who {
            guard let o = s.firstIndex(of: "("), let c = s.lastIndex(of: ")"), o < c else { continue }
            let host = String(s[s.index(after: o)..<c])
            if host.isEmpty || host.hasPrefix(":") || host.contains("tmux") || host.contains("(") { continue }
            let cols = s.split(separator: " ").map(String.init)
            let user = cols.first ?? ""
            let tty = cols.count > 1 ? cols[1] : "?"
            userByHost[host] = userByHost[host].map { $0.contains(user) ? $0 : "\($0), \(user)" } ?? user
            whoSessions.append(RemoteConnection(ip: host, remotePort: tty, service: "SSH", user: user, firstSeen: Date()))
        }
        for (k, c) in result where c.service == "SSH" { result[k]?.user = userByHost[c.ip] }
        // 3) Dự phòng: nếu netstat không thấy socket, vẫn lấy phiên SSH đã đăng nhập từ `who`
        let sshIps = Set(result.values.filter { $0.service == "SSH" }.map(\.ip))
        for s in whoSessions where !sshIps.contains(s.ip) { result[s.id] = s }
        return Array(result.values)
    }

    /// Quét ở luồng nền (chạy `who`, đọc file netstat — không chặn giao diện), cập nhật trạng thái ở luồng chính.
    /// Bỏ lượt nếu lượt trước chưa xong (máy bận) để các lượt quét không chồng lên nhau.
    private var scanning = false
    func pollAsync() {
        guard !scanning else { return }
        scanning = true
        DispatchQueue.global(qos: .utility).async {
            let found = self.scan()
            DispatchQueue.main.async { self.apply(found, initial: false); self.scanning = false }
        }
    }

    func poll(initial: Bool) { apply(scan(), initial: initial) }

    private func apply(_ found: [RemoteConnection], initial: Bool) {
        let oldById = Dictionary(uniqueKeysWithValues: active.map { ($0.id, $0) })
        var newActive: [RemoteConnection] = []
        var changed = false

        for var c in found {
            if let old = oldById[c.id] {
                c.firstSeen = old.firstSeen
                if old.user != c.user, let hid = openHistory[c.id], let i = history.firstIndex(where: { $0.id == hid }) {
                    history[i].user = c.user; changed = true
                    if c.user != nil { let conn = c; DispatchQueue.main.async { self.onUserLogin?(conn) } }
                }
            } else {
                let e = HistoryEntry(ip: c.ip, remotePort: c.remotePort, service: c.service, user: c.user, start: c.firstSeen)
                history.insert(e, at: 0)
                openHistory[c.id] = e.id
                changed = true
                let newConn = c
                DispatchQueue.main.async { self.onNewConnection?(newConn, initial) } // báo sau khi đã lưu
            }
            newActive.append(c)
        }
        let foundIds = Set(found.map(\.id))
        for (cid, hid) in openHistory where !foundIds.contains(cid) {
            if let i = history.firstIndex(where: { $0.id == hid }) {
                history[i].end = Date()
                let e = history[i]
                DispatchQueue.main.async { self.onSessionEnd?(e) }
            }
            openHistory[cid] = nil
            changed = true
        }
        if history.count > 2000 { history.removeLast(history.count - 2000) }
        if changed { saveHistory() }
        newActive.sort { $0.firstSeen < $1.firstSeen }
        if newActive != active { active = newActive; changed = true }
        if changed || initial { onChange?() }
    }

    func saveHistory() { Store.save(history, to: Store.historyURL) }

    /// IP tin cậy hoặc kết nối từ chính máy này (giống cách alert() xử lý)
    func isTrusted(_ ip: String) -> Bool { trusted.contains(ip) || ip.hasPrefix("127.") || ip == "::1" || ip == "localhost" }

    func toggleTrust(_ ip: String) { setTrust([ip], !trusted.contains(ip)) }

    func setTrust(_ ips: [String], _ on: Bool) {
        var t = trusted
        for ip in ips { if on { t.insert(ip) } else { t.remove(ip) } }
        guard t != trusted else { return }
        trusted = t
        Store.save(trusted, to: Store.trustedURL)
        onChange?()
    }
}
