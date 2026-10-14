// MacSentry — cảnh báo an ninh cho máy Mac, chạy trên thanh menu (status bar).
// App (chạy bằng user): theo dõi kết nối truy cập từ xa + popup, khoá/mở khoá màn hình, ngủ, app bị tắt.
// Daemon macsentryd (chạy bằng root, xem daemon/): bật/tắt máy, đăng nhập sai, thay đổi hệ thống, phần cứng & mạng.
import AppKit
import SwiftUI
import UserNotifications
import CoreAudio
import CoreMediaIO

// MARK: - Model

/// Cổng của các dịch vụ truy cập từ xa cần theo dõi (khớp với REMOTE_PORTS trong daemon/macsentryd.sh)
let remoteServices: [String: String] = [
    "22": "SSH", "5900": "Screen Sharing/VNC", "3283": "Apple Remote Desktop", "445": "Chia sẻ file SMB", "548": "AFP", "3031": "Remote Apple Events",
]

struct RemoteConnection: Identifiable, Hashable {
    let ip: String
    let remotePort: String
    let service: String
    var user: String?
    var firstSeen: Date
    var id: String { "\(service)|\(ip):\(remotePort)" }
}

struct HistoryEntry: Codable, Identifiable, Hashable {
    var id = UUID()
    let ip: String
    let remotePort: String
    var service: String? // nil = dữ liệu cũ từ SSHWatch (chỉ có SSH)
    var user: String?
    let start: Date
    var end: Date?
}

// MARK: - Store (lưu lịch sử + danh sách IP tin cậy)

final class Store {
    static let dir: URL = {
        let d = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("MacSentry", isDirectory: true)
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }()
    static let historyURL = dir.appendingPathComponent("history.json")
    static let trustedURL = dir.appendingPathComponent("trusted.json")
    static let daemonLogPath = "/var/log/macsentry.log"

    static func load<T: Decodable>(_ url: URL, as: T.Type) -> T? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        let dec = JSONDecoder(); dec.dateDecodingStrategy = .iso8601
        return try? dec.decode(T.self, from: data)
    }
    static func save<T: Encodable>(_ value: T, to url: URL) {
        let enc = JSONEncoder(); enc.dateEncodingStrategy = .iso8601; enc.outputFormatting = .prettyPrinted
        try? enc.encode(value).write(to: url, options: .atomic)
    }
}

// MARK: - Telegram (gửi cảnh báo ra ngoài máy để không bị xoá dấu vết tại chỗ)

enum Telegram {
    struct Config: Codable { let botToken: String; let chatId: String }
    static let configURL = Store.dir.appendingPathComponent("telegram.json")
    static var config: Config? { Store.load(configURL, as: Config.self) }
    static let hostName = Host.current().localizedName ?? ProcessInfo.processInfo.hostName
    /// Đã cài macsentryd (daemon root) thì nó lo tin bật/tắt máy, kết nối mở/đóng, đăng nhập, thức dậy → app không gửi trùng
    static var daemonInstalled: Bool {
        FileManager.default.fileExists(atPath: "/Library/LaunchDaemons/io.github.vuminhhoa.macsentry.daemon.plist")
    }

    /// Gửi tin nhắn, thử lại tới ~5 phút nếu lỗi mạng. `silent` = không kêu chuông trên điện thoại (tin thông tin).
    /// `wait` = chờ gửi xong (dùng khi app sắp thoát / máy sắp ngủ).
    static func send(_ text: String, silent: Bool = false, wait: Bool = false, attempt: Int = 1) {
        guard let cfg = config,
              let url = URL(string: "https://api.telegram.org/bot\(cfg.botToken)/sendMessage") else { return }
        var req = URLRequest(url: url, timeoutInterval: 10)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: [
            "chat_id": cfg.chatId, "text": "🖥 \(hostName)\n\(text)", "disable_notification": silent,
        ])
        let done = DispatchSemaphore(value: 0)
        URLSession.shared.dataTask(with: req) { data, resp, err in
            defer { done.signal() }
            if (resp as? HTTPURLResponse)?.statusCode == 200 { return }
            NSLog("MacSentry Telegram lỗi (lần \(attempt)): \(err?.localizedDescription ?? String(decoding: data ?? Data(), as: UTF8.self))")
            if attempt < 12 && !wait {
                DispatchQueue.global().asyncAfter(deadline: .now() + .seconds(min(attempt * 5, 30))) {
                    send(text, silent: silent, attempt: attempt + 1)
                }
            }
        }.resume()
        if wait { _ = done.wait(timeout: .now() + 5) }
    }
}

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

    func start() {
        // Đóng các phiên còn "mở" từ lần chạy trước (app bị tắt giữa chừng)
        for i in history.indices where history[i].end == nil { history[i].end = Date() }
        saveHistory()
        startHelper()
        poll(initial: true)
        let t = Timer(timeInterval: 2, repeats: true) { [weak self] _ in self?.pollAsync() }
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

    func scan() -> [RemoteConnection] {
        // 1) Kết nối TCP ESTABLISHED tới cổng của các dịch vụ truy cập từ xa (không cần quyền root)
        var result: [String: RemoteConnection] = [:]
        for line in netstatOutput().split(separator: "\n") {
            let cols = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard cols.count >= 6, cols[0].hasPrefix("tcp"), cols[5] == "ESTABLISHED",
                  let (_, lport) = splitAddr(cols[3]), let service = remoteServices[lport],
                  let (rip, rport) = splitAddr(cols[4]) else { continue }
            var ip = rip
            if ip.hasPrefix("::ffff:") { ip = String(ip.dropFirst(7)) }
            let c = RemoteConnection(ip: ip, remotePort: rport, service: service, user: nil, firstSeen: Date())
            result[c.id] = c
        }
        // 2) Ghép tên user đã đăng nhập SSH từ `who` (bỏ các phiên tmux/screen, X11 — không phải SSH)
        var userByHost: [String: String] = [:]
        var whoSessions: [RemoteConnection] = []
        for line in run("/usr/bin/who", []).split(separator: "\n") {
            let s = String(line)
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

    func toggleTrust(_ ip: String) {
        if trusted.contains(ip) { trusted.remove(ip) } else { trusted.insert(ip) }
        Store.save(trusted, to: Store.trustedURL)
        onChange?()
    }
}

// MARK: - Camera / micro đang được dùng

enum AVSensors {
    /// Các app đang thu âm từ micro (API theo từng tiến trình — không nhầm với thiết bị chỉ đang phát âm thanh)
    static let micIgnored: Set<String> = [
        "com.apple.CoreSpeech",               // "Hey Siri" — luôn nghe theo thiết kế
        "com.apple.accessibility.heard",      // Nhận diện âm thanh (Trợ năng)
    ]
    static func micsInUse() -> [String] {
        var addr = AudioObjectPropertyAddress(mSelector: kAudioHardwarePropertyProcessObjectList,
                                              mScope: kAudioObjectPropertyScopeGlobal, mElement: kAudioObjectPropertyElementMain)
        var size: UInt32 = 0
        guard AudioObjectGetPropertyDataSize(AudioObjectID(kAudioObjectSystemObject), &addr, 0, nil, &size) == noErr else { return [] }
        var ids = [AudioObjectID](repeating: 0, count: Int(size) / MemoryLayout<AudioObjectID>.size)
        AudioObjectGetPropertyData(AudioObjectID(kAudioObjectSystemObject), &addr, 0, nil, &size, &ids)
        return ids.compactMap { id in
            guard let input: UInt32 = prop(id, kAudioProcessPropertyIsRunningInput), input != 0 else { return nil }
            let bundle: Unmanaged<CFString>? = prop(id, kAudioProcessPropertyBundleID)
            let bid = (bundle?.takeRetainedValue() as String?) ?? ""
            if micIgnored.contains(bid) { return nil }
            let pid: pid_t = prop(id, kAudioProcessPropertyPID) ?? 0
            return NSRunningApplication(processIdentifier: pid)?.localizedName ?? (bid.isEmpty ? "pid \(pid)" : bid)
        }
    }

    private static func prop<T>(_ id: AudioObjectID, _ sel: AudioObjectPropertySelector) -> T? {
        var addr = AudioObjectPropertyAddress(mSelector: sel, mScope: kAudioObjectPropertyScopeGlobal, mElement: kAudioObjectPropertyElementMain)
        var size = UInt32(MemoryLayout<T>.size)
        let buf = UnsafeMutablePointer<T>.allocate(capacity: 1); defer { buf.deallocate() }
        return AudioObjectGetPropertyData(id, &addr, 0, nil, &size, buf) == noErr ? buf.pointee : nil
    }

    /// Tên các camera đang được app nào đó dùng
    static func camerasInUse() -> [String] {
        func addr(_ sel: Int) -> CMIOObjectPropertyAddress {
            CMIOObjectPropertyAddress(mSelector: CMIOObjectPropertySelector(sel),
                                      mScope: CMIOObjectPropertyScope(kCMIOObjectPropertyScopeGlobal),
                                      mElement: CMIOObjectPropertyElement(kCMIOObjectPropertyElementMain))
        }
        var a = addr(kCMIOHardwarePropertyDevices)
        var size: UInt32 = 0, used: UInt32 = 0
        guard CMIOObjectGetPropertyDataSize(CMIOObjectID(kCMIOObjectSystemObject), &a, 0, nil, &size) == noErr else { return [] }
        var ids = [CMIOObjectID](repeating: 0, count: Int(size) / MemoryLayout<CMIOObjectID>.size)
        CMIOObjectGetPropertyData(CMIOObjectID(kCMIOObjectSystemObject), &a, 0, nil, size, &used, &ids)
        return ids.compactMap { id in
            var ra = addr(kCMIODevicePropertyDeviceIsRunningSomewhere)
            var running: UInt32 = 0
            CMIOObjectGetPropertyData(id, &ra, 0, nil, UInt32(MemoryLayout<UInt32>.size), &used, &running)
            guard running != 0 else { return nil }
            var na = addr(kCMIOObjectPropertyName)
            var name: Unmanaged<CFString>?
            CMIOObjectGetPropertyData(id, &na, 0, nil, UInt32(MemoryLayout<Unmanaged<CFString>?>.size), &used, &name)
            return (name?.takeRetainedValue() as String?) ?? "Camera"
        }
    }
}

// MARK: - Khởi động cùng máy (LaunchAgent) — bắt buộc, không cho tắt

enum LaunchAtLogin {
    static let label = "io.github.vuminhhoa.macsentry"
    static var plistURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/\(label).plist")
    }
    /// Ghi lại plist mỗi lần chạy: tạo lại nếu bị xoá và cập nhật đường dẫn nếu app bị di chuyển
    static func ensure() {
        let exe = Bundle.main.executablePath ?? CommandLine.arguments[0]
        let plist: [String: Any] = [
            "Label": label,
            "ProgramArguments": [exe],
            "RunAtLoad": true,
            "KeepAlive": ["SuccessfulExit": false],
            "ProcessType": "Interactive",
        ]
        try? FileManager.default.createDirectory(at: plistURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        (plist as NSDictionary).write(to: plistURL, atomically: true)
    }

    /// launchd đặt XPC_SERVICE_NAME = label cho tiến trình do nó chạy
    static var runningUnderLaunchd: Bool { ProcessInfo.processInfo.environment["XPC_SERVICE_NAME"] == label }

    /// Giao app cho launchd quản lý (KeepAlive: bị kill sẽ tự chạy lại), rồi thoát tiến trình hiện tại
    static func handOverToLaunchd() -> Never {
        ensure()
        let domain = "gui/\(getuid())"
        for args in [["bootstrap", domain, plistURL.path], ["kickstart", "\(domain)/\(label)"]] {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
            p.arguments = args
            p.standardError = FileHandle.nullDevice
            try? p.run(); p.waitUntilExit()
        }
        exit(0)
    }
}

// MARK: - UI danh sách

let timeFmt: DateFormatter = { let f = DateFormatter(); f.dateFormat = "dd/MM/yyyy HH:mm:ss"; return f }()

func durationString(_ from: Date, _ to: Date) -> String {
    let s = Int(to.timeIntervalSince(from))
    if s < 60 { return "\(s)s" }
    if s < 3600 { return "\(s / 60)m \(s % 60)s" }
    return "\(s / 3600)h \((s % 3600) / 60)m"
}

final class ViewState: ObservableObject {
    @Published var tab = 0
    @Published var filter = ""
    @Published var events: [String] = []

    /// Đọc log sự kiện của daemon (mới nhất lên đầu). Log chỉ được ghi thêm, không xoay vòng → có thể rất lớn,
    /// nên chỉ đọc ~1 MB cuối file.
    func loadEvents() {
        guard let h = FileHandle(forReadingAtPath: Store.daemonLogPath) else { events = []; return }
        defer { try? h.close() }
        let size = (try? h.seekToEnd()) ?? 0
        let start = size > 1_000_000 ? size - 1_000_000 : 0
        try? h.seek(toOffset: start)
        var s = String(decoding: h.readDataToEndOfFile(), as: UTF8.self)
        if start > 0, let nl = s.firstIndex(of: "\n") { s = String(s[s.index(after: nl)...]) }   // bỏ dòng bị cắt dở
        events = s.split(separator: "\n").suffix(2000).reversed().map(String.init)
    }
}

struct ContentView: View {
    @ObservedObject var monitor: Monitor
    @ObservedObject var ui: ViewState
    var filter: String { ui.filter }

    var filteredHistory: [HistoryEntry] {
        filter.isEmpty ? monitor.history : monitor.history.filter {
            $0.ip.contains(filter) || ($0.user ?? "").contains(filter) || ($0.service ?? "SSH").contains(filter)
        }
    }
    var filteredEvents: [String] {
        filter.isEmpty ? ui.events : ui.events.filter { $0.localizedCaseInsensitiveContains(filter) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Picker("", selection: $ui.tab) {
                Text("Đang kết nối (\(monitor.active.count))").tag(0)
                Text("Lịch sử kết nối (\(monitor.history.count))").tag(1)
                Text("Sự kiện").tag(3)
                Text("IP tin cậy (\(monitor.trusted.count))").tag(2)
            }
            .pickerStyle(.segmented)
            .labelsHidden()

            switch ui.tab {
            case 0: activeTable
            case 1: historyTable
            case 3: eventsList
            default: trustedList
            }
        }
        .padding(12)
        .frame(minWidth: 760, minHeight: 420)
    }

    var activeTable: some View {
        Group {
            if monitor.active.isEmpty {
                VStack { Spacer(); Text("Không có kết nối truy cập từ xa nào.").foregroundStyle(.secondary); Spacer() }
                    .frame(maxWidth: .infinity)
            } else {
                Table(monitor.active) {
                    TableColumn("IP") { c in
                        HStack {
                            Image(systemName: monitor.trusted.contains(c.ip) ? "checkmark.shield.fill" : "exclamationmark.triangle.fill")
                                .foregroundStyle(monitor.trusted.contains(c.ip) ? .green : .orange)
                            Text(c.ip).textSelection(.enabled)
                        }
                    }
                    TableColumn("Dịch vụ") { Text($0.service) }.width(130)
                    TableColumn("Cổng / TTY") { Text($0.remotePort) }.width(80)
                    TableColumn("User") { Text($0.user ?? "—").foregroundStyle($0.user == nil ? .secondary : .primary) }
                    TableColumn("Bắt đầu") { Text(timeFmt.string(from: $0.firstSeen)) }
                    TableColumn("Thời lượng") { c in
                        TimelineView(.periodic(from: .now, by: 1)) { ctx in Text(durationString(c.firstSeen, ctx.date)) }
                    }.width(80)
                    TableColumn("") { c in
                        Button(monitor.trusted.contains(c.ip) ? "Bỏ tin cậy" : "Tin cậy") { monitor.toggleTrust(c.ip) }
                    }.width(90)
                }
            }
        }
    }

    var historyTable: some View {
        VStack(alignment: .leading) {
            HStack {
                TextField("Lọc theo IP, user hoặc dịch vụ…", text: $ui.filter).textFieldStyle(.roundedBorder)
                Button("Mở thư mục dữ liệu") { NSWorkspace.shared.open(Store.dir) }
            }
            Table(filteredHistory) {
                TableColumn("IP") { Text($0.ip).textSelection(.enabled) }
                TableColumn("Dịch vụ") { Text($0.service ?? "SSH") }.width(130)
                TableColumn("User") { Text($0.user ?? "—") }
                TableColumn("Bắt đầu") { Text(timeFmt.string(from: $0.start)) }
                TableColumn("Kết thúc") { e in
                    if let end = e.end { Text(timeFmt.string(from: end)) } else { Text("đang kết nối").foregroundStyle(.green) }
                }
                TableColumn("Thời lượng") { e in Text(durationString(e.start, e.end ?? Date())) }.width(80)
            }
        }
    }

    var eventsList: some View {
        VStack(alignment: .leading) {
            HStack {
                TextField("Lọc sự kiện…", text: $ui.filter).textFieldStyle(.roundedBorder)
                Button("Làm mới") { ui.loadEvents() }
            }
            if !Telegram.daemonInstalled {
                Text("Chưa cài macsentryd — chạy: sudo ~/MacSentry/daemon/install.sh")
                    .font(.caption).foregroundStyle(.orange)
            }
            // id theo vị trí: log có thể có các dòng trùng nhau (cùng nội dung, cùng giây) → id: \.self làm SwiftUI nhầm hàng
            List(Array(filteredEvents.enumerated()), id: \.offset) { Text($0.element).font(.system(.body, design: .monospaced)).textSelection(.enabled) }
        }
        .onAppear { ui.loadEvents() }
    }

    var trustedList: some View {
        VStack(alignment: .leading) {
            Text("IP tin cậy vẫn được ghi lịch sử, nhưng không bật popup cảnh báo.")
                .font(.caption).foregroundStyle(.secondary)
            List {
                ForEach(monitor.trusted.sorted(), id: \.self) { ip in
                    HStack { Text(ip); Spacer(); Button("Xoá") { monitor.toggleTrust(ip) } }
                }
            }
        }
    }
}

// MARK: - App delegate / status bar

final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate, NSMenuDelegate {
    let monitor = Monitor()
    var statusItem: NSStatusItem!
    var window: NSWindow?
    var notificationsAllowed = false
    var alertShowing = false
    var poweringOff = false
    var sleptAt: Date?
    var sensorsInUse: Set<String> = []
    var sensorTimer: Timer?
    var watchdogTimer: Timer?
    var daemonMissing: [String: Int] = [:]

    func applicationDidFinishLaunching(_ note: Notification) {
        // Chỉ cho chạy 1 instance. Bản mở bằng Finder/`open` giao cho launchd rồi mới thoát, nên bản launchd
        // có thể thấy nó còn sống trong giây lát → đợi tối đa 5s. Vẫn trùng → thoát mã lỗi để launchd thử lại sau
        // (thoát mã 0 thì launchd coi là "thoát bình thường" và không chạy lại → không còn bản nào chạy).
        if let bid = Bundle.main.bundleIdentifier {
            var tries = 0
            while NSRunningApplication.runningApplications(withBundleIdentifier: bid).count > 1 {
                if tries == 10 { exit(LaunchAtLogin.runningUnderLaunchd ? 1 : 0) } // không qua applicationWillTerminate
                tries += 1
                Thread.sleep(forTimeInterval: 0.5)
            }
        }
        // Mở bằng Finder/`open` → chuyển cho launchd chạy, để bị kill thì launchd tự mở lại
        if !LaunchAtLogin.runningUnderLaunchd { LaunchAtLogin.handOverToLaunchd() }
        LaunchAtLogin.ensure()

        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        let menu = NSMenu()
        menu.delegate = self
        statusItem.menu = menu

        let center = UNUserNotificationCenter.current()
        center.delegate = self
        center.requestAuthorization(options: [.alert, .sound, .badge]) { ok, _ in
            DispatchQueue.main.async { self.notificationsAllowed = ok }
        }

        monitor.onChange = { [weak self] in self?.refreshStatusItem() }
        monitor.onNewConnection = { [weak self] c, atStartup in self?.alert(c, atStartup: atStartup) }
        monitor.onUserLogin = { [weak self] c in
            if Telegram.daemonInstalled { return }
            let mark = self?.monitor.trusted.contains(c.ip) == true ? "✅" : "⚠️"
            Telegram.send("\(mark) Đã đăng nhập SSH\nIP: \(c.ip):\(c.remotePort)\nUser: \(c.user ?? "?")")
        }
        monitor.onSessionEnd = { e in
            if Telegram.daemonInstalled { return }
            Telegram.send("🔌 Kết thúc phiên \(e.service ?? "SSH")\nIP: \(e.ip)" + (e.user.map { "\nUser: \($0)" } ?? "")
                          + "\nThời lượng: \(durationString(e.start, e.end ?? Date()))", silent: true)
        }
        notifyStartup()
        observeSystemEvents()
        monitor.start()
    }

    func observeSystemEvents() {
        let ws = NSWorkspace.shared.notificationCenter
        // Tắt máy / khởi động lại / đăng xuất: macOS báo trước khi đóng các app
        ws.addObserver(forName: NSWorkspace.willPowerOffNotification, object: nil, queue: .main) { [weak self] _ in
            guard let self, !self.poweringOff else { return }
            self.poweringOff = true
            if !Telegram.daemonInstalled { Telegram.send("🔴 Máy đang tắt / khởi động lại / đăng xuất\nLúc: \(timeFmt.string(from: Date()))", wait: true) }
            if self.alertShowing { NSApp.abortModal() } // popup đang mở thì đóng, để không chặn việc tắt máy
        }
        // Ngủ / thức dậy. Lúc ngủ chờ gửi xong (mạng sắp bị ngắt); lúc thức mạng chưa sẵn sàng thì Telegram.send tự thử lại
        ws.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { [weak self] _ in
            self?.sleptAt = Date()
            Telegram.send("😴 Máy đi ngủ\nLúc: \(timeFmt.string(from: Date()))", silent: true, wait: true)
        }
        ws.addObserver(forName: NSWorkspace.didWakeNotification, object: nil, queue: .main) { [weak self] _ in
            let slept = self?.sleptAt.map { "\nĐã ngủ: \(durationString($0, Date()))" } ?? ""
            self?.sleptAt = nil
            if Telegram.daemonInstalled { return }
            Telegram.send("☀️ Máy thức dậy\nLúc: \(timeFmt.string(from: Date()))\(slept)")
        }
        // Khoá / mở khoá màn hình (tin im lặng: xảy ra nhiều lần mỗi ngày)
        let dn = DistributedNotificationCenter.default()
        dn.addObserver(forName: .init("com.apple.screenIsLocked"), object: nil, queue: .main) { _ in
            Telegram.send("🔒 Màn hình đã khoá\nLúc: \(timeFmt.string(from: Date()))", silent: true)
        }
        dn.addObserver(forName: .init("com.apple.screenIsUnlocked"), object: nil, queue: .main) { _ in
            // Mở khoá lúc 0h–6h sáng là bất thường → có chuông
            let night = Calendar.current.component(.hour, from: Date()) < 6
            Telegram.send("\(night ? "🌙 Máy được mở khoá lúc NỬA ĐÊM" : "🔓 Màn hình được mở khoá") (\(NSUserName()))\nLúc: \(timeFmt.string(from: Date()))",
                          silent: !night)
        }
        // Camera / micro bật-tắt (kiểm tra mỗi 3 giây)
        sensorsInUse = Set(AVSensors.camerasInUse().map { "📷 Camera: \($0)" } + AVSensors.micsInUse().map { "🎙 Micro đang được dùng bởi: \($0)" })
        let t = Timer(timeInterval: 3, repeats: true) { [weak self] _ in self?.checkSensors() }
        RunLoop.main.add(t, forMode: .common)
        sensorTimer = t

        // Giám sát chéo: app (user) canh daemon root và helper Endpoint Security — bị tắt mà không kịp tự báo
        // (kill -9, launchctl bootout) thì app báo thay. Mỗi 20 giây, vắng 3 lần liên tiếp (~1 phút) mới báo.
        let w = Timer(timeInterval: 20, repeats: true) { [weak self] _ in self?.checkDaemons() }
        RunLoop.main.add(w, forMode: .common)
        watchdogTimer = w
    }

    /// (tên hiển thị, file plist — có cài mới canh, đoạn nhận diện trong dòng lệnh của `ps`)
    static let watched = [
        ("macsentryd (daemon chính)", "/Library/LaunchDaemons/io.github.vuminhhoa.macsentry.daemon.plist", "/usr/local/libexec/macsentryd"),
        ("macsentry-es (Endpoint Security)", "/Library/LaunchDaemons/io.github.vuminhhoa.macsentry.es.plist", "/usr/local/libexec/macsentry-es"),
    ]

    func checkDaemons() {
        DispatchQueue.global().async {
            let p = Process(); p.executableURL = URL(fileURLWithPath: "/bin/ps"); p.arguments = ["-axo", "command="]
            let out = Pipe(); p.standardOutput = out
            guard (try? p.run()) != nil else { return }
            let ps = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            p.waitUntilExit()
            DispatchQueue.main.async {
                for (name, plist, marker) in Self.watched where FileManager.default.fileExists(atPath: plist) {
                    if ps.contains(marker) {
                        if (self.daemonMissing[name] ?? 0) >= 3 {
                            Telegram.send("✅ \(name) đã chạy lại\nLúc: \(timeFmt.string(from: Date()))", silent: true)
                        }
                        self.daemonMissing[name] = 0
                    } else {
                        let n = (self.daemonMissing[name] ?? 0) + 1
                        self.daemonMissing[name] = n
                        if n == 3 {
                            Telegram.send("⚠️ \(name) KHÔNG chạy (~1 phút)\nCó thể đã bị tắt bằng launchctl bootout / kill.\n"
                                          + "Kiểm tra: sudo launchctl print system/\((plist as NSString).lastPathComponent.replacingOccurrences(of: ".plist", with: ""))\n"
                                          + "Lúc: \(timeFmt.string(from: Date()))")
                        }
                    }
                }
            }
        }
    }

    func checkSensors() {
        let now = Set(AVSensors.camerasInUse().map { "📷 Camera: \($0)" } + AVSensors.micsInUse().map { "🎙 Micro đang được dùng bởi: \($0)" })
        let front = NSWorkspace.shared.frontmostApplication?.localizedName ?? "?"
        for s in now.subtracting(sensorsInUse).sorted() {
            // Micro đã biết chính xác app; camera thì chỉ đoán theo app đang mở phía trước
            let who = s.hasPrefix("🎙") ? "" : "\nApp đang mở phía trước: \(front)"
            Telegram.send("\(s) — ĐANG BẬT\(who)\nLúc: \(timeFmt.string(from: Date()))")
        }
        for s in sensorsInUse.subtracting(now).sorted() {
            Telegram.send("\(s) — đã tắt\nLúc: \(timeFmt.string(from: Date()))", silent: true)
        }
        sensorsInUse = now
    }

    /// Thời điểm máy khởi động (kern.boottime)
    static func bootTime() -> Date? {
        var tv = timeval(), size = MemoryLayout<timeval>.size
        var mib: [Int32] = [CTL_KERN, KERN_BOOTTIME]
        guard sysctl(&mib, 2, &tv, &size, nil, 0) == 0 else { return nil }
        return Date(timeIntervalSince1970: TimeInterval(tv.tv_sec))
    }

    /// Lần chạy đầu tiên sau khi bật máy → báo "máy vừa khởi động"/"đã đăng nhập", còn lại → báo app khởi động lại
    func notifyStartup() {
        guard let boot = Self.bootTime() else { Telegram.send("▶️ MacSentry đã khởi động"); return }
        let last = UserDefaults.standard.double(forKey: "lastBootTime")
        UserDefaults.standard.set(boot.timeIntervalSince1970, forKey: "lastBootTime")
        let newBoot = abs(last - boot.timeIntervalSince1970) > 1
        if newBoot && Telegram.daemonInstalled {
            Telegram.send("👤 \(NSUserName()) đã đăng nhập máy\nLúc: \(timeFmt.string(from: Date()))", silent: true)
        } else if newBoot {
            Telegram.send("🟢 Máy vừa khởi động\nBật lúc: \(timeFmt.string(from: boot))\nĐăng nhập: \(NSUserName()) lúc \(timeFmt.string(from: Date()))")
        } else {
            Telegram.send("▶️ MacSentry đã khởi động lại (máy bật từ \(timeFmt.string(from: boot)))", silent: true)
        }
    }

    func refreshStatusItem() {
        let count = monitor.active.count
        let untrusted = monitor.active.contains { !monitor.trusted.contains($0.ip) }
        if let button = statusItem.button {
            let symbol = count == 0 ? "lock.shield" : (untrusted ? "exclamationmark.shield.fill" : "checkmark.shield.fill")
            let img = NSImage(systemSymbolName: symbol, accessibilityDescription: "MacSentry")
            if count > 0 && untrusted {
                let cfg = NSImage.SymbolConfiguration(paletteColors: [.white, .systemRed])
                button.image = img?.withSymbolConfiguration(cfg)
                button.image?.isTemplate = false
            } else {
                button.image = img
                button.image?.isTemplate = true
            }
            button.title = count > 0 ? " \(count)" : ""
            button.imagePosition = .imageLeading
            button.toolTip = count == 0 ? "MacSentry: không có truy cập từ xa" : "MacSentry: \(count) kết nối truy cập từ xa"
        }
    }

    // Dựng lại menu mỗi lần mở để thời lượng luôn mới
    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        if monitor.active.isEmpty {
            menu.addItem(NSMenuItem(title: "Không có truy cập từ xa", action: nil, keyEquivalent: ""))
        } else {
            menu.addItem(NSMenuItem(title: "Đang truy cập từ xa:", action: nil, keyEquivalent: ""))
            for c in monitor.active {
                let mark = monitor.trusted.contains(c.ip) ? "✅" : "⚠️"
                let user = c.user.map { " — \($0)" } ?? ""
                let item = NSMenuItem(title: "\(mark) [\(c.service)] \(c.ip):\(c.remotePort)\(user)  (\(durationString(c.firstSeen, Date())))",
                                      action: #selector(copyIP(_:)), keyEquivalent: "")
                item.representedObject = c.ip
                item.target = self
                item.toolTip = "Bấm để copy IP"
                menu.addItem(item)
            }
        }
        menu.addItem(.separator())
        menu.addItem(item("Mở MacSentry…", #selector(openWindow), "l"))
        menu.addItem(item(Telegram.config == nil ? "Telegram: chưa cấu hình…" : "Gửi thử Telegram", #selector(testTelegram), ""))
        let daemon = NSMenuItem(title: Telegram.daemonInstalled ? "Daemon macsentryd: đã cài" : "Daemon macsentryd: CHƯA cài",
                                action: nil, keyEquivalent: "")
        menu.addItem(daemon)
        menu.addItem(item("Cài đặt Chia sẻ (Remote Login)…", #selector(openSharing), ""))
    }

    func item(_ title: String, _ sel: Selector, _ key: String) -> NSMenuItem {
        let i = NSMenuItem(title: title, action: sel, keyEquivalent: key)
        i.target = self
        return i
    }

    // MARK: Cảnh báo

    func alert(_ c: RemoteConnection, atStartup: Bool = false) {
        // Kết nối từ chính máy này coi như tin cậy (không popup)
        let local = c.ip.hasPrefix("127.") || c.ip == "::1" || c.ip == "localhost"
        let trusted = monitor.trusted.contains(c.ip) || local
        let title = trusted ? "Kết nối \(c.service) (IP tin cậy)" : "⚠️ Có kết nối \(c.service) mới!"
        let body = "Dịch vụ: \(c.service)\nIP: \(c.ip):\(c.remotePort)" + (c.user.map { "\nUser: \($0)" } ?? "")
        // Gửi Telegram trước tiên, trước cả popup (runModal sẽ chặn luồng chính)
        if !Telegram.daemonInstalled {
            Telegram.send("\(trusted ? "✅ Kết nối \(c.service) (IP tin cậy)" : "🚨 Kết nối \(c.service) từ IP LẠ")\n\(body)\nLúc: \(timeFmt.string(from: c.firstSeen))",
                          silent: trusted)
        }

        if notificationsAllowed {
            let content = UNMutableNotificationContent()
            content.title = title
            content.body = body
            content.sound = trusted ? nil : .default
            UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: c.id, content: content, trigger: nil))
        } else {
            // Dự phòng khi chưa cấp quyền thông báo
            let script = "display notification \"\(body.replacingOccurrences(of: "\n", with: " "))\" with title \"\(title)\" sound name \"Sosumi\""
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            p.arguments = ["-e", script]
            try? p.run()
        }

        if !trusted && !alertShowing && !atStartup {
            alertShowing = true
            defer { alertShowing = false }
            NSSound(named: "Sosumi")?.play()
            NSApp.activate(ignoringOtherApps: true)
            let a = NSAlert()
            a.alertStyle = .critical
            a.messageText = "Có kết nối \(c.service) từ IP lạ"
            a.informativeText = body + "\nThời điểm: \(timeFmt.string(from: c.firstSeen))"
            a.addButton(withTitle: "OK")
            a.addButton(withTitle: "Tin cậy IP này")
            a.addButton(withTitle: "Xem danh sách")
            switch a.runModal() {
            case .alertSecondButtonReturn: monitor.toggleTrust(c.ip)
            case .alertThirdButtonReturn: openWindow()
            default: break
            }
        }
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent n: UNNotification,
                                withCompletionHandler h: @escaping (UNNotificationPresentationOptions) -> Void) {
        h([.banner, .sound, .list])
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive r: UNNotificationResponse,
                                withCompletionHandler h: @escaping () -> Void) {
        DispatchQueue.main.async { self.openWindow() }
        h()
    }

    // MARK: Actions

    @objc func copyIP(_ sender: NSMenuItem) {
        guard let ip = sender.representedObject as? String else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(ip, forType: .string)
    }

    @objc func openWindow() {
        if window == nil {
            let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 880, height: 500),
                             styleMask: [.titled, .closable, .resizable, .miniaturizable],
                             backing: .buffered, defer: false)
            w.title = "MacSentry"
            w.contentView = NSHostingView(rootView: ContentView(monitor: monitor, ui: ViewState()))
            w.isReleasedWhenClosed = false
            w.center()
            window = w
        }
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }

    @objc func openSharing() {
        NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.Sharing-Settings.extension")!)
    }

    /// Không cho thoát app, trừ khi đang tắt máy / khởi động lại / đăng xuất (để không chặn việc tắt máy)
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if poweringOff { return .terminateNow }
        let reason = NSAppleEventManager.shared().currentAppleEvent?
            .attributeDescriptor(forKeyword: AEKeyword(kAEQuitReason))?.enumCodeValue
        let systemReasons: [OSType] = [OSType(kAELogOut), OSType(kAEReallyLogOut), OSType(kAEShowRestartDialog),
                                       OSType(kAEShowShutdownDialog), OSType(kAERestart), OSType(kAEShutDown)]
        if let reason, systemReasons.contains(reason) { poweringOff = true; return .terminateNow }
        Telegram.send("⛔️ Có lệnh thoát MacSentry — đã chặn\nLúc: \(timeFmt.string(from: Date()))", silent: true)
        return .terminateCancel
    }

    func applicationWillTerminate(_ note: Notification) {
        if !poweringOff { Telegram.send("⏹ MacSentry (app) đã bị tắt", wait: true) }
        Monitor.stopHelper()
    }

    @objc func testTelegram() {
        if Telegram.config == nil {
            NSWorkspace.shared.open(Store.dir)
            let a = NSAlert()
            a.messageText = "Chưa cấu hình Telegram"
            a.informativeText = "Tạo file telegram.json trong thư mục vừa mở với nội dung:\n{\"botToken\": \"...\", \"chatId\": \"...\"}"
            NSApp.activate(ignoringOtherApps: true)
            a.runModal()
        } else {
            Telegram.send("🔔 Tin nhắn thử từ MacSentry")
        }
    }
}

// `MacSentry --scan`: in danh sách kết nối hiện tại rồi thoát (để debug)
if CommandLine.arguments.contains("--scan") {
    for c in Monitor().scan() { print(c.service, c.ip, c.remotePort, c.user ?? "-") }
    exit(0)
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory) // chỉ hiện trên thanh menu, không có icon Dock
app.run()
