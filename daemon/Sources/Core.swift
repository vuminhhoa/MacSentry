import CryptoKit
import Foundation
import SystemConfiguration

// MARK: - Cấu hình, đường dẫn, hàng đợi

let env = ProcessInfo.processInfo.environment
let confPath = env["CONF"] ?? "/etc/macsentry.conf"
let logPath = env["LOG"] ?? "/var/log/macsentry.log"      // cờ sappnd: chỉ được ghi thêm
let stateDir = env["STATE"] ?? "/var/db/macsentry"
let pubDir = env["PUB_DIR"] ?? "/var/run/macsentry"       // trạng thái chia sẻ cho app (ai cũng đọc, chỉ root ghi)
let trustedPath = env["TRUSTED"] ?? "/etc/macsentry.trusted"
let dryRun = env["DRYRUN"] != nil                          // chạy thử: không gửi Telegram

struct Config {
    var token = "", chat = "", heartbeat = ""
    /// Giám sát toàn vẹn file nhạy cảm: "auto" = file Wazuh syscheck đã theo dõi (khi Wazuh đang chạy, kết nối
    /// manager) để Wazuh lo; "local" = MacSentry tự theo dõi mọi file (báo kèm nội dung đổi qua Telegram)
    var fim = "auto"
}
func loadConfig() -> Config? {
    guard let text = try? String(contentsOfFile: confPath, encoding: .utf8) else { return nil }
    var c = Config()
    for line in text.split(separator: "\n") {
        let l = line.trimmingCharacters(in: .whitespaces)
        guard !l.hasPrefix("#"), let eq = l.firstIndex(of: "=") else { continue }
        var v = String(l[l.index(after: eq)...])
        if v.count >= 2, let f = v.first, f == v.last, f == "\"" || f == "'" { v = String(v.dropFirst().dropLast()) }
        switch l[..<eq] {
        case "TOKEN": c.token = v
        case "CHAT": c.chat = v
        case "HEARTBEAT_URL": c.heartbeat = v
        case "FIM": c.fim = v
        default: break
        }
    }
    return c
}
var config = Config()

/// Mọi kiểm tra và trạng thái chạy tuần tự trên hàng đợi này (không cần khoá). Nguồn sự kiện (FSEvents, IOKit,
/// SCDynamicStore...) chỉ đẩy việc vào đây.
let q = DispatchQueue(label: "macsentryd", qos: .utility)
/// Lệnh chậm (sfltool 3–5 giây, whois...) chạy ở đây để không chặn hàng đợi chính
let slowQ = DispatchQueue(label: "macsentryd.slow", qos: .background)

let hostName = (SCDynamicStoreCopyComputerName(nil, nil) as String?) ?? ProcessInfo.processInfo.hostName

// MARK: - Log và Telegram

let timeFmt: DateFormatter = { let f = DateFormatter(); f.dateFormat = "dd/MM/yyyy HH:mm:ss"; return f }()
func nowStr() -> String { timeFmt.string(from: Date()) }

func log(_ s: String) {
    let line = "\(nowStr()) \(s.replacingOccurrences(of: "\n", with: " "))\n"
    let fd = open(logPath, O_WRONLY | O_APPEND | O_CREAT, 0o644)
    guard fd >= 0 else { return }
    _ = line.withCString { write(fd, $0, strlen($0)) }
    close(fd)
}

/// Telegram giới hạn 4096 ký tự (UTF-16) → cắt bớt, ghi chú xem đủ trong log
func tgText(_ t: String) -> String {
    let s = "🛡 \(hostName)\n\(t)"
    guard s.utf16.count > 3900 else { return s }
    var n = 0, end = s.startIndex
    for i in s.indices { n += s[i].utf16.count; if n > 3800 { break }; end = s.index(after: i) }
    return String(s[..<end]) + "\n…(đã cắt bớt, xem đủ trong \(logPath))"
}

/// Gửi Telegram (token chỉ nằm trong bộ nhớ, không bao giờ trên dòng lệnh). Chỉ thử lại khi lỗi tạm thời
/// (mạng, 429, 5xx) — tới ~5 phút, lúc mới bật/thức máy có thể chưa có mạng.
func post(_ text: String, silent: Bool, attempt: Int = 1, maxAttempts: Int = 30, done: (() -> Void)? = nil) {
    if dryRun || config.token.isEmpty { done?(); return }
    guard let url = URL(string: "https://api.telegram.org/bot\(config.token)/sendMessage") else { done?(); return }
    var req = URLRequest(url: url, timeoutInterval: 10)
    req.httpMethod = "POST"
    req.setValue("application/json", forHTTPHeaderField: "Content-Type")
    req.httpBody = try? JSONSerialization.data(withJSONObject: ["chat_id": config.chat, "text": tgText(text), "disable_notification": silent])
    URLSession.shared.dataTask(with: req) { _, resp, _ in
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        if code == 200 { done?(); return }
        let temporary = code == 0 || code == 429 || code >= 500
        if temporary && attempt < maxAttempts {
            q.asyncAfter(deadline: .now() + 10) { post(text, silent: silent, attempt: attempt + 1, maxAttempts: maxAttempts, done: done) }
        } else {
            q.async { log("Gửi Telegram thất bại (HTTP \(code)\(temporary ? ", hết lượt thử lại" : ""))") }
            done?()
        }
    }.resume()
}
func alert(_ t: String) { log(t); post(t, silent: false) }   // có chuông
func info(_ t: String) { log(t); post(t, silent: true) }     // im lặng
/// Gửi ngay và chờ tối đa 5 giây (dùng khi sắp tắt máy)
func sendNow(_ t: String) {
    log(t)
    let sem = DispatchSemaphore(value: 0)
    post(t, silent: false, maxAttempts: 1) { sem.signal() }
    _ = sem.wait(timeout: .now() + 5)
}

// MARK: - Trạng thái lưu trên đĩa

func sp(_ name: String) -> String { "\(stateDir)/\(name)" }
func readText(_ p: String) -> String? { try? String(contentsOfFile: p, encoding: .utf8) }
func writeText(_ p: String, _ s: String) { try? s.write(toFile: p, atomically: true, encoding: .utf8) }
func exists(_ p: String) -> Bool { FileManager.default.fileExists(atPath: p) }
func lines(_ s: String?) -> [String] { (s ?? "").split(separator: "\n").map(String.init) }

/// So sánh danh sách mới với danh sách đã lưu ở `name`. Lần đầu chỉ lưu làm mốc (không báo).
/// `nonempty`: danh sách không bao giờ rỗng thật (user, app...) → rỗng nghĩa là đọc lỗi, bỏ qua lần này.
func diffState(_ name: String, _ list: [String], nonempty: Bool = false) -> (added: [String], removed: [String]) {
    let new = Set(list.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty })
    if nonempty && new.isEmpty { return ([], []) }
    let p = sp(name)
    let text = new.sorted().map { $0 + "\n" }.joined()
    guard let oldText = readText(p) else { writeText(p, text); return ([], []) }
    let old = Set(lines(oldText))
    if old == new { return ([], []) }
    writeText(p, text)
    return (new.subtracting(old).sorted(), old.subtracting(new).sorted())
}

/// Chống spam: true nếu khoá chưa dùng trong `seconds` giây gần đây (lưu trên đĩa, giữ qua lần khởi động lại)
var throttleMem: [String: TimeInterval] = [:]
func throttle(_ key: String, _ seconds: TimeInterval) -> Bool {
    let safe = String(String(key.map { $0.isLetter && $0.isASCII || $0.isNumber && $0.isASCII || "._-".contains($0) ? $0 : "_" }).prefix(150))
    let f = sp("throttle/\(safe)")
    let now = Date().timeIntervalSince1970
    let last = throttleMem[safe] ?? readText(f).flatMap { TimeInterval($0.trimmingCharacters(in: .whitespacesAndNewlines)) } ?? 0
    guard now - last >= seconds else { return false }
    throttleMem[safe] = now
    writeText(f, "\(Int(now))\n")
    return true
}
/// Dọn khoá chống spam cũ (khoá dài nhất 7 ngày) — mỗi ngày một lần
func cleanupState() {
    guard throttle("cleanup_state", 86400) else { return }
    let dir = sp("throttle"), limit = Date().addingTimeInterval(-8 * 86400)
    for f in (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? [] {
        let p = "\(dir)/\(f)"
        if let m = (try? FileManager.default.attributesOfItem(atPath: p))?[.modificationDate] as? Date, m < limit {
            try? FileManager.default.removeItem(atPath: p)
        }
    }
    throttleMem = throttleMem.filter { Date().timeIntervalSince1970 - $0.value < 8 * 86400 }
}

/// Chữ ký nhận diện thay đổi của danh sách file: ctime (mọi lần ghi / đổi metadata đều cập nhật, không đặt lại
/// được bằng touch như mtime), kích thước, tên. Trả về true nếu khác lần gọi trước cùng khoá → mới cần băm lại.
func statChanged(_ name: String, _ paths: [String]) -> Bool {
    let sig = paths.map { p -> String in
        var st = stat()
        guard lstat(p, &st) == 0 else { return "- \(p)" }
        return "\(st.st_ctimespec.tv_sec) \(st.st_size) \(p)"
    }.joined(separator: "\n")
    let f = sp("statsig_\(name)")
    if readText(f) == sig { return false }
    writeText(f, sig)
    return true
}

func sha16(_ path: String) -> String? {
    guard let d = FileManager.default.contents(atPath: path) else { return nil }
    return SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined().prefix(16).description
}

enum Change: String { case changed, new, removed }
/// Theo dõi nội dung file qua mã băm (lần đầu chỉ lưu mốc)
func hashChanges(_ name: String, _ paths: [String]) -> [(Change, String)] {
    let sums = paths.compactMap { p in sha16(p).map { "\($0) \(p)" } }
    let d = diffState(name, sums)
    func path(_ l: String) -> String { String(l.dropFirst(17)) }
    let added = Set(d.added.map(path)), removed = Set(d.removed.map(path))
    return added.union(removed).sorted().map { p in
        (added.contains(p) && removed.contains(p) ? .changed : added.contains(p) ? .new : .removed, p)
    }
}

/// Phần mới ghi thêm vào file kể từ lần gọi trước (tối đa 200 KB).
/// File chưa có → mốc 0, nên khi file xuất hiện (vd active-responses.log ở lần ĐẦU) sẽ đọc từ đầu.
/// Chưa có mốc mà file đã có: lần chạy đầu → chỉ ghi mốc; `newOK` (file mới xuất hiện sau lần quét đầu) → đọc từ đầu.
func tailNew(_ name: String, _ path: String, newOK: Bool = false) -> String {
    let f = sp("tail_\(name)")
    var st = stat()
    guard stat(path, &st) == 0 else { if !exists(f) { writeText(f, "0\n") }; return "" }
    let size = UInt64(st.st_size)
    let prev = readText(f).flatMap { UInt64($0.trimmingCharacters(in: .whitespacesAndNewlines)) }
    writeText(f, "\(size)\n")
    var off: UInt64
    if let prev { off = prev } else { guard newOK else { return "" }; off = 0 }
    if size < off { off = 0 }   // file bị xoay vòng / làm mới
    guard size > off, let h = FileHandle(forReadingAtPath: path) else { return "" }
    defer { try? h.close() }
    try? h.seek(toOffset: off)
    let data = (try? h.read(upToCount: 200_000)) ?? Data()
    return String(decoding: data, as: UTF8.self)
}

/// Bản sao file để so nội dung lần sau
func copyOf(_ p: String) -> String { sp("files/" + p.replacingOccurrences(of: "/", with: "_")) }

/// Che giá trị bí mật trước khi gửi nội dung file ra Telegram (vd "export API_TOKEN=abc" → "export API_TOKEN=***")
let secretRe = try! NSRegularExpression(pattern: #"((KEY|TOKEN|SECRET|PASS|PASSWORD|PWD|AUTH|CREDENTIAL)[A-Za-z0-9_]*\s*[=:]\s*).*"#,
                                        options: [.caseInsensitive])
func maskSecrets(_ s: String) -> String {
    secretRe.stringByReplacingMatches(in: s, range: NSRange(s.startIndex..., in: s), withTemplate: "$1***")
}

/// Khác biệt giữa 2 nội dung: "< dòng cũ" / "> dòng mới", tối đa `limit` dòng, mỗi dòng ≤ 200 ký tự, đã che bí mật
func lineDiff(_ old: String, _ new: String, limit: Int) -> String {
    let d = lines(new).difference(from: lines(old))
    var out: [String] = []
    for c in d {
        switch c {
        case .remove(_, let l, _): out.append("< " + l)
        case .insert(_, let l, _): out.append("> " + l)
        }
        if out.count >= limit { break }
    }
    return out.map { maskSecrets(String($0.prefix(200))) }.joined(separator: "\n")
}
func headLines(_ p: String, _ n: Int) -> String {
    lines(readText(p)).prefix(n).map { maskSecrets(String($0.prefix(200))) }.joined(separator: "\n")
}

// MARK: - Tiện ích hệ thống

/// Mở rộng mẫu đường dẫn (glob), đường dẫn được có dấu cách
func glob(_ patterns: [String]) -> [String] {
    var out: [String] = []
    for p in patterns {
        var g = glob_t()
        defer { globfree(&g) }
        guard Darwin.glob(p, 0, nil, &g) == 0 else { continue }
        for i in 0..<Int(g.gl_pathc) { if let c = g.gl_pathv[i] { out.append(String(cString: c)) } }
    }
    return Array(Set(out)).sorted()
}

/// Chạy lệnh, trả stdout. Chỉ dùng cho việc không có API (chạy thưa, ngoài vòng nhịp nhanh).
@discardableResult
func run(_ path: String, _ args: [String] = [], timeout: TimeInterval = 30) -> String {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = args
    let out = Pipe()
    p.standardOutput = out
    p.standardError = FileHandle.nullDevice
    p.standardInput = FileHandle.nullDevice
    do { try p.run() } catch { return "" }
    let killer = DispatchWorkItem { if p.isRunning { p.terminate() } }
    DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: killer)
    let data = out.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    killer.cancel()
    return String(decoding: data, as: UTF8.self)
}

func plist(_ p: String) -> [String: Any]? {
    guard let d = FileManager.default.contents(atPath: p) else { return nil }
    return (try? PropertyListSerialization.propertyList(from: d, format: nil)) as? [String: Any]
}
/// Nội dung plist dạng chữ (XML) để so khác biệt; file không phải plist → nội dung gốc
func plistText(_ p: String) -> String {
    if let d = FileManager.default.contents(atPath: p),
       let o = try? PropertyListSerialization.propertyList(from: d, format: nil),
       let x = try? PropertyListSerialization.data(fromPropertyList: o, format: .xml, options: 0) {
        return String(decoding: x, as: UTF8.self)
    }
    return readText(p) ?? ""
}

func dur(_ s: Int) -> String {
    s < 60 ? "\(s)s" : s < 3600 ? "\(s / 60)m \(s % 60)s" : "\(s / 3600)h \(s % 3600 / 60)m"
}

func bootTime() -> Int {
    var tv = timeval(), size = MemoryLayout<timeval>.size
    var mib: [Int32] = [CTL_KERN, KERN_BOOTTIME]
    return sysctl(&mib, 2, &tv, &size, nil, 0) == 0 ? tv.tv_sec : 0
}
func fmtDate(_ t: Int, _ f: String = "dd/MM/yyyy HH:mm:ss") -> String {
    let d = DateFormatter(); d.dateFormat = f
    return d.string(from: Date(timeIntervalSince1970: TimeInterval(t)))
}

/// User đang đăng nhập màn hình (chủ của /dev/console), "root" khi ở màn hình đăng nhập
func consoleUser() -> String {
    var st = stat()
    guard stat("/dev/console", &st) == 0 else { return "root" }
    return userName(Int(st.st_uid))
}

/// Thư mục home của các user thật (UID >= 500)
func userHomes() -> [String] {
    glob(["/Users/*"]).filter { h in
        var st = stat()
        return stat(h, &st) == 0 && st.st_uid >= 500 && (st.st_mode & S_IFMT) == S_IFDIR
    }
}
