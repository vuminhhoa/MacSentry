// macsentry-es — đọc sự kiện Endpoint Security qua /usr/bin/eslogger (chạy bằng root, LaunchDaemon riêng)
// và đẩy cảnh báo vào hàng đợi của macsentryd (/var/db/macsentry/spool). Không giữ token Telegram.
//
// Cần quyền Full Disk Access cho chính file này (/usr/local/libexec/macsentry-es): eslogger là tiến trình con
// nên macOS tính quyền theo tiến trình chịu trách nhiệm là helper này.
//
// Sự kiện theo dõi:
//   authentication          xác thực thất bại + CHÍNH XÁC tiến trình nào yêu cầu (thay cho đoán qua log)
//   screensharing_attach/…  có người xem / điều khiển màn hình qua Screen Sharing / ARD
//   tcc_modify              cấp quyền Accessibility, Ghi màn hình, Theo dõi bàn phím, Full Disk Access, camera, micro…
//   xp_malware_*            XProtect phát hiện / xử lý mã độc
//   gatekeeper_user_override  cho phép chạy app bị Gatekeeper chặn
//   od_modify_password      đổi mật khẩu tài khoản
//   kextload                nạp kernel extension
//   exec                    lệnh nguy hiểm: reverse shell, dump keychain, tắt bảo vệ, tắt giám sát, cài cửa hậu…

import Foundation

let stateDir = ProcessInfo.processInfo.environment["STATE"] ?? "/var/db/macsentry"
let spoolDir = stateDir + "/spool"
let samplesDir = stateDir + "/es_samples"
let events = ["authentication", "screensharing_attach", "screensharing_detach", "tcc_modify",
              "xp_malware_detected", "xp_malware_remediated", "gatekeeper_user_override",
              "od_modify_password", "kextload", "exec"]

// MARK: - Gửi qua macsentryd

enum Level: String { case alert, info, log }

let tokenRegex = try! NSRegularExpression(pattern: #"bot[0-9]{6,}:[A-Za-z0-9_-]{20,}"#)
/// Che token bot Telegram và giá trị bí mật dạng KEY=... trong mọi nội dung gửi đi / ghi log
func redact(_ s: String) -> String {
    var out = tokenRegex.stringByReplacingMatches(in: s, range: NSRange(s.startIndex..., in: s), withTemplate: "bot<đã che>")
    out = secretRegex.stringByReplacingMatches(in: out, range: NSRange(out.startIndex..., in: out), withTemplate: "$1***")
    return out
}
let secretRegex = try! NSRegularExpression(
    pattern: #"((?:KEY|TOKEN|SECRET|PASS|PASSWORD|PWD|AUTH)[A-Za-z0-9_]*\s*[=:]\s*)[^\s'"]+"#, options: [.caseInsensitive])

func spool(_ level: Level, _ rawText: String) {
    let text = redact(rawText)
    let name = "\(Int(Date().timeIntervalSince1970 * 1000))-\(UInt32.random(in: 0...UInt32.max))"
    let tmp = "\(spoolDir)/\(name).tmp"
    guard FileManager.default.createFile(atPath: tmp, contents: Data("\(level.rawValue)\n\(text)".utf8),
                                         attributes: [.posixPermissions: 0o600]) else { return }
    rename(tmp, "\(spoolDir)/\(name).msg")   // đổi tên nguyên tử: daemon không bao giờ đọc file viết dở
}

var throttled: [String: Date] = [:]
func throttle(_ key: String, _ seconds: TimeInterval) -> Bool {
    if let t = throttled[key], Date().timeIntervalSince(t) < seconds { return false }
    throttled[key] = Date(); return true
}

func touch(_ path: String) {
    FileManager.default.createFile(atPath: path, contents: nil)
}

func writeStatus(_ s: String) {
    try? s.write(toFile: stateDir + "/es_status", atomically: true, encoding: .utf8)
}

// MARK: - Đọc JSON của eslogger (định dạng có thể đổi giữa các bản macOS → đọc mềm dẻo, thiếu trường thì bỏ qua)

typealias JSON = [String: Any]

func dict(_ v: Any?, _ keys: String...) -> JSON? {
    var cur = v
    for k in keys { cur = (cur as? JSON)?[k] }
    return cur as? JSON
}
func str(_ v: Any?, _ keys: String...) -> String? {
    var cur = v
    for k in keys { cur = (cur as? JSON)?[k] }
    if let s = cur as? String { return s }
    if let n = cur as? NSNumber { return n.stringValue }
    return nil
}
func int(_ v: Any?, _ keys: String...) -> Int? {
    var cur = v
    for k in keys { cur = (cur as? JSON)?[k] }
    return (cur as? NSNumber)?.intValue
}
/// Tìm chuỗi đầu tiên có khoá `key` ở bất kỳ độ sâu nào
func deepStr(_ v: Any?, _ key: String) -> String? {
    if let d = v as? JSON {
        if let s = d[key] as? String { return s }
        for (_, x) in d { if let s = deepStr(x, key) { return s } }
    } else if let a = v as? [Any] {
        for x in a { if let s = deepStr(x, key) { return s } }
    }
    return nil
}

func pid(_ p: JSON?) -> Int? { int(p, "audit_token", "pid") }
func path(_ p: JSON?) -> String { str(p, "executable", "path") ?? "?" }
func base(_ s: String) -> String { (s as NSString).lastPathComponent }

// Thông tin tiến trình qua libproc / sysctl — không fork `ps` (helper tra chuỗi cha rất thường xuyên)

/// Tên ngắn và pid cha của tiến trình (nil nếu đã thoát)
func procInfo(_ pid: Int) -> (name: String, ppid: Int)? {
    var info = proc_bsdinfo()
    let size = Int32(MemoryLayout<proc_bsdinfo>.size)
    guard proc_pidinfo(Int32(pid), PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
    // pbi_name (32 ký tự) đầy đủ hơn pbi_comm (16 ký tự)
    var name = withUnsafeBytes(of: info.pbi_name) { String(cString: $0.bindMemory(to: CChar.self).baseAddress!) }
    if name.isEmpty { name = withUnsafeBytes(of: info.pbi_comm) { String(cString: $0.bindMemory(to: CChar.self).baseAddress!) } }
    return (name, Int(info.pbi_ppid))
}

/// Dòng lệnh đầy đủ (argv) của tiến trình, đọc từ KERN_PROCARGS2: [argc][đường dẫn exec]\0…\0[argv0]\0[argv1]\0…
func procArgs(_ pid: Int) -> String {
    var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, Int32(pid)]
    var size = 0
    guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 4 else { return "" }
    var buf = [UInt8](repeating: 0, count: size)
    guard sysctl(&mib, 3, &buf, &size, nil, 0) == 0 else { return "" }
    let argc = buf.withUnsafeBytes { $0.load(as: Int32.self) }
    var i = 4
    while i < size && buf[i] != 0 { i += 1 }   // bỏ đường dẫn exec
    while i < size && buf[i] == 0 { i += 1 }   // và phần đệm
    var args: [String] = []
    while args.count < argc && i < size {
        var j = i
        while j < size && buf[j] != 0 { j += 1 }
        args.append(String(decoding: buf[i..<j], as: UTF8.self))
        i = j + 1
    }
    return args.joined(separator: " ")
}

func userName(_ uid: Int) -> String {
    guard let pw = getpwuid(uid_t(uid)) else { return "\(uid)" }
    return String(cString: pw.pointee.pw_name)
}

/// Chuỗi tiến trình cha (tên(pid) ← …), tối đa 6 cấp, kèm dòng lệnh đầy đủ của từng cấp (để nhận diện
/// tiến trình con của macsentryd: tên tiến trình chỉ là "sh", phải nhìn dòng lệnh mới thấy "macsentryd")
func ancestry(_ start: Int?) -> (text: String, commands: [String]) {
    guard var p = start else { return ("?", []) }
    var parts: [String] = [], cmds: [String] = []
    for _ in 0..<6 {
        guard let info = procInfo(p) else { break }
        parts.append("\(info.name)(\(p))")
        cmds.append(procArgs(p))
        if info.ppid <= 1 { break }
        p = info.ppid
    }
    return (parts.isEmpty ? "?" : parts.joined(separator: " ← "), cmds)
}
func chain(_ start: Int?) -> String { ancestry(start).text }

/// Mô tả một tiến trình trong sự kiện: đường dẫn, pid, chữ ký (signing id / team id), chuỗi cha
func describe(_ p: JSON?) -> String {
    guard let p else { return "?" }
    let team = str(p, "team_id") ?? ""
    let signer = (p["is_platform_binary"] as? Bool) == true ? "Apple" : (team.isEmpty ? "không có Team ID" : "Team \(team)")
    // Tiến trình thường đã thoát khi helper kịp tra (vd dscl) → lần chuỗi từ ppid ghi sẵn trong sự kiện
    var c = chain(pid(p))
    if c == "?", let pp = int(p, "ppid") ?? int(p, "original_ppid"), pp > 1 { c = "\(base(path(p)))(đã thoát) ← \(chain(pp))" }
    return "\(path(p)) (pid \(pid(p).map(String.init) ?? "?"), \(signer))\nChuỗi tiến trình: \(c)"
}

// MARK: - Xử lý từng loại sự kiện

/// Dịch vụ nền của Apple tự kiểm tra mật khẩu đã lưu sau khi đăng nhập (không phải người gõ)
let systemAuthCallers: Set<String> = ["akd", "appleaccountd", "cdpd", "filevaultd"]

func onAuthentication(_ e: JSON, _ msg: JSON) {
    guard (e["success"] as? Bool) == false else { return }
    let data = dict(e, "data")
    if let od = dict(data, "od") {
        let who = dict(od, "instigator") ?? dict(msg, "process")
        let user = str(od, "record_name") ?? "?"
        let caller = base(path(who))
        if systemAuthCallers.contains(caller) {
            spool(.log, "Dịch vụ hệ thống \(caller) kiểm tra mật khẩu của \(user) thất bại (không phải người nhập)")
            return
        }
        let source: String
        switch caller {
        case "loginwindow": source = "màn hình khoá / đăng nhập"
        case "authorizationhost", "SecurityAgent", "SecurityPrivacyExtension": source = "hộp thoại xác thực (quyền admin / Cài đặt)"
        case "sshd", "sshd-session": source = "SSH"
        case "sudo", "su", "login": source = "terminal (\(caller))"
        default: source = "tiến trình lạ"
        }
        guard throttle("auth_\(user)_\(caller)", 30) else { return }
        spool(.alert, "🔐 Nhập sai mật khẩu\nUser: \(user)\nNguồn: \(source)\nTiến trình: \(describe(who))")
    } else if let t = dict(data, "touchid") {
        spool(.log, "Touch ID không khớp (\(base(path(dict(t, "instigator") ?? dict(msg, "process")))))")
    } else {
        let kind = data?.keys.first ?? "?"
        spool(.info, "🔐 Xác thực thất bại (loại: \(kind))\nTiến trình: \(describe(dict(msg, "process")))")
    }
}

var ssFails: [String: Int] = [:]
func onScreenSharing(_ e: JSON, attach: Bool) {
    let ip = str(e, "source_address") ?? "?"
    if attach {
        let ok = (e["success"] as? Bool) ?? true
        // Thử sai liên tục (dò mật khẩu) → mỗi IP 1 cảnh báo / 5 phút, kèm số lần thử trong khoảng đó
        if !ok {
            ssFails[ip, default: 0] += 1
            guard throttle("ssfail_\(ip)", 300) else {
                spool(.log, "Screen Sharing đăng nhập sai từ \(ip) (lần \(ssFails[ip]!))"); return
            }
            let n = ssFails[ip]!; ssFails[ip] = 0
            spool(.alert, """
                🖥 Thử kết nối Screen Sharing THẤT BẠI\(n > 1 ? " (\(n) lần từ cảnh báo trước — có thể đang DÒ MẬT KHẨU)" : "")
                Từ: \(ip)
                Xác thực: \(str(e, "authentication_type") ?? "?") \(str(e, "authentication_username") ?? "")
                (các lần sai tiếp theo từ IP này trong 5 phút được gom lại)
                """)
            return
        }
        spool(.alert, """
            \(ok ? "🖥 Có người đang XEM / ĐIỀU KHIỂN màn hình (Screen Sharing)" : "🖥 Thử kết nối Screen Sharing THẤT BẠI")
            Từ: \(ip)\(str(e, "viewer_appleid").map { "\nApple ID người xem: \($0)" } ?? "")
            Xác thực: \(str(e, "authentication_type") ?? "?") \(str(e, "authentication_username") ?? "")
            Phiên của user: \(str(e, "session_username") ?? "?")
            """)
    } else {
        spool(.info, "🖥 Kết thúc phiên Screen Sharing (\(ip))")
    }
}

let sensitiveTCC: [String: String] = [
    "kTCCServiceAccessibility": "Trợ năng (điều khiển máy, đọc nội dung cửa sổ)",
    "kTCCServiceScreenCapture": "Ghi màn hình",
    "kTCCServiceListenEvent": "Theo dõi bàn phím (Input Monitoring — keylogger)",
    "kTCCServicePostEvent": "Giả lập bàn phím / chuột",
    "kTCCServiceSystemPolicyAllFiles": "Truy cập toàn bộ ổ đĩa (Full Disk Access)",
    "kTCCServiceSystemPolicySysAdminFiles": "Quản trị file hệ thống",
    "kTCCServiceCamera": "Camera",
    "kTCCServiceMicrophone": "Micro",
    "kTCCServiceAppleEvents": "Điều khiển app khác (Automation)",
    "kTCCServiceDeveloperTool": "Công cụ dev (chạy phần mềm bỏ qua Gatekeeper)",
    "kTCCServiceEndpointSecurityClient": "Endpoint Security",
    "kTCCServiceRemoteDesktop": "Điều khiển từ xa",
]

func onTCC(_ e: JSON, _ msg: JSON) {
    let service = str(e, "service") ?? "?"
    let identity = str(e, "identity") ?? "?"
    let right = int(e, "right") ?? -1          // 0 từ chối, 2 cho phép, 3 giới hạn, 4 thêm, 5 theo phiên…
    let update = int(e, "update_type") ?? -1   // 1 tạo, 2 sửa, 3 xoá
    let granted = [2, 3, 4, 5].contains(right) && update != 3
    guard let label = sensitiveTCC[service], granted else {
        spool(.log, "TCC: \(service) → \(identity) (right \(right), update \(update))")
        return
    }
    let who = dict(e, "instigator") ?? dict(msg, "process")
    spool(.alert, """
        🔓 Vừa CẤP QUYỀN \(label)
        Cho: \(identity)
        Người/tiến trình cấp: \(describe(who))
        (nếu bạn không vừa bấm cho phép → thu hồi ngay trong Cài đặt → Quyền riêng tư & Bảo mật)
        """)
}

func onExec(_ e: JSON, _ msg: JSON) {
    guard let target = dict(e, "target") else { return }
    let args = (e["args"] as? [String]) ?? []
    let exe = path(target)
    let cmd = args.isEmpty ? exe : args.joined(separator: " ")
    guard let rule = suspicious(exe: exe, cmd: cmd) else { return }
    // Bỏ qua lệnh do chính MacSentry chạy (nhìn dòng lệnh đầy đủ của tiến trình cha), và lệnh động tới
    // MacSentry lúc đang cập nhật (install.sh)
    let anc = ancestry(int(target, "ppid"))
    let parents = anc.text
    if anc.commands.contains(where: { $0.contains("/usr/local/libexec/macsentry") }) { return }
    if rule.selfRelated && FileManager.default.fileExists(atPath: stateDir + "/updating") { return }
    if allowed("\(cmd) || \(parents)") {
        // Lệnh được cho phép thường lặp liên tục (vd Claude Code đọc keychain) → ghi log mỗi giờ 1 lần, tránh phình log
        if throttle("allowed_\(rule.name)_\(cmd.prefix(120))", 3600) {
            spool(.log, "\(rule.name) (trong danh sách cho phép, lặp lại trong 1 giờ không ghi): \(cmd.prefix(200)) — \(parents)")
        }
        return
    }
    guard throttle("exec_\(rule.name)_\(cmd.prefix(120))", 60) else { return }
    spool(rule.level, """
        \(rule.name)
        Lệnh: \(String(cmd.prefix(400)))
        User: \(int(target, "audit_token", "euid").map(userName) ?? "?")
        Tiến trình cha: \(parents)
        """)
}

/// `exes`: quy tắc chỉ xét khi chính chương trình được chạy có tên này (nil = mọi chương trình trừ curl/wget...).
/// Nhờ vậy chữ "security find-generic-password" nằm trong NỘI DUNG tin nhắn mà curl gửi đi không bị tính là lệnh.
/// `needles`: chuỗi mà dòng JSON thô của sự kiện PHẢI chứa thì quy tắc mới có thể khớp — dùng để bỏ qua việc
/// parse JSON cho hầu hết sự kiện exec (mặc định: `<tên chương trình>"`, khớp cả "path":"/usr/bin/x" lẫn args "x").
/// Lưu ý: dòng exec có cả biến môi trường (PATH...) → tránh needle chung chung như "curl", "exec".
struct Rule {
    let name: String; let level: Level; let regex: NSRegularExpression; let exes: Set<String>?; let selfRelated: Bool
    let needles: [String]
}
func rule(_ name: String, _ level: Level, _ exes: Set<String>?, _ pattern: String,
          needles: [String]? = nil, selfRelated: Bool = false) -> Rule {
    Rule(name: name, level: level, regex: try! NSRegularExpression(pattern: pattern, options: [.caseInsensitive]),
         exes: exes, selfRelated: selfRelated, needles: needles ?? (exes ?? []).map { "\($0)\"" })
}
let shells: Set<String> = ["sh", "bash", "zsh", "dash", "ksh", "tcsh", "csh", "fish"]
let interpreters: Set<String> = shells.union(["nc", "ncat", "netcat", "socat", "mkfifo", "perl", "ruby", "php", "lua",
                                              "python", "python3", "python2", "node", "osascript", "tclsh", "expect"])
/// Chương trình chỉ mang dữ liệu (URL, nội dung gửi đi) — không bao giờ xét quy tắc
let dataCarriers: Set<String> = ["curl", "wget", "http", "xh", "echo", "printf", "logger", "grep", "rg", "git"]

let rules: [Rule] = [
    rule("☠️ Lệnh REVERSE SHELL", .alert, interpreters,
         #"/dev/(tcp|udp)/|\bnc(at)?\b.*\s-(e|c)\s|\bncat\b.*--(sh-)?exec\b|socat\b.*exec:|\b(ba|z)?sh\s+-i\b.*>&|pty\.spawn|socket\.socket\(.*connect|fsockopen\(|TCPSocket\.(new|open)|mkfifo\b.*\bnc\b"#,
         needles: ["/dev/tcp/", "/dev/udp/", "pty", "socket", "fsockopen", "TCPSocket", "mkfifo",
                   "nc\"", "ncat\"", "netcat\"", "socat\""]),
    rule("🔑 Lệnh đọc mật khẩu trong Keychain", .alert, ["security"],
         #"(^|/)security\s+(dump-keychain|(find-generic-password|find-internet-password)\b.*\s-[wg]\b|export\b)"#),
    rule("🛡 Lệnh TẮT lớp bảo vệ của macOS", .alert, ["spctl", "csrutil", "tccutil", "socketfilterfw", "pfctl", "nvram", "log", "chflags"],
         #"spctl\s+(--(master|global)-disable|developer-mode)|csrutil\s+disable|tccutil\s+reset|socketfilterfw\s+--setglobalstate\s+off|\bpfctl\s+-d\b|nvram\s+.*boot-args|(^|/)log\s+erase\b|chflags\s+no(s|u)?(appnd|chg)"#),
    rule("⛔️ Lệnh TẮT giám sát (MacSentry / Wazuh / agent bảo mật)", .alert, ["launchctl", "pkill", "killall", "wazuh-control"],
         #"launchctl\s+(bootout|unload|disable|remove)\b.*(macsentry\.(daemon|es)\b|wazuh|crowdstrike|sentinel|wdav|sophos|jamf|santa|littlesnitch|lulu)|\b(pkill|killall)\b.*(macsentryd|macsentry-es|wazuh|falcond|sentineld|wdavdaemon|santad)|wazuh-control\s+stop"#,
         selfRelated: true),
    rule("👑 Lệnh tạo user / cấp quyền admin / đổi mật khẩu", .alert, ["dscl", "dseditgroup", "sysadminctl"],
         #"\bdscl\b.*(-append\s+/Groups/admin|-passwd|-create\s+/Users)|dseditgroup\b.*-a\b.*\badmin\b|sysadminctl\b.*(-addUser|-resetPasswordFor|-guestAccount\s+on)"#),
    rule("🪝 Lệnh cài cửa hậu / bật truy cập từ xa", .alert, ["defaults", "systemsetup", "kickstart", "launchctl", "security"],
         #"defaults\s+write\b.*loginwindow\b.*(LoginHook|LogoutHook|autoLoginUser)|systemsetup\b.*-setremotelogin\s+on|kickstart\b.*-activate|launchctl\s+(load|enable|bootstrap)\b.*screensharing|(^|/)security\s+authorizationdb\s+write"#),
    rule("🎣 Hộp thoại giả hỏi mật khẩu (osascript)", .alert, ["osascript"],
         #"(hidden answer|password)"#),
    rule("📥 Tải script từ Internet rồi chạy ngay", .info, shells,
         #"(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b|\$\((curl|wget)\b"#, needles: ["| sh", "|sh", "| bash", "|bash", "| zsh", "|zsh", "| sudo", "|sudo", "$(curl", "$(wget"]),
    rule("🏷 Gỡ cờ quarantine (bỏ qua kiểm tra Gatekeeper)", .info, ["xattr"],
         #"-(d|c|rd|dr)\b.*com\.apple\.quarantine|(^|/)xattr\s+-c\b"#),
]

/// Aho–Corasick dạng DFA (không phân biệt hoa thường ASCII): tìm NHIỀU chuỗi cùng lúc trong MỘT lượt quét.
/// Thay cho việc gọi memmem cho từng chuỗi (42 chuỗi × 4 KB mỗi dòng exec → quét lại dữ liệu 42 lần).
struct MultiMatcher {
    private let table: [Int32]   // trạng thái * 256 + byte → trạng thái kế tiếp
    private let accept: [Bool]   // trạng thái kết thúc một chuỗi nào đó

    init(_ patterns: [String]) {
        var go: [[Int32]] = [Array(repeating: -1, count: 256)]
        var acc = [false]
        for pat in patterns where !pat.isEmpty {   // 1) cây tiền tố
            var st = 0
            for b in pat.lowercased().utf8.map(Int.init) {
                if go[st][b] < 0 { go.append(Array(repeating: -1, count: 256)); acc.append(false); go[st][b] = Int32(go.count - 1) }
                st = Int(go[st][b])
            }
            acc[st] = true
        }
        var fail = Array(repeating: 0, count: go.count), queue: [Int] = []   // 2) liên kết thất bại theo BFS
        for b in 0..<256 {
            if go[0][b] < 0 { go[0][b] = 0 } else { queue.append(Int(go[0][b])) }
        }
        var qi = 0
        while qi < queue.count {
            let st = queue[qi]; qi += 1
            acc[st] = acc[st] || acc[fail[st]]
            for b in 0..<256 {
                let t = go[st][b]
                if t < 0 { go[st][b] = go[fail[st]][b] } else { fail[Int(t)] = Int(go[fail[st]][b]); queue.append(Int(t)) }
            }
        }
        for st in go.indices { for b in 65...90 { go[st][b] = go[st][b + 32] } }   // 3) A-Z đi như a-z
        table = go.flatMap { $0 }; accept = acc
    }

    func matches(_ hay: UnsafeRawBufferPointer) -> Bool {
        table.withUnsafeBufferPointer { t in
            accept.withUnsafeBufferPointer { a in
                var st = 0
                for byte in hay {
                    st = Int(t[st &* 256 &+ Int(byte)])
                    if a[st] { return true }
                }
                return false
            }
        }
    }
}

// Thêm biến thể "\/" cho chuỗi có "/" phòng khi JSON escape dấu gạch chéo (vd "\/dev\/tcp\/")
let needleMatcher = MultiMatcher(Array(Set(rules.flatMap(\.needles).flatMap { [$0, $0.replacingOccurrences(of: "/", with: "\\/")] })))
let execMarker = Array(#"{"exec":"#.utf8)
/// Dòng exec không chứa chuỗi bắt buộc của quy tắc nào → bỏ qua, không cần parse JSON (đa số sự kiện)
func execIrrelevant(_ hay: UnsafeRawBufferPointer) -> Bool {
    let isExec = execMarker.withUnsafeBytes { memmem(hay.baseAddress, hay.count, $0.baseAddress, $0.count) != nil }
    return isExec && !needleMatcher.matches(hay)
}

func suspicious(exe: String, cmd: String) -> Rule? {
    let name = base(exe)
    if dataCarriers.contains(name) { return nil }
    let r = NSRange(cmd.startIndex..., in: cmd)
    return rules.first { ($0.exes?.contains(name) ?? true) && $0.regex.firstMatch(in: cmd, range: r) != nil }
}

/// Danh sách cho phép: /etc/macsentry.allow, mỗi dòng một regex so với "lệnh || chuỗi tiến trình cha".
/// Khớp → chỉ ghi log. Đọc lại mỗi phút (sửa file không cần khởi động lại).
var allowList: [NSRegularExpression] = []
var allowLoaded = Date.distantPast
func allowed(_ s: String) -> Bool {
    if Date().timeIntervalSince(allowLoaded) > 60 {
        allowLoaded = Date()
        let text = (try? String(contentsOfFile: ProcessInfo.processInfo.environment["ALLOW"] ?? "/etc/macsentry.allow", encoding: .utf8)) ?? ""
        allowList = text.split(separator: "\n").compactMap { l in
            let t = l.trimmingCharacters(in: .whitespaces)
            return t.isEmpty || t.hasPrefix("#") ? nil : try? NSRegularExpression(pattern: t, options: [.caseInsensitive])
        }
    }
    let r = NSRange(s.startIndex..., in: s)
    return allowList.contains { $0.firstMatch(in: s, range: r) != nil }
}

func onEvent(_ type: String, _ e: JSON, _ msg: JSON) {
    switch type {
    case "authentication": onAuthentication(e, msg)
    case "screensharing_attach": onScreenSharing(e, attach: true)
    case "screensharing_detach": onScreenSharing(e, attach: false)
    case "tcc_modify": onTCC(e, msg)
    case "exec": onExec(e, msg)
    case "xp_malware_detected":
        spool(.alert, """
            🦠 XProtect PHÁT HIỆN MÃ ĐỘC
            Loại: \(str(e, "malware_identifier") ?? "?")
            File: \(str(e, "detected_path") ?? deepStr(e, "path") ?? "?")
            (phiên bản dữ liệu nhận diện: \(str(e, "signature_version") ?? "?"))
            """)
    case "xp_malware_remediated":
        spool(.info, "🦠 XProtect đã xử lý mã độc: \(str(e, "malware_identifier") ?? "?")\nKết quả: \((e["success"] as? Bool) == true ? "thành công" : "THẤT BẠI")\nFile: \(str(e, "remediated_path") ?? deepStr(e, "path") ?? "?")")
    case "gatekeeper_user_override":
        spool(.alert, """
            🛂 Vừa cho phép chạy app bị Gatekeeper CHẶN
            File: \(deepStr(e, "path") ?? str(e, "file") ?? "?")
            Team ID: \(deepStr(e, "team_id") ?? "không có")
            (nếu không phải bạn vừa bấm "Vẫn mở" → kiểm tra file này)
            """)
    case "od_modify_password":
        let ok = int(e, "error_code") == 0
        spool(ok ? .alert : .info, """
            🔑 \(ok ? "Mật khẩu tài khoản vừa được ĐỔI" : "Thử đổi mật khẩu tài khoản thất bại")
            Tài khoản: \(str(e, "account_name") ?? "?")
            Tiến trình: \(describe(dict(e, "instigator") ?? dict(msg, "process")))
            """)
    case "kextload":
        spool(.alert, "🧷 Nạp kernel extension: \(str(e, "identifier") ?? "?")\nTiến trình: \(describe(dict(msg, "process")))")
    default: break
    }
}

// MARK: - Chạy eslogger

var sampled: Set<String> = []
/// Lưu mẫu JSON đầu tiên của mỗi loại sự kiện (để đối chiếu định dạng khi cần sửa bộ đọc)
func sample(_ type: String, _ line: Data) {
    guard !sampled.contains(type) else { return }
    sampled.insert(type)
    FileManager.default.createFile(atPath: "\(samplesDir)/\(type).json", contents: line, attributes: [.posixPermissions: 0o600])
}

var lastAlive: time_t = 0
func handle(_ raw: UnsafeRawBufferPointer) {
    let now = time(nil)
    if now - lastAlive > 30 { touch(stateDir + "/es_alive"); lastAlive = now }
    if execIrrelevant(raw) { return }   // lọc trên buffer thô, chưa cấp phát gì
    let line = Data(raw)
    guard let msg = (try? JSONSerialization.jsonObject(with: line)) as? JSON,
          let ev = msg["event"] as? JSON, let type = ev.keys.first, let e = ev[type] as? JSON else { return }
    sample(type, line)
    onEvent(type, e, msg)
}

/// Đọc từng dòng bằng getline(3): đệm ở user space và tái dùng một buffer cho mọi dòng — nhanh hơn hàng chục lần
/// so với FileHandle.availableData + Data.removeSubrange (O(n) mỗi dòng) hay readLine() tạo String mỗi dòng
func forEachLine(fd: Int32, _ body: (UnsafeRawBufferPointer) -> Void) {
    guard let fp = fdopen(dup(fd), "r") else { return }   // dup: fclose không đóng fd của Pipe
    var line: UnsafeMutablePointer<CChar>? = nil
    var cap = 0
    defer { free(line); fclose(fp) }
    while true {
        var len = getline(&line, &cap, fp)
        if len < 0 { break }   // EOF / lỗi
        if len > 0 && line![len - 1] == 0x0A { len -= 1 }
        if len > 0 { body(UnsafeRawBufferPointer(start: line, count: len)) }
    }
}

for d in [spoolDir, samplesDir] { try? FileManager.default.createDirectory(atPath: d, withIntermediateDirectories: true) }
// Chạy thử không cần root: STATE=./thu-muc macsentry-es --replay < su-kien.jsonl
if CommandLine.arguments.contains("--replay") {
    forEachLine(fd: 0, handle)
    exit(0)
}
guard getuid() == 0 else { FileHandle.standardError.write(Data("macsentry-es cần chạy bằng root\n".utf8)); exit(1) }
signal(SIGTERM) { _ in exit(0) }   // launchd dừng helper: eslogger con nhận SIGTERM theo nhóm tiến trình

while true {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/eslogger")
    p.arguments = events
    // stderr ghi ra file (không dùng Pipe: không ai đọc trong lúc chạy → pipe đầy sẽ làm eslogger treo)
    let errPath = stateDir + "/eslogger.err"
    FileManager.default.createFile(atPath: errPath, contents: nil)
    let out = Pipe()
    p.standardOutput = out; p.standardError = FileHandle(forWritingAtPath: errPath)
    do { try p.run() } catch {
        writeStatus("Không chạy được /usr/bin/eslogger: \(error.localizedDescription)")
        sleep(60); continue
    }
    writeStatus("eslogger đang chạy (pid \(p.processIdentifier)) từ \(Date())")
    touch(stateDir + "/es_alive"); lastAlive = time(nil)

    // eslogger sống mà không có sự kiện nào (máy rảnh) vẫn phải được coi là còn sống
    let keepAlive = DispatchSource.makeTimerSource(queue: .global())
    keepAlive.schedule(deadline: .now() + 60, repeating: 60)
    keepAlive.setEventHandler { if p.isRunning { touch(stateDir + "/es_alive") } }
    keepAlive.resume()

    forEachLine(fd: out.fileHandleForReading.fileDescriptor, handle)   // trả về khi eslogger thoát (EOF)
    keepAlive.cancel()
    p.waitUntilExit()
    let why = ((try? String(contentsOfFile: errPath, encoding: .utf8)) ?? "")
        .trimmingCharacters(in: .whitespacesAndNewlines)
    let status = "eslogger dừng (mã \(p.terminationStatus)) lúc \(Date()): \(why.prefix(300))"
    writeStatus(why.localizedCaseInsensitiveContains("permit") || why.contains("TCC")
                ? status + "\n→ Chưa có Full Disk Access" : status)
    try? FileManager.default.removeItem(atPath: stateDir + "/es_alive")
    sleep(30)
}
