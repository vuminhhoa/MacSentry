import Foundation

// MARK: - Quy tắc phát hiện lệnh nguy hiểm (exec) và danh sách cho phép

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
