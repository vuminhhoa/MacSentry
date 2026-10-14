import Foundation

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
    let now = Date()
    if let t = throttled[key], now.timeIntervalSince(t) < seconds { return false }
    // Khoá có chứa dòng lệnh → dọn mục cũ để từ điển không phình mãi (khoá dài nhất là 1 giờ)
    if throttled.count > 2000 { throttled = throttled.filter { now.timeIntervalSince($0.value) < 3600 } }
    throttled[key] = now; return true
}

func touch(_ path: String) {
    FileManager.default.createFile(atPath: path, contents: nil)
}

func writeStatus(_ s: String) {
    try? s.write(toFile: stateDir + "/es_status", atomically: true, encoding: .utf8)
}
