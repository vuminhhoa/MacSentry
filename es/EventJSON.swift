import Foundation

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
