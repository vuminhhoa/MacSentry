import Foundation

// MARK: - Xác thực qua `log stream` — chỉ là DỰ PHÒNG khi helper Endpoint Security không chạy
// (`log stream` tốn ~5% một nhân; helper đã có sự kiện authentication / sudo / su / openssh_login, chính xác hơn)

private var authProc: Process?
private var authCaller = ""
private var authMarker = Date.distantPast

/// Gọi mỗi 30 giây: bật `log stream` khi helper ES chết, tắt khi helper sống lại
func manageAuthStream() {
    let es = esAlive()
    if es, let p = authProc { p.terminate(); authProc = nil; return }
    guard !es, authProc?.isRunning != true else { return }
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/log")
    p.arguments = ["stream", "--style", "compact", "--predicate", """
        (process == "opendirectoryd" AND eventMessage CONTAINS "Authentication failed for")
         OR (eventMessage == "Verify basic credentials")
         OR (eventMessage CONTAINS "OpenDirectory - The authtok is incorrect")
         OR (process BEGINSWITH "sshd" AND eventMessage CONTAINS "authentication error for")
         OR (process == "sudo" AND eventMessage CONTAINS "COMMAND=")
        """]
    let out = Pipe()
    p.standardOutput = out
    p.standardError = FileHandle.nullDevice
    guard (try? p.run()) != nil else { return }
    authProc = p
    let h = out.fileHandleForReading
    Thread.detachNewThread {
        guard let fp = fdopen(dup(h.fileDescriptor), "r") else { return }
        var line: UnsafeMutablePointer<CChar>?, cap = 0
        defer { free(line); fclose(fp) }
        while getline(&line, &cap, fp) >= 0 {
            let s = String(cString: line!).trimmingCharacters(in: .newlines)
            q.async { onAuthLine(s) }
        }
    }
}
func stopAuthStream() { authProc?.terminate() }

private func after(_ s: String, _ marker: String) -> String {
    s.range(of: marker).map { String(s[$0.upperBound...]).trimmingCharacters(in: .whitespaces) } ?? s
}
private func field4(_ s: String) -> String {
    let c = s.split(separator: " ", omittingEmptySubsequences: true)
    return c.count > 3 ? String(c[3]) : ""
}

private func onAuthLine(_ line: String) {
    if line.contains("(CFOpenDirectory) Verify basic credentials") {
        // Tiến trình yêu cầu kiểm tra mật khẩu (dòng này tới ngay trước "Authentication failed for")
        authCaller = field4(line)
    } else if line.contains("OpenDirectory - The authtok is incorrect") {
        authMarker = Date()   // lỗi PAM từ sshd/sudo: không báo trùng thành "sai mật khẩu" chung
    } else if line.contains("Authentication failed for") {
        let uuid = line.matches(#"Authentication failed for [^(]*\(([0-9A-Fa-f-]*)\)"#).first ?? ""
        let user = run("/usr/bin/dscl", [".", "-search", "/Users", "GeneratedUID", uuid]).split(separator: "\t").first.map(String.init) ?? "?"
        let caller = authCaller, cname = String(caller.split(separator: "[").first ?? "")
        // Đợi xem có phải từ sshd/sudo không (dòng PAM tới ngay sau); nếu không → màn hình khoá / hộp thoại xác thực
        q.asyncAfter(deadline: .now() + 3) {
            guard Date().timeIntervalSince(authMarker) > 5 else { return }
            if esAlive() { log("Xác thực thất bại: \(user) qua \(caller) (helper ES xử lý cảnh báo)"); return }
            let whereFrom: String
            switch cname {
            case "akd", "appleaccountd", "cdpd", "filevaultd":
                // Dịch vụ nền của Apple tự kiểm tra mật khẩu đã lưu — không phải người gõ
                log("Dịch vụ hệ thống \(caller) kiểm tra mật khẩu của \(user) thất bại (không phải người nhập, không cảnh báo)"); return
            case "loginwindow": whereFrom = "màn hình khoá / đăng nhập"
            case "authorizationhost", "SecurityAgent", "SecurityPrivacyExtension": whereFrom = "hộp thoại xác thực (quyền admin / Cài đặt)"
            case "": whereFrom = "không rõ tiến trình"
            default: whereFrom = "tiến trình lạ"
            }
            if throttle("od_\(user)_\(cname)", 30) {
                alert("🔐 Nhập sai mật khẩu\nUser: \(user)\nNguồn: \(whereFrom)\nTiến trình: \(caller.isEmpty ? "?" : caller)\nLúc: \(nowStr())")
            }
        }
    } else if line.contains("authentication error for") {
        authMarker = Date()
        let rest = after(line, "authentication error for")
        let parts = rest.components(separatedBy: " from ")
        let user = parts.first ?? "?", ip = parts.count > 1 ? parts[1] : "?"
        if throttle("sshfail_\(ip)", 300) {
            alert("🔐 SSH sai mật khẩu\nUser: \(user)\nIP: \(ip)\nLúc: \(nowStr())\n(các lần lặp lại từ IP này trong 5 phút sẽ không báo)")
        } else { log("SSH sai mật khẩu: \(user) từ \(ip)") }
    } else if line.contains(" sudo[") {
        let msg = line.replacingOccurrences(of: #".*sudo\[[^\]]*\] *"#, with: "", options: .regularExpression)
        if line.contains("incorrect password attempt") { alert("🔐 sudo nhập sai mật khẩu\n\(msg)") }
        else if line.contains("a password is required") { log("sudo -n bị từ chối (chưa nhập mật khẩu): \(msg)") }
        else if line.contains("NOT in sudoers") || line.contains("command not allowed") || line.contains("not allowed to run") {
            alert("⛔️ sudo bị TỪ CHỐI (user không có quyền)\n\(msg)")
        } else if line.contains("COMMAND="), throttle("sudo_\(msg.prefix(120))", 10) { info("⚡️ sudo\n\(msg)") }
    }
}
