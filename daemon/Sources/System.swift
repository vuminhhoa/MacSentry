import Foundation

// MARK: - Tự khởi động mới, app MacSentry còn chạy, tài khoản / admin, firewall, Gatekeeper

/// Helper Endpoint Security (macsentry-es) còn sống: nó chạm file này mỗi phút khi eslogger đang chạy được
func esAlive() -> Bool {
    guard let m = (try? FileManager.default.attributesOfItem(atPath: sp("es_alive")))?[.modificationDate] as? Date else { return false }
    return Date().timeIntervalSince(m) < 180
}

/// LaunchAgent / LaunchDaemon mới — cách phổ biến nhất để mã độc tự chạy lại. Gọi ngay khi FSEvents thấy thư mục
/// đổi (và quét dự phòng mỗi 10 giây). Helper ES ghi thêm vào log tiến trình nào đã cài (sự kiện BTM).
let launchDirs = ["/Library/LaunchAgents/*", "/Library/LaunchDaemons/*", "/Users/*/Library/LaunchAgents/*"]
func checkLaunchItems() {
    let d = diffState("persistence", glob(launchDirs), nonempty: true)
    for path in d.added {
        let pl = plist(path)
        let prog = (pl?["Program"] as? String) ?? (pl?["ProgramArguments"] as? [String])?.first
        alert("🧩 Có chương trình tự khởi động mới\nFile: \(path)\nChạy: \(prog ?? "?")\nChữ ký: \(signer(prog))")
    }
    for path in d.removed { info("🧩 Đã gỡ chương trình tự khởi động\nFile: \(path)") }
}

/// App MacSentry phải luôn chạy khi có người đăng nhập (vắng ~30 giây liên tục → có thể đã bị gỡ)
var appMissing = 0
func checkApp(_ procs: [Proc]) {
    let console = consoleUser()
    guard console != "root", !running("MacSentry", in: procs) else { appMissing = 0; return }
    appMissing += 1
    if appMissing >= 3, throttle("appmissing", 600) {
        alert("⚠️ App MacSentry KHÔNG chạy (user đang đăng nhập: \(console))\nCó thể đã bị gỡ LaunchAgent hoặc xoá app")
    }
}

/// Tài khoản user (UID >= 500), nhóm admin, firewall, Gatekeeper.
/// Khi helper ES chạy, nó đã báo tức thì tạo user / cấp admin (kèm tiến trình) → ở đây chỉ là tin im lặng dự phòng.
func checkAccounts() {
    let es = esAlive()
    var users: [String] = []
    setpwent()
    while let pw = getpwent() { if pw.pointee.pw_uid >= 500 { users.append(String(cString: pw.pointee.pw_name)) } }
    endpwent()
    let du = diffState("users", users, nonempty: true)
    for u in du.added { es ? info("👥 Có tài khoản user mới: \(u)") : alert("👥 Có tài khoản user mới: \(u)") }
    for u in du.removed { es ? info("👥 Đã xoá tài khoản user: \(u)") : alert("👥 Đã xoá tài khoản user: \(u)") }

    var admins: [String] = []
    if let g = getgrnam("admin"), var m = g.pointee.gr_mem {
        while let p = m.pointee { admins.append(String(cString: p)); m += 1 }
    }
    let da = diffState("admins", admins, nonempty: true)
    for u in da.added { es ? info("👑 \(u) vừa được cấp quyền ADMIN") : alert("👑 \(u) vừa được cấp quyền ADMIN") }
    for u in da.removed { info("👑 \(u) bị gỡ quyền admin") }

    // Lệnh lỗi → rỗng → bỏ qua (nonempty)
    func onOff(_ s: String) -> [String] { s.contains("disabled") ? ["TẮT"] : s.contains("enabled") ? ["BẬT"] : [] }
    for v in diffState("firewall", onOff(run("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"])), nonempty: true).added {
        v == "TẮT" ? alert("🧱 Firewall vừa bị TẮT") : info("🧱 Firewall đã bật")
    }
    for v in diffState("gatekeeper", onOff(run("/usr/sbin/spctl", ["--status"])), nonempty: true).added {
        v == "TẮT" ? alert("🛂 Gatekeeper vừa bị TẮT (cho chạy app không rõ nguồn gốc)") : info("🛂 Gatekeeper đã bật")
    }
}
