import Foundation

// MARK: - Tư thế bảo mật (SIP, FileVault, khoá màn hình...) và tự bảo vệ file của MacSentry

func checkPosture(_ procs: [Proc], tick: Int) {
    let sip = run("/usr/bin/csrutil", ["status"]).contains("enabled.") ? "BẬT" : "TẮT"
    let fv = run("/usr/bin/fdesetup", ["status"]).contains("FileVault is On") ? "BẬT" : "TẮT"
    let su = plist("/Library/Preferences/com.apple.SoftwareUpdate.plist")
    let lw = plist("/Library/Preferences/com.apple.loginwindow.plist")
    let rm = plist("/Library/Preferences/com.apple.RemoteManagement.plist")
    func on(_ v: Any?) -> Bool { (v as? Bool) == true || (v as? Int) == 1 }
    let alu = lw?["autoLoginUser"] as? String
    let console = consoleUser()
    var lock = ""
    if console != "root" {
        writeText(sp("expect_sudo"), "")   // báo trước cho helper ES: lệnh sudo ngay sau đây là của MacSentry, không báo
        for l in lines(run("/usr/bin/sudo", ["-u", console, "/usr/sbin/sysadminctl", "-screenLock", "status"])) {
            if let r = l.range(of: "screenLock delay is ") { lock = String(l[r.upperBound...]).trimmingCharacters(in: .whitespaces); break }
            if l.contains("screenLock is off") { lock = "off"; break }
        }
    }
    let mdm = lines(run("/usr/bin/profiles", ["status", "-type", "enrollment"])).first { $0.contains("MDM enrollment") }
        .map { l -> String in let v = l.components(separatedBy: ": ").last ?? ""; return v.hasPrefix("No") ? "không" : "ĐÃ ĐĂNG KÝ (\(v)) ⚠️" } ?? ""
    let xpPlist = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
    let fmm = run("/usr/sbin/nvram", ["fmm-mobileme-token-FMM"]).contains("fmm-mobileme-token-FMM")
    // Quy ước: dòng kết thúc bằng "TẮT" hoặc chứa "⚠️" là trạng thái xấu → chuyển sang trạng thái đó thì có chuông
    var posture = """
        SIP: \(sip)
        FileVault: \(fv)
        Tự cập nhật bảo mật: \(on(su?["CriticalUpdateInstall"]) ? "BẬT" : "TẮT")
        Tự đăng nhập không cần mật khẩu: \(alu.map { "BẬT (\($0)) ⚠️" } ?? "không")
        Tài khoản Guest: \(on(lw?["GuestEnabled"]) ? "BẬT ⚠️" : "không")
        Remote Management (ARD): \(running("ARDAgent", in: procs) ? "đang chạy ⚠️" : "không")
        VNC cho phép mật khẩu kiểu cũ (≤8 ký tự): \(on(rm?["VNCLegacyConnectionsEnabled"]) ? "BẬT ⚠️" : "không")
        Screen Sharing cho phép mã hoá yếu (insecure DH): \(on(rm?["allowInsecureDH"]) ? "BẬT ⚠️" : "không")
        Find My Mac: \(fmm ? "BẬT" : "TẮT")
        Quản lý thiết bị (MDM): \(mdm)
        XProtect: \(plist(xpPlist)?["CFBundleShortVersionString"] as? String ?? "? ⚠️")
        """
    switch lock {
    case "": break
    case "immediate": posture += "\nKhoá màn hình đòi mật khẩu: ngay lập tức"
    case "off": posture += "\nKhoá màn hình đòi mật khẩu: TẮT"
    default: posture += "\nKhoá màn hình đòi mật khẩu: sau \(lock) ⚠️"
    }
    writeText(sp("posture_now"), posture + "\n")
    for v in diffState("posture", lines(posture)).added {
        v.hasSuffix("TẮT") || v.contains("⚠️") ? alert("🛡 Bảo mật bị hạ: \(v)") : info("🛡 Bảo mật: \(v)")
    }

    // Dữ liệu nhận diện mã độc XProtect quá cũ → máy không nhận được cập nhật bảo mật
    if let m = (try? FileManager.default.attributesOfItem(atPath: xpPlist))?[.modificationDate] as? Date {
        let age = Int(Date().timeIntervalSince(m) / 86400)
        if age > 45, throttle("xprotect_old", 86400) { alert("🦠 XProtect chưa cập nhật \(age) ngày — kiểm tra Software Update / kết nối mạng") }
    }

    // Helper Endpoint Security phải đang chạy nếu đã cài (cho nó 2 phút khởi động)
    if exists("/Library/LaunchDaemons/io.github.vuminhhoa.macsentry.es.plist"), !esAlive(), tick > 60, throttle("es_dead", 21600) {
        alert("⚠️ Giám sát Endpoint Security KHÔNG hoạt động\n\(readText(sp("es_status")) ?? "Helper macsentry-es không chạy")\n→ Cấp Full Disk Access cho /usr/local/libexec/macsentry-es (Cài đặt → Quyền riêng tư & Bảo mật → Truy cập toàn bộ ổ đĩa)")
    }

    // Full Disk Access của chính daemon: thiếu thì một số vị trí (DB Background Items, file của user trong vùng được
    // bảo vệ...) đọc ra rỗng → bỏ sót. Phép thử chuẩn: mở DB TCC của hệ thống (chỉ đọc được khi có FDA).
    if !hasFullDiskAccess(), throttle("daemon_fda", 86400) {
        alert("⚠️ macsentryd chưa có Full Disk Access — một số giám sát có thể bỏ sót\n→ Cài đặt → Quyền riêng tư & Bảo mật → Truy cập toàn bộ ổ đĩa → + → Cmd+Shift+G gõ /usr/local/libexec/macsentryd → bật công tắc")
    }

    // Bot của app và của daemon dùng chung token → phần mềm chạy bằng user đọc được token của app là xoá được
    // cả cảnh báo của daemon (bot xoá được tin chính nó gửi trong 48 giờ)
    for f in glob(["/Users/*/Library/Application Support/MacSentry/telegram.json"]) {
        let tok = FileManager.default.contents(atPath: f).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }?["botToken"] as? String
        if tok == config.token, throttle("sametoken", 604800) {
            info("🔑 App và daemon đang dùng CHUNG bot Telegram. Nên tạo bot riêng cho daemon rồi chạy trong thư mục mã nguồn MacSentry: sudo ./daemon/install.sh --reconfigure")
        }
    }
}

/// File của chính MacSentry bị sửa/xoá (nếu không phải bạn vừa cập nhật → có thể bị can thiệp)
func checkSelf() {
    let files = glob(["/usr/local/libexec/macsentryd", "/usr/local/libexec/macsentry-es", "/Library/LaunchDaemons/io.github.vuminhhoa.macsentry.daemon.plist",
                      "/Library/LaunchDaemons/io.github.vuminhhoa.macsentry.es.plist", "/etc/macsentry.conf", trustedPath,
                      "/Users/*/Applications/MacSentry.app/Contents/MacOS/MacSentry"])
    // Lần đầu: ghi chữ ký hiện tại của các file chạy để lần sau so
    for f in files where !f.hasSuffix(".plist") && !f.hasPrefix("/etc/") {
        let sf = sp("signers/self_" + f.replacingOccurrences(of: "/", with: "_"))
        if !exists(sf) { writeText(sf, signer(f)) }
    }
    guard statChanged("self", files) else { return }
    // install.sh ghi dấu "just_updated" khi cài/cập nhật → thay đổi trong 10 phút sau đó chỉ là tin im lặng
    let updated = ((try? FileManager.default.attributesOfItem(atPath: sp("just_updated")))?[.modificationDate] as? Date)
        .map { Date().timeIntervalSince($0) < 600 } ?? false
    for (kind, f) in hashChanges("selfsums", files) {
        // File chạy (app, daemon, helper): build lại hợp lệ giữ nguyên chứng chỉ ký → chỉ báo im lặng; đổi / mất chữ ký
        // (bị tráo bằng binary khác) → cảnh báo
        let isExe = !f.hasSuffix(".plist") && !f.hasPrefix("/etc/")
        let sigFile = sp("signers/self_" + f.replacingOccurrences(of: "/", with: "_"))
        let sig = isExe && kind != .removed ? signer(f) : ""
        let oldSig = readText(sigFile)
        if isExe && kind != .removed { writeText(sigFile, sig) }
        switch kind {
        case .removed: alert("🧬 File của MacSentry bị XOÁ: \(f)")
        case .new: info("🧬 File mới của MacSentry: \(f)")
        case .changed where updated: info("🧬 File của MacSentry được cập nhật: \(f)")
        case .changed where isExe && oldSig == sig && !sig.hasPrefix("⚠️"): info("🧬 File của MacSentry được build lại (cùng chữ ký: \(sig)): \(f)")
        case .changed where isExe:
            alert("🧬 File chạy của MacSentry thay đổi CHỮ KÝ: \(f)\nTrước: \(oldSig ?? "?")\nBây giờ: \(sig)\n(nếu bạn không vừa đổi chứng chỉ ký → có thể bị tráo file)")
        case .changed: alert("🧬 File của MacSentry thay đổi: \(f)\n(nếu bạn không vừa cập nhật MacSentry → có thể bị can thiệp)")
        }
    }
}

func hasFullDiskAccess() -> Bool {
    let fd = open("/Library/Application Support/com.apple.TCC/TCC.db", O_RDONLY)
    if fd >= 0 { close(fd); return true }
    return false
}
