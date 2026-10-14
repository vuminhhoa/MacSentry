import Foundation

// MARK: - Chống cài cắm: file nhạy cảm, Login Items, profile, cert, kext, extension trình duyệt...

/// File cấu hình nhạy cảm — hacker hay sửa để giữ quyền truy cập (báo kèm nội dung thay đổi)
let sensitivePatterns = [
    "/Users/*/.ssh/authorized_keys", "/Users/*/.ssh/authorized_keys2", "/var/root/.ssh/authorized_keys",
    "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*", "/etc/sudoers", "/etc/sudoers.d/*", "/etc/pam.d/*",
    "/etc/crontab", "/usr/lib/cron/tabs/*", "/etc/hosts", "/etc/zshrc", "/etc/zprofile", "/etc/zshenv", "/etc/bashrc", "/etc/profile",
    "/etc/paths", "/etc/paths.d/*", "/etc/periodic.conf", "/etc/rc.common", "/etc/launchd.conf", "/etc/ssh/ssh_config",
    "/Users/*/.ssh/config", "/Users/*/.zshrc", "/Users/*/.zprofile", "/Users/*/.zshenv", "/Users/*/.zlogin",
    "/Users/*/.bashrc", "/Users/*/.bash_profile", "/Users/*/.profile", "/var/root/.zshrc", "/var/root/.profile",
]

/// Luôn băm MỌI file (để khi Wazuh dừng / mất kết nối, MacSentry nhận lại việc mà không báo nhầm hàng loạt "file mới"),
/// nhưng file Wazuh syscheck đang theo dõi thời gian thực (FIM=auto) thì chỉ ghi log — Wazuh báo về manager.
func checkFiles() {
    try? FileManager.default.createDirectory(atPath: sp("files"), withIntermediateDirectories: true)
    let list = glob(sensitivePatterns)
    // Đổi danh sách mẫu theo dõi → tăng phiên bản để lấy mốc lại, không báo nhầm hàng loạt "file MỚI"
    let filesV = "3"
    if readText(sp("files_v")) != filesV { try? FileManager.default.removeItem(atPath: sp("filesums")); writeText(sp("files_v"), filesV) }
    let first = !exists(sp("filesums"))
    // Chỉ băm khi ctime / kích thước / danh sách đổi
    guard statChanged("files", list) || first else { return }
    let changes = hashChanges("filesums", list)
    if first { for f in list { try? FileManager.default.removeItem(atPath: copyOf(f)); try? FileManager.default.copyItem(atPath: f, toPath: copyOf(f)) }; return }
    for (kind, f) in changes {
        let copy = copyOf(f)
        if wazuhFIMCovers(f) {
            log("📝 File nhạy cảm \(kind.rawValue): \(f) (Wazuh syscheck đang theo dõi thời gian thực — Wazuh báo về manager)")
            try? FileManager.default.removeItem(atPath: copy)
            if kind != .removed { try? FileManager.default.copyItem(atPath: f, toPath: copy) }
            continue
        }
        switch kind {
        case .removed:
            alert("📝 File nhạy cảm bị XOÁ: \(f)"); try? FileManager.default.removeItem(atPath: copy)
        case .new:
            alert("📝 File nhạy cảm MỚI: \(f)\n\(headLines(f, 10))")
        case .changed:
            var notify = alert, hint = ""
            if f.hasPrefix("/etc/pam.d/") || ["/etc/zshrc", "/etc/zprofile", "/etc/zshenv", "/etc/bashrc", "/etc/profile",
                                               "/etc/ssh/sshd_config", "/etc/ssh/ssh_config", "/etc/paths"].contains(f) {
                hint = "\n(file của macOS — nếu vừa cập nhật macOS thì thường là bình thường)"
            } else if f.hasPrefix("/Users/") {
                // Shell rc / ssh config của user: bạn hay tự sửa → tin im lặng (vẫn kèm nội dung để soát)
                notify = info
                hint = "\n(file của user — nếu bạn không vừa sửa thì kiểm tra dòng mới: alias/lệnh lạ chạy mỗi lần mở terminal)"
            }
            notify("📝 File nhạy cảm bị SỬA: \(f)\n\(lineDiff(readText(copy) ?? "", readText(f) ?? "", limit: 15))\n(< dòng cũ, > dòng mới)\(hint)")
        }
        if kind != .removed { try? FileManager.default.removeItem(atPath: copy); try? FileManager.default.copyItem(atPath: f, toPath: copy) }
    }
}

// MARK: - Login Items / Background Items (SMAppService) — dự phòng cho sự kiện BTM của helper ES

/// sfltool tốn 3–5 giây → chạy NỀN khi file DB Background Items đổi; khi helper ES chạy (đã có sự kiện BTM tức thì)
/// thì chỉ 6 giờ một lần, không thì mỗi giờ. Kết quả được so ở lượt kế tiếp.
func checkBTM(es: Bool) {
    if let out = readText(sp("btm_scan")) {
        try? FileManager.default.removeItem(atPath: sp("btm_scan"))
        let d = diffState("btm", lines(out), nonempty: true)
        for r in d.added { es ? info("🧩 Mục chạy nền / Login Item mới: \(r)") : alert("🧩 Mục chạy nền / Login Item mới: \(r)") }
        for r in d.removed { info("🧩 Đã gỡ mục chạy nền: \(r)") }
    }
    let dbs = glob(["/private/var/db/com.apple.backgroundtaskmanagement/*"])
    let period = es ? 6 * 3600 : 3600
    let sig = dbs.map { p -> String in var st = stat(); stat(p, &st); return "\(st.st_ctimespec.tv_sec) \(st.st_size) \(p)" }.joined(separator: "\n")
        + " \(Int(Date().timeIntervalSince1970) / period)"
    // ES chạy: chỉ theo nhịp thời gian (sự kiện BTM đã báo thay đổi)
    let key = es ? " \(Int(Date().timeIntervalSince1970) / period)" : sig
    guard readText(sp("btm_sig")) != key else { return }
    writeText(sp("btm_sig"), key)
    slowQ.async {
        var t = "", out: [String] = []
        for l in lines(run("/usr/bin/sfltool", ["dumpbtm"], timeout: 60)) {
            let s = l.trimmingCharacters(in: .whitespaces)
            if s.hasPrefix("Type:") { t = String(s.dropFirst(5)).trimmingCharacters(in: .whitespaces) }
            if s.hasPrefix("Identifier:"), !(t.hasPrefix("developer") || t.hasPrefix("app") || t.hasPrefix("legacy")) {
                out.append("\(t) | \(String(s.dropFirst(11)).trimmingCharacters(in: .whitespaces))")
            }
        }
        let text = Set(out).sorted().map { $0 + "\n" }.joined()
        q.async { writeText(sp("btm_scan"), text) }
    }
}

// MARK: - Các vị trí cài cắm khác (mỗi phút, hoặc ngay khi FSEvents thấy thư mục đổi)

func checkPersistence() {
    let es = esAlive()
    checkBTM(es: es)

    // Configuration profile — helper ES có sự kiện profile_add (kèm tiến trình cài) → khi đó chỉ quét mỗi giờ, tin im lặng
    if !es || throttle("profiles_scan", 3600) {
        let profs = lines(run("/usr/bin/profiles", ["list", "-all"])).compactMap { l -> String? in
            guard let r = l.range(of: "profileIdentifier: ") else { return nil }
            let id = String(l[r.upperBound...]).trimmingCharacters(in: .whitespaces)
            return id.hasPrefix("com.apple.ManagedSettings.") ? nil : id   // profile Screen Time do macOS tự tạo/xoá
        }
        let d = diffState("profiles", profs)
        for p in d.added {
            let m = "📜 Có configuration profile MỚI: \(p)\n(profile có thể ép proxy, chứng chỉ, quản lý máy từ xa)"
            es ? info(m) : alert(m)
        }
        for p in d.removed { info("📜 Đã gỡ profile: \(p)") }
    }

    // System extension (đọc thẳng DB của sysextd thay vì `systemextensionsctl`)
    let exts = ((plist("/Library/SystemExtensions/db.plist")?["extensions"] as? [[String: Any]]) ?? []).compactMap { e -> String? in
        guard let id = e["identifier"] as? String, (e["state"] as? String)?.hasPrefix("activated") == true else { return nil }
        return id
    }
    let dx = diffState("sysext", exts)
    for e in dx.added { alert("🧷 System extension mới: \(e)") }
    for e in dx.removed { info("🧷 System extension đã gỡ: \(e)") }

    checkPersistDirs()

    // Login/Logout hook (cách cũ nhưng vẫn chạy bằng root mỗi lần đăng nhập)
    var hooks: [String] = []
    for d in ["/Library/Preferences/com.apple.loginwindow.plist", "/var/root/Library/Preferences/com.apple.loginwindow.plist"] {
        for k in ["LoginHook", "LogoutHook"] { if let v = plist(d)?[k] as? String { hooks.append("\(k): \(v)") } }
    }
    for v in diffState("hooks", hooks).added { alert("🪝 Login/Logout hook MỚI: \(v)") }

    // Chứng chỉ Root CA được tin cậy thêm (dùng để giải mã/nghe lén HTTPS) — chỉ đọc lại khi keychain / trust đổi
    if statChanged("certs_src", ["/Library/Keychains/System.keychain", "/Library/Security/Trust Settings/Admin.plist"]) || !exists(sp("certs")) {
        var certs: [String] = [], h = ""
        for l in lines(run("/usr/bin/security", ["find-certificate", "-a", "-Z", "/Library/Keychains/System.keychain"])) {
            if l.hasPrefix("SHA-1 hash:") { h = String(l.dropFirst(12).prefix(12)) }
            if l.contains("\"labl\""), let r = l.range(of: "=\"") { certs.append("System.keychain | \(l[r.upperBound...].dropLast()) | \(h)") }
        }
        for l in lines(run("/usr/bin/security", ["dump-trust-settings", "-d"])) where l.hasPrefix("Cert ") {
            if let r = l.range(of: ": ") { certs.append("Tin cậy (admin) | \(l[r.upperBound...])") }
        }
        let d = diffState("certs", certs, nonempty: true)
        for v in d.added { alert("📜 Chứng chỉ MỚI được thêm / tin cậy: \(v)\n(chứng chỉ gốc lạ cho phép nghe lén HTTPS — nếu không phải bạn cài (mkcert, Proxyman...) thì gỡ ngay)") }
        for v in d.removed { info("📜 Đã gỡ chứng chỉ: \(v)") }
    }

    // Kernel extension bên thứ ba đang nạp (helper ES đã có sự kiện kextload → khi đó quét thưa)
    if !es || throttle("kmutil_scan", 1800) {
        let kexts = lines(run("/usr/bin/kmutil", ["showloaded", "--list-only"])).compactMap { l -> String? in
            let c = l.split(separator: " ", omittingEmptySubsequences: true)
            guard c.count >= 6, !c[5].hasPrefix("com.apple.") else { return nil }
            return String(c[5])
        }
        let d = diffState("kexts", kexts)
        for k in d.added { alert("🧷 Kernel extension MỚI được nạp: \(k)") }
        for k in d.removed { info("🧷 Kernel extension đã gỡ: \(k)") }
    }

    // Dịch vụ hệ thống bị tắt (launchctl disable) — đọc thẳng DB của launchd
    let disabled = (plist("/private/var/db/com.apple.xpc.launchd/disabled.plist") ?? [:]).compactMap { $0.value as? Bool == true ? $0.key : nil }
    let dd = diffState("launchd_disabled", disabled)
    for s in dd.added { alert("⛔️ Dịch vụ hệ thống vừa bị TẮT (launchctl disable): \(s)") }
    for s in dd.removed { info("Dịch vụ được bật lại: \(s)") }

    checkBrowserExtensions()

    let apps = glob(["/Applications/*.app", "/Users/*/Applications/*.app"])
    let dapp = diffState("apps", apps, nonempty: true)
    for a in dapp.added { info("📦 App mới được cài: \(a)\nChữ ký: \(signer(a))") }
    for a in dapp.removed { info("📦 App bị gỡ: \(a)") }
}

/// Thư mục cài cắm ít gặp nhưng nguy hiểm: authorization plugin (chạy lúc đăng nhập, đọc được mật khẩu), helper chạy
/// bằng root, StartupItems, plugin Directory Services, kext, plugin âm thanh (nghe lén), periodic
func checkPersistDirs() {
    let pdirs = glob(["/Library/Security/SecurityAgentPlugins/*", "/Library/PrivilegedHelperTools/*", "/Library/StartupItems/*",
                      "/Library/DirectoryServices/PlugIns/*", "/Library/Extensions/*", "/Library/Audio/Plug-Ins/HAL/*",
                      "/etc/periodic/*/*", "/usr/local/etc/periodic/*/*"])
    let d = diffState("persist_dirs", pdirs)
    for path in d.added {
        let hint = path.hasPrefix("/Library/Security/SecurityAgentPlugins/") ? "\n(authorization plugin: chạy trong quá trình đăng nhập, có thể đọc mật khẩu)"
                 : path.hasPrefix("/Library/PrivilegedHelperTools/") ? "\n(helper chạy bằng quyền root)" : ""
        alert("🧩 Thành phần tự chạy MỚI: \(path)\nChữ ký: \(signer(path))\(hint)")
    }
    for path in d.removed { info("🧩 Đã gỡ: \(path)") }
}

/// Extension trình duyệt (Chrome / Edge / Brave): extension độc đọc được mọi trang, cookie, mật khẩu đã nhập
func checkBrowserExtensions() {
    let browsers = ["Google/Chrome", "Microsoft Edge", "BraveSoftware/Brave-Browser"]
    // Thư mục trình duyệt có nhưng không đọc được (thiếu Full Disk Access — macOS bảo vệ dữ liệu app) → bỏ qua lượt
    // này, KHÔNG lấy mốc rỗng (nếu không, khi được cấp quyền mọi extension có sẵn sẽ bị báo là "MỚI")
    for root in glob(browsers.map { "/Users/*/Library/Application Support/\($0)" })
        where (try? FileManager.default.contentsOfDirectory(atPath: root)) == nil { return }
    let dirs = glob(browsers.map { "/Users/*/Library/Application Support/\($0)/*/Extensions" })
    guard statChanged("browser_ext_dirs", dirs) else { return }
    var exts: [String] = []
    for d in dirs {
        let user = d.split(separator: "/").dropFirst(1).first.map(String.init) ?? "?"
        let browser = browsers.first { d.contains("/\($0)/") } ?? "?"
        for e in glob(["\(d)/*"]) {
            let m = glob(["\(e)/*/manifest.json"]).last
            var n = m.flatMap { FileManager.default.contents(atPath: $0) }
                .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }?["name"] as? String ?? "?"
            if n.hasPrefix("__MSG_") { n = "?" }
            exts.append("\(browser) (\(user)) | \(base(e)) | \(n)")
        }
    }
    let dd = diffState("browser_ext", exts)
    for v in dd.added { alert("🧩 Extension trình duyệt MỚI: \(v)") }
    for v in dd.removed { info("🧩 Đã gỡ extension trình duyệt: \(v)") }
}

// MARK: - Mọi LaunchDaemon/Agent: nội dung plist bị sửa, file chạy bị thay bằng file có CHỮ KÝ KHÁC

func checkDaemonIntegrity() {
    try? FileManager.default.createDirectory(atPath: sp("signers"), withIntermediateDirectories: true)
    try? FileManager.default.createDirectory(atPath: sp("files"), withIntermediateDirectories: true)
    let plists = glob(["/Library/LaunchDaemons/*.plist", "/Library/LaunchAgents/*.plist", "/Users/*/Library/LaunchAgents/*.plist"])
    if statChanged("plists", plists) {
        for (kind, f) in hashChanges("plist_sums", plists) where kind == .changed {
            let copy = copyOf(f), new = plistText(f)
            let d = lineDiff(readText(copy) ?? "", new, limit: 15)
            // LaunchAgent của user hay bị app tự cập nhật → tin im lặng
            let n: (String) -> Void = f.hasPrefix("/Users/") ? info : alert
            n("🧩 Cấu hình tự khởi động bị SỬA: \(f)\n\(d.isEmpty ? "(không đọc được nội dung cũ)" : d)\n(< cũ, > mới)")
            writeText(copy, new)
        }
        for f in plists where !exists(copyOf(f)) { writeText(copyOf(f), plistText(f)) }
    }
    for f in plists where !f.hasPrefix("/Users/") {
        guard let pl = plist(f), let label = pl["Label"] as? String,
              let prog = (pl["Program"] as? String) ?? (pl["ProgramArguments"] as? [String])?.first else { continue }
        let sf = sp("signers/\(label)")
        // Chỉ kiểm lại chữ ký khi file chạy đổi ctime / kích thước
        var st = stat()
        let key = stat(prog, &st) == 0 ? "\(st.st_ctimespec.tv_sec) \(st.st_size)" : ""
        if !key.isEmpty, readText(sf + ".key") == key, exists(sf) { continue }
        writeText(sf + ".key", key)
        let sig = signer(prog)
        if let old = readText(sf), !old.isEmpty, old != sig {
            alert("☠️ File chạy của dịch vụ \(label) đổi CHỮ KÝ\nFile: \(prog)\nTrước: \(old)\nBây giờ: \(sig)\n(cập nhật hợp lệ thường giữ nguyên nhà phát hành — đổi nhà phát hành / mất chữ ký là dấu hiệu bị tráo file)")
        }
        writeText(sf, sig)
    }
}
