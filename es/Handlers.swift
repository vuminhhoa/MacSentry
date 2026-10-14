import Foundation

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
        case "sshd", "sshd-session", "sudo", "su":
            return   // đã có sự kiện openssh_login / sudo / su riêng, chi tiết hơn
        case "login": source = "terminal (login)"
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
            if ssFails.count > 1000 { ssFails.removeAll() }   // dò mật khẩu từ rất nhiều IP: không giữ mãi
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

var sshFails: [String: Int] = [:]
func onSSHLogin(_ e: JSON) {
    let ip = str(e, "source_address") ?? "?"
    let user = str(e, "username") ?? "?"
    // Đăng nhập thành công: macsentryd đã báo (theo dõi `who`) → chỉ ghi log
    if (e["success"] as? Bool) == true { spool(.log, "SSH đăng nhập thành công: \(user) từ \(ip)"); return }
    if sshFails.count > 1000 { sshFails.removeAll() }   // dò mật khẩu từ rất nhiều IP: không giữ mãi
    sshFails[ip, default: 0] += 1
    guard throttle("sshfail_\(ip)", 300) else { spool(.log, "SSH sai mật khẩu: \(user) từ \(ip) (lần \(sshFails[ip]!))"); return }
    let n = sshFails[ip]!; sshFails[ip] = 0
    spool(.alert, """
        🔐 SSH đăng nhập THẤT BẠI\(n > 1 ? " (\(n) lần — có thể đang DÒ MẬT KHẨU)" : "")
        User: \(user)
        IP: \(ip)
        (các lần lặp lại từ IP này trong 5 phút được gom lại)
        """)
}

/// sudo / su: thất bại → cảnh báo; thành công → tin im lặng (như macsentryd làm trước đây với log stream)
func onSudo(_ e: JSON, _ msg: JSON, kind: String) {
    // Lệnh do chính MacSentry chạy (`sudo -u <user> sysadminctl -screenLock status` để đọc cài đặt khoá màn hình).
    // Không dựa vào chuỗi tiến trình cha: sudo và subshell gọi nó đã thoát khi sự kiện tới. macsentryd chạm file
    // expect_sudo ngay trước khi gọi → sudo từ root trong vài giây sau đó là của nó.
    let fromRoot = str(e, "from_username") == "root" || int(e, "from_uid") == 0
    if fromRoot, let m = (try? FileManager.default.attributesOfItem(atPath: stateDir + "/expect_sudo"))?[.modificationDate] as? Date,
       Date().timeIntervalSince(m) < 15 { return }
    let from = str(e, "from_username") ?? str(e, "from_uid") ?? "?"
    let to = str(e, "to_username") ?? str(e, "to_uid") ?? "root"
    let cmd = String((str(e, "command") ?? "").prefix(300))
    if (e["success"] as? Bool) == false {
        let why = str(e, "reject_info", "failure_message") ?? str(e, "failure_message") ?? deepStr(e, "failure_message") ?? "?"
        // `sudo -n` khi chưa nhập mật khẩu (công cụ tự kiểm tra quyền) → chỉ ghi log
        if why.localizedCaseInsensitiveContains("password is required") {
            spool(.log, "\(kind) -n bị từ chối (chưa nhập mật khẩu): \(from) → \(to) \(cmd)"); return
        }
        let notAllowed = why.localizedCaseInsensitiveContains("not in the sudoers") || why.localizedCaseInsensitiveContains("not allowed")
        guard throttle("\(kind)fail_\(from)_\(cmd.prefix(80))", 30) else { return }
        spool(.alert, "\(notAllowed ? "⛔️ \(kind) bị TỪ CHỐI (không có quyền)" : "🔐 \(kind) nhập sai mật khẩu")\nUser: \(from) → \(to)\nLệnh: \(cmd.isEmpty ? "?" : cmd)\nLý do: \(why)")
    } else {
        guard throttle("\(kind)_\(from)_\(cmd.prefix(120))", 10) else { return }
        spool(.info, "⚡️ \(kind): \(from) → \(to)\(cmd.isEmpty ? "" : "\n\(cmd)")")
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


/// Mục tự khởi động đăng ký qua Background Task Management (LaunchAgent/Daemon, Login Item, SMAppService).
/// Mục "legacy" (plist trong LaunchAgents/LaunchDaemons) macsentryd đã báo kèm chữ ký file chạy → ở đây chỉ ghi
/// log ai đã cài; mục KHÔNG legacy (Login Item / SMAppService) trước đây chỉ thấy qua `sfltool` mỗi giờ → báo ngay.
let btmTypes = [0: "mục của user", 1: "app", 2: "Login Item", 3: "LaunchAgent", 4: "LaunchDaemon"]
func onBTM(_ e: JSON, _ msg: JSON, add: Bool) {
    let item = dict(e, "item")
    let kind = int(item, "item_type").flatMap { btmTypes[$0] } ?? "?"
    let url = str(item, "item_url") ?? "?"
    let exe = str(e, "executable_path") ?? str(item, "app_url") ?? "?"
    let who = dict(e, "instigator") ?? dict(msg, "process")
    let legacy = (item?["legacy"] as? Bool) == true
    guard add else {
        spool(.info, "🧩 Đã gỡ mục tự khởi động (\(kind)): \(url)")
        return
    }
    if legacy {
        spool(.log, "BTM: mục tự khởi động (\(kind)) \(url) — chạy \(exe) — cài bởi \(describe(who).replacingOccurrences(of: "\n", with: " "))")
        return
    }
    spool(.alert, """
        🧩 Mục tự khởi động MỚI (\(kind))
        Mục: \(url)
        Chạy: \(exe)\(str(item, "app_url").map { "\nThuộc app: \($0)" } ?? "")
        Cài bởi: \(describe(who))
        """)
}

func onProfile(_ e: JSON, _ msg: JSON, add: Bool) {
    let p = dict(e, "profile")
    let id = str(p, "identifier") ?? "?"
    // Profile Screen Time (com.apple.ManagedSettings.*): macOS tự tạo/xoá khi đổi cài đặt Screen Time
    if id.hasPrefix("com.apple.ManagedSettings.") { spool(.log, "Profile Screen Time \(add ? "thêm" : "gỡ"): \(id)"); return }
    let name = [str(p, "display_name"), str(p, "organization")].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " — ")
    if !add { spool(.info, "📜 Đã gỡ configuration profile: \(id)\(name.isEmpty ? "" : " (\(name))")"); return }
    let update = (e["is_update"] as? Bool) == true
    spool(.alert, """
        📜 Configuration profile \(update ? "được CẬP NHẬT" : "MỚI"): \(id)
        Tên: \(name.isEmpty ? "?" : name) | Phạm vi: \(str(p, "scope") ?? "?")
        Cài bởi: \(describe(dict(e, "instigator") ?? dict(msg, "process")))
        (profile có thể ép proxy, chứng chỉ, quản lý máy từ xa)
        """)
}

/// Tài khoản / nhóm (Open Directory). Chỉ báo khi thao tác thành công (error_code 0).
func onOD(_ type: String, _ e: JSON, _ msg: JSON) {
    guard int(e, "error_code") == 0 else { return }
    let who = describe(dict(e, "instigator") ?? dict(msg, "process"))
    let group = str(e, "group_name") ?? "?"
    let member = deepStr(dict(e, "member"), "name") ?? deepStr(dict(e, "member"), "uuid") ?? "?"
    switch type {
    case "od_create_user": spool(.alert, "👥 Có tài khoản user MỚI: \(str(e, "user_name") ?? "?")\nTạo bởi: \(who)")
    case "od_delete_user": spool(.alert, "👥 Đã XOÁ tài khoản user: \(str(e, "user_name") ?? "?")\nXoá bởi: \(who)")
    case "od_group_add" where group == "admin": spool(.alert, "👑 \(member) vừa được cấp quyền ADMIN\nCấp bởi: \(who)")
    case "od_group_remove" where group == "admin": spool(.info, "👑 \(member) bị gỡ quyền admin\nBởi: \(who)")
    case "od_group_set" where group == "admin": spool(.alert, "👑 Danh sách nhóm ADMIN vừa bị ĐẶT LẠI\nBởi: \(who)")
    default: spool(.log, "OD \(type): nhóm \(group), thành viên \(member) — \(who.replacingOccurrences(of: "\n", with: " "))")
    }
}

func onEvent(_ type: String, _ e: JSON, _ msg: JSON) {
    switch type {
    case "authentication": onAuthentication(e, msg)
    case "screensharing_attach": onScreenSharing(e, attach: true)
    case "screensharing_detach": onScreenSharing(e, attach: false)
    case "tcc_modify": onTCC(e, msg)
    case "exec": onExec(e, msg)
    case "openssh_login": onSSHLogin(e)
    case "sudo": onSudo(e, msg, kind: "sudo")
    case "su": onSudo(e, msg, kind: "su")
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
    case "btm_launch_item_add": onBTM(e, msg, add: true)
    case "btm_launch_item_remove": onBTM(e, msg, add: false)
    case "profile_add": onProfile(e, msg, add: true)
    case "profile_remove": onProfile(e, msg, add: false)
    case "od_create_user", "od_delete_user", "od_group_add", "od_group_remove", "od_group_set": onOD(type, e, msg)
    case "kextload":
        spool(.alert, "🧷 Nạp kernel extension: \(str(e, "identifier") ?? "?")\nTiến trình: \(describe(dict(msg, "process")))")
    default: break
    }
}
