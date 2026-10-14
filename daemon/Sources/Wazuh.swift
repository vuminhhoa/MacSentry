import Foundation

// MARK: - Wazuh agent: tiến trình, kết nối manager, cấu hình, active response; phân việc giám sát toàn vẹn file
// Wazuh chạy bằng root và nhận lệnh từ manager: theo dõi agent còn chạy, kết nối tới đâu, cấu hình có bị đổi (kể cả
// cấu hình manager đẩy xuống), manager có chạy lệnh / active response trên máy không.

let wz = env["WAZUH_DIR"] ?? "/Library/Ossec"   // đổi được khi chạy thử
var wazuhProcs: Set<String> = []
var wazuhConnected = false

// MARK: Phân việc FIM: file nào Wazuh syscheck đã theo dõi THỜI GIAN THỰC thì để Wazuh lo (báo về manager/SIEM)

private struct WazuhFIM { var dirs: [String] = []; var ignore: [String] = []; var ignoreRe: [NSRegularExpression] = [] }
private var fim = WazuhFIM(), fimSig = ""

private func normPath(_ p: String) -> String {
    for (a, b) in [("/private/etc", "/etc"), ("/private/var", "/var"), ("/private/tmp", "/tmp")] where p == a || p.hasPrefix(a + "/") {
        return b + p.dropFirst(a.count)
    }
    return p
}

/// Đọc các khối <syscheck> của ossec.conf. Chỉ tính thư mục có realtime="yes" / whodata="yes" (quét định kỳ mặc
/// định 12 giờ/lần — chậm hơn nhiều so với MacSentry, nên vẫn tự theo dõi) và không có `restrict`.
private func loadFIM() {
    let conf = "\(wz)/etc/ossec.conf"
    var st = stat()
    let sig = stat(conf, &st) == 0 ? "\(st.st_ctimespec.tv_sec) \(st.st_size)" : ""
    guard sig != fimSig else { return }
    fimSig = sig
    fim = WazuhFIM()
    guard let text = readText(conf) else { return }
    var rest = Substring(text)
    while let s = rest.range(of: "<syscheck>"), let e = rest.range(of: "</syscheck>", range: s.upperBound..<rest.endIndex) {
        let block = String(rest[s.upperBound..<e.lowerBound]).replacingOccurrences(of: #"<!--[\s\S]*?-->"#, with: "", options: .regularExpression)
        rest = rest[e.upperBound...]
        if block.range(of: #"<disabled>\s*yes\s*</disabled>"#, options: .regularExpression) != nil { continue }
        let tag = try! NSRegularExpression(pattern: #"<(directories|ignore)([^>]*)>([^<]*)</\1>"#)
        for m in tag.matches(in: block, range: NSRange(block.startIndex..., in: block)) {
            let name = String(block[Range(m.range(at: 1), in: block)!]), attrs = String(block[Range(m.range(at: 2), in: block)!])
            let value = String(block[Range(m.range(at: 3), in: block)!]).trimmingCharacters(in: .whitespacesAndNewlines)
            if name == "directories" {
                guard attrs.range(of: #"(realtime|whodata)\s*=\s*"yes""#, options: .regularExpression) != nil, !attrs.contains("restrict") else { continue }
                fim.dirs += value.split(separator: ",").map { normPath($0.trimmingCharacters(in: .whitespaces)) }.filter { !$0.isEmpty }
            } else if attrs.contains("sregex") {
                if let re = try? NSRegularExpression(pattern: value) { fim.ignoreRe.append(re) }
            } else {
                fim.ignore.append(normPath(value))
            }
        }
    }
}

/// true nếu Wazuh đang theo dõi thời gian thực file này và Wazuh đang khoẻ (syscheckd chạy, kết nối manager)
func wazuhFIMCovers(_ path: String) -> Bool {
    guard config.fim == "auto", exists(wz), wazuhProcs.contains("wazuh-syscheckd"), wazuhConnected else { return false }
    loadFIM()
    let p = normPath(path)
    func under(_ d: String) -> Bool { p == d || p.hasPrefix(d.hasSuffix("/") ? d : d + "/") }
    guard fim.dirs.contains(where: under) else { return false }
    if fim.ignore.contains(where: under) { return false }
    if fim.ignoreRe.contains(where: { $0.firstMatch(in: p, range: NSRange(p.startIndex..., in: p)) != nil }) { return false }
    return true
}

// MARK: Giám sát Wazuh

func checkWazuh(_ procs: [Proc]) {
    guard exists(wz) else { return }
    let first = !exists(sp("wazuh_posture"))

    // Tiến trình: dừng tiến trình nào cũng báo (tắt EDR là bước đầu của kẻ tấn công)
    let names: Set<String> = ["wazuh-agentd", "wazuh-execd", "wazuh-syscheckd", "wazuh-logcollector", "wazuh-modulesd"]
    wazuhProcs = Set(procs.map(\.name).filter(names.contains))
    let dp = diffState("wazuh_procs", Array(wazuhProcs))
    for p in dp.removed { alert("⚠️ Wazuh: tiến trình \(p) vừa DỪNG") }
    for p in dp.added { info("Wazuh: \(p) chạy lại") }

    // Kết nối tới manager (2 lần liên tiếp mất kết nối mới báo, tránh báo khi đổi mạng chớp nhoáng)
    let st = lines(readText("\(wz)/var/run/wazuh-agentd.state")).first { $0.hasPrefix("status=") }
        .map { $0.dropFirst(7).trimmingCharacters(in: CharacterSet(charactersIn: "'\"")) }
    if let st {
        wazuhConnected = st == "connected"
        let prev = readText(sp("wazuh_status")); writeText(sp("wazuh_status"), st)
        let sent = readText(sp("wazuh_status_sent"))
        if st == "disconnected", prev == "disconnected", sent != "disconnected" {
            writeText(sp("wazuh_status_sent"), "disconnected")
            if hasDefaultRoute() { alert("⚠️ Wazuh agent MẤT KẾT NỐI tới manager (máy vẫn có mạng)") }
            else { log("Wazuh mất kết nối (máy không có mạng)") }
        } else if st == "connected", sent == "disconnected" {
            writeText(sp("wazuh_status_sent"), "connected"); info("Wazuh agent đã kết nối lại manager")
        }
    }

    // Tư thế: manager là ai, có được chạy lệnh từ xa / active response không, phiên bản — chỉ tính lại khi cấu hình đổi
    let conf = "\(wz)/etc/ossec.conf", lio = "\(wz)/etc/local_internal_options.conf"
    var ver = ""
    if first || statChanged("wazuh_posture_src", [conf, lio, "\(wz)/bin/wazuh-control"]) {
        let c = readText(conf) ?? ""
        let mgr = c.matches(#"<address>(.*?)</address>"#).joined(separator: " ")
        let rcmd = lines(readText(lio)).filter { $0.replacingOccurrences(of: " ", with: "").range(of: #"^(logcollector|wazuh_command|sca)\.remote_commands=1"#, options: .regularExpression) != nil }
            .map { $0.replacingOccurrences(of: " ", with: "") }.joined(separator: " ")
        var ar = "BẬT", inAR = false
        for l in lines(c) {
            if l.contains("<active-response>") { inAR = true }
            if inAR && l.contains("<disabled>yes</disabled>") { ar = "TẮT" }
            if l.contains("</active-response>") { inAR = false }
        }
        ver = lines(readText("\(wz)/etc/ossec-init.conf")).first { $0.hasPrefix("WAZUH_VERSION=") }
            .map { $0.dropFirst(14).trimmingCharacters(in: CharacterSet(charactersIn: "\"")) }
            ?? run("\(wz)/bin/wazuh-control", ["info", "-v"]).trimmingCharacters(in: .whitespacesAndNewlines)
        let wp = """
            Wazuh manager: \(mgr.isEmpty ? "?" : mgr)
            Wazuh cho manager chạy lệnh từ xa: \(rcmd.isEmpty ? "không" : "BẬT (\(rcmd)) ⚠️")
            Wazuh active response (manager chạy script trên máy): \(ar)
            Wazuh phiên bản: \(ver.isEmpty ? "?" : ver)
            """
        writeText(sp("wazuh_now"), wp + "\n")
        let d = diffState("wazuh_posture", lines(wp))
        if first {
            info("🐺 Bắt đầu giám sát Wazuh agent\n\(wp)\nTiến trình đang chạy: \(wazuhProcs.sorted().joined(separator: " "))")
        } else {
            for v in d.added {
                if v.hasPrefix("Wazuh manager:") { alert("🐺 Wazuh ĐỔI máy chủ quản lý → \(v)") }
                else if v.contains("⚠️") { alert("🐺 \(v)") } else { info("🐺 \(v)") }
            }
        }
    }
    if ver.isEmpty { ver = lines(readText(sp("wazuh_now"))).first { $0.hasPrefix("Wazuh phiên bản: ") }.map { String($0.dropFirst(17)) } ?? "?" }

    // File cấu hình (agent.conf = cấu hình manager đẩy xuống) — kèm nội dung đổi; client.keys chỉ báo, không gửi nội dung
    try? FileManager.default.createDirectory(atPath: sp("files"), withIntermediateDirectories: true)
    let wfiles = glob([conf, lio, "\(wz)/etc/internal_options.conf", "\(wz)/etc/shared/agent.conf", "\(wz)/etc/client.keys",
                       "/Library/LaunchDaemons/com.wazuh.agent.plist", "/Library/StartupItems/WAZUH/*"])
    if statChanged("wazuh_cfg", wfiles) {
        for (kind, f) in hashChanges("wazuh_cfg", wfiles) {
            let copy = copyOf(f), keys = f.hasSuffix("/client.keys")
            if keys { alert("🐺 Khoá đăng ký Wazuh (client.keys) \(kind.rawValue) — agent có thể đã được đăng ký lại với manager khác") }
            else {
                switch kind {
                case .removed: alert("🐺 File cấu hình Wazuh bị XOÁ: \(f)")
                case .new: info("🐺 File cấu hình Wazuh mới: \(f)\n\(headLines(f, 15))")
                case .changed: alert("🐺 Cấu hình Wazuh THAY ĐỔI: \(f)\n\(lineDiff(readText(copy) ?? "", readText(f) ?? "", limit: 20))\n(< dòng cũ, > dòng mới)")
                }
                try? FileManager.default.removeItem(atPath: copy)
                if kind != .removed { try? FileManager.default.copyItem(atPath: f, toPath: copy) }
            }
        }
    }
    // Lần đầu: lưu bản sao để lần sau có nội dung so sánh
    for f in wfiles where !f.hasSuffix("/client.keys") && !exists(copyOf(f)) { try? FileManager.default.copyItem(atPath: f, toPath: copyOf(f)) }

    // File thực thi và script active response bị thay (cập nhật Wazuh hợp lệ cũng báo, kèm phiên bản)
    let wbins = glob(["\(wz)/bin/*", "\(wz)/active-response/bin/*"])
    if statChanged("wazuh_bin", wbins) {
        for (kind, f) in hashChanges("wazuh_bin", wbins) {
            if f.contains("/active-response/bin/") {
                alert("🐺 Script active response của Wazuh \(kind.rawValue): \(f)\n(script này chạy bằng root khi manager ra lệnh)")
            } else if throttle("wazuh_bin", 600) {
                info("🐺 File thực thi Wazuh \(kind.rawValue): \(f) (phiên bản: \(ver))\n(thường do cập nhật Wazuh; nhiều file đổi cùng lúc chỉ báo 1 lần)")
            }
        }
    }

    // Manager vừa chạy active response trên máy
    let ar = lines(tailNew("wazuh_ar", "\(wz)/logs/active-responses.log")).suffix(10).map { String($0.prefix(250)) }
    if !ar.isEmpty { alert("⚡️ Wazuh manager vừa chạy ACTIVE RESPONSE trên máy (bằng root)\n\(ar.joined(separator: "\n"))") }

    // Log của agent: đổi cấu hình từ manager, nâng cấp từ xa, lệnh từ xa, lỗi nghiêm trọng
    let ol = lines(tailNew("wazuh_ossec", "\(wz)/logs/ossec.log"))
        .filter { $0.range(of: #"CRITICAL|restarting due to|[Uu]pgrade|WPK|[Rr]emote command|wazuh-modulesd:command|logcollector.*command"#, options: .regularExpression) != nil }
        .suffix(10).map { String($0.prefix(250)) }
    if !ol.isEmpty { info("🐺 Wazuh agent log:\n\(ol.joined(separator: "\n"))") }
}

extension String {
    /// Nhóm bắt thứ nhất của mọi lần khớp
    func matches(_ pattern: String) -> [String] {
        guard let re = try? NSRegularExpression(pattern: pattern) else { return [] }
        return re.matches(in: self, range: NSRange(startIndex..., in: self)).compactMap { Range($0.range(at: 1), in: self).map { String(self[$0]) } }
    }
}
