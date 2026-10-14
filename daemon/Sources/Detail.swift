import Foundation
import Security

// MARK: - Chi tiết giúp phân biệt cảnh báo thật / giả: chữ ký số, tiến trình, IP, máy chủ tin cậy

/// Chữ ký số của file thực thi / app (Security framework, không fork `codesign`)
func signer(_ path: String?) -> String {
    guard let path, !path.isEmpty, exists(path) else { return "? (không tìm thấy file)" }
    var code: SecStaticCode?
    guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, let code else { return "?" }
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
          let d = info as? [String: Any] else { return "?" }
    guard d[kSecCodeInfoIdentifier as String] != nil else { return "⚠️ KHÔNG có chữ ký số" }
    let team = d[kSecCodeInfoTeamIdentifier as String] as? String
    guard let leaf = (d[kSecCodeInfoCertificates as String] as? [SecCertificate])?.first,
          let auth = SecCertificateCopySubjectSummary(leaf) as String? else { return "⚠️ ký ad-hoc (không rõ nhà phát hành)" }
    if auth == "Software Signing" || auth == "macOS Software Signing" { return "✅ Apple (thành phần hệ thống)" }
    if let team, !auth.contains("(\(team))") { return "\(auth) (Team \(team))" }
    return auth
}

/// Mô tả tiến trình: dòng lệnh, user, thời điểm chạy, chuỗi tiến trình cha, chữ ký số
func procDetail(_ pid: Int32) -> String {
    guard let p = procBSD(pid) else { return "(tiến trình \(pid) đã kết thúc trước khi kịp ghi chi tiết)" }
    let argv = procArgs(Int(pid))
    let exe = procPath(pid)
    let parents = p.ppid > 1 ? chain(p.ppid) : "launchd"
    return """
        Lệnh: \((argv.isEmpty ? p.name : argv).prefix(300))
        User: \(userName(p.uid)) | Chạy từ: \(timeFmt.string(from: p.start))
        Tiến trình cha: \(parents)
        File chạy: \(exe ?? "?") — \(signer(exe))
        """
}

/// Tên miền (reverse DNS) và chủ sở hữu IP (whois) — có thể mất vài giây → chỉ gọi trên slowQ
func ipInfo(_ ip: String) -> String {
    let priv = ["10.", "192.168.", "fe80:", "fd"] + (16...31).map { "172.\($0)." } + (64...127).map { "100.\($0)." }
    if priv.contains(where: ip.hasPrefix) { return "IP mạng nội bộ / Tailscale" }
    var name = "không có"
    var hints = addrinfo(ai_flags: AI_NUMERICHOST, ai_family: AF_UNSPEC, ai_socktype: 0, ai_protocol: 0,
                         ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
    var res: UnsafeMutablePointer<addrinfo>?
    if getaddrinfo(ip, nil, &hints, &res) == 0, let r = res {
        var host = [CChar](repeating: 0, count: 1025)
        if getnameinfo(r.pointee.ai_addr, r.pointee.ai_addrlen, &host, 1025, nil, 0, NI_NAMEREQD) == 0 { name = String(cString: host) }
        freeaddrinfo(r)
    }
    var org = "", country = ""
    for l in lines(run("/usr/bin/whois", [ip], timeout: 8)) {
        let parts = l.split(separator: ":", maxSplits: 1)
        guard parts.count == 2 else { continue }
        let k = parts[0].lowercased().trimmingCharacters(in: .whitespaces), v = parts[1].trimmingCharacters(in: .whitespaces)
        if org.isEmpty, ["orgname", "org-name", "descr", "netname"].contains(k) { org = v }
        if country.isEmpty, k == "country" { country = v }
    }
    return "Tên miền: \(name) | Chủ IP: \(org.isEmpty ? "không rõ" : org)\(country.isEmpty ? "" : ", \(country)")"
}

/// Gửi cảnh báo kèm thông tin IP (tra whois trên slowQ, không chặn hàng đợi chính)
func alertWithIP(_ msg: String, _ ip: String, tail: String = "") {
    slowQ.async {
        let i = ipInfo(ip)
        q.async { alert("\(msg)\n\(i)\(tail)") }
    }
}

// MARK: - Máy chủ tin cậy (/etc/macsentry.trusted, dạng "tên-miền:cổng" hoặc "tên-miền"): phân giải thành (ip, cổng)

var trusted: [(ip: String, port: String, name: String)] = []
func resolveTrusted() {
    var out: [(String, String, String)] = []
    for raw in lines(readText(trustedPath)) {
        let entry = (raw.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? "")
            .trimmingCharacters(in: .whitespaces)
        guard !entry.isEmpty else { continue }
        let parts = entry.split(separator: ":", maxSplits: 1).map(String.init)
        let h = parts[0], port = parts.count > 1 ? parts[1] : "*"
        var res: UnsafeMutablePointer<addrinfo>?
        var ips: [String] = []
        if getaddrinfo(h, nil, nil, &res) == 0 {
            var p = res
            while let a = p {
                var buf = [CChar](repeating: 0, count: 64)
                if getnameinfo(a.pointee.ai_addr, a.pointee.ai_addrlen, &buf, 64, nil, 0, NI_NUMERICHOST) == 0 { ips.append(String(cString: buf)) }
                p = a.pointee.ai_next
            }
            freeaddrinfo(res)
        }
        for ip in Set(ips.isEmpty ? [h] : ips) { out.append((ip, port, h)) }
    }
    trusted = out
}
func trustedName(_ ip: String, _ port: Int) -> String? {
    trusted.first { $0.ip == ip && ($0.port == "*" || $0.port == String(port)) }?.name
}

// MARK: - Bảng tiến trình (một lần mỗi lượt, dùng chung cho các kiểm tra)

struct Proc { let pid: Int32; let name: String; let path: String? }
/// Tên tiến trình: tên file thực thi (giống `ps -o comm` rồi lấy basename), không đọc được thì tên của kernel
func processes() -> [Proc] {
    allPids().compactMap { pid in
        guard let b = procBSD(pid) else { return nil }
        let path = procPath(pid)
        return Proc(pid: pid, name: path.map(base) ?? b.name, path: path)
    }
}
func running(_ name: String, in procs: [Proc]) -> Bool { procs.contains { $0.name == name } }
