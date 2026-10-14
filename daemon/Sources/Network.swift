import Foundation

// MARK: - Socket TCP theo tiến trình (libproc — thay `lsof`), kết nối từ netstat, phiên đăng nhập (utmpx — thay `who`)

struct Sock {
    let pid: Int32, fd: Int32, name: String
    let listen: Bool, established: Bool
    let lAddr: String, lPort: Int, rAddr: String, rPort: Int
}

private func ntop(_ ini: in_sockinfo, local: Bool) -> String {
    var buf = [CChar](repeating: 0, count: 64)
    // insi_laddr / insi_faddr là 2 kiểu union khác tên trong Swift → lấy riêng từng trường
    var v4 = local ? ini.insi_laddr.ina_46.i46a_addr4 : ini.insi_faddr.ina_46.i46a_addr4
    var v6 = local ? ini.insi_laddr.ina_6 : ini.insi_faddr.ina_6
    if ini.insi_vflag & UInt8(INI_IPV4) != 0 { inet_ntop(AF_INET, &v4, &buf, 64) } else { inet_ntop(AF_INET6, &v6, &buf, 64) }
    return String(cString: buf)
}

/// Socket TCP của các tiến trình (lọc theo tên nếu có `names`, để chỉ đọc fd của tiến trình cần xem)
func tcpSockets(_ procs: [Proc], names: ((String) -> Bool)? = nil) -> [Sock] {
    var out: [Sock] = []
    let fdSize = MemoryLayout<proc_fdinfo>.stride, siSize = Int32(MemoryLayout<socket_fdinfo>.size)
    for p in procs where names?(p.name) ?? true {
        let sz = proc_pidinfo(p.pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard sz > 0 else { continue }
        var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: Int(sz) / fdSize + 16)
        let got = proc_pidinfo(p.pid, PROC_PIDLISTFDS, 0, &fds, Int32(fds.count * fdSize))
        guard got > 0 else { continue }
        for f in fds.prefix(Int(got) / fdSize) where f.proc_fdtype == UInt32(PROX_FDTYPE_SOCKET) {
            var si = socket_fdinfo()
            guard proc_pidfdinfo(p.pid, f.proc_fd, PROC_PIDFDSOCKETINFO, &si, siSize) == siSize,
                  si.psi.soi_kind == Int32(SOCKINFO_TCP) else { continue }
            let t = si.psi.soi_proto.pri_tcp, ini = t.tcpsi_ini
            out.append(Sock(pid: p.pid, fd: f.proc_fd, name: p.name,
                            listen: t.tcpsi_state == TSI_S_LISTEN, established: t.tcpsi_state == TSI_S_ESTABLISHED,
                            lAddr: ntop(ini, local: true), lPort: Int(UInt16(bigEndian: UInt16(truncatingIfNeeded: ini.insi_lport))),
                            rAddr: ntop(ini, local: false), rPort: Int(UInt16(bigEndian: UInt16(truncatingIfNeeded: ini.insi_fport)))))
        }
    }
    return out
}
func isLoopback(_ a: String) -> Bool { a.hasPrefix("127.") || a == "::1" || a.hasPrefix("::ffff:127.") }

/// Cổng của các dịch vụ truy cập từ xa (khớp với remoteServices trong app)
let remotePorts: [Int: String] = [22: "SSH", 5900: "Screen Sharing/VNC", 3283: "Apple Remote Desktop",
                                  445: "Chia sẻ file SMB", 548: "AFP", 3031: "Remote Apple Events"]
func portName(_ p: Int) -> String { remotePorts[p] ?? "cổng \(p)" }

/// Bảng kết nối TCP của kernel (`netstat`): thấy cả socket không thuộc tiến trình nào (dịch vụ trong kernel, socket
/// launchd giữ hộ sshd), nên dùng cho kết nối từ xa. Một lần fork mỗi lượt, định dạng ổn định nhiều năm.
struct NetstatRow { let state: String; let lPort: Int; let remote: String }   // remote: "addr.port" như netstat
func netstat() -> [NetstatRow] {
    lines(run("/usr/sbin/netstat", ["-an", "-p", "tcp"], timeout: 10)).compactMap { l in
        let c = l.split(separator: " ", omittingEmptySubsequences: true)
        guard c.count >= 6, c[0].hasPrefix("tcp"), let dot = c[3].lastIndex(of: "."), let port = Int(c[3][c[3].index(after: dot)...])
        else { return nil }
        return NetstatRow(state: String(c[5]), lPort: port, remote: String(c[4]))
    }
}

/// Kết nối / cổng lắng nghe của dịch vụ truy cập từ xa: gộp netstat (thấy socket của kernel) và libproc (netstat có
/// thể bị macOS ẩn socket khi gọi từ binary không phải của Apple). Địa chỉ xa dạng "addr.port" như netstat, bỏ "%scope".
struct RemoteView { var established: Set<String> = []; var listening: Set<Int> = [] }
func remoteView(_ ns: [NetstatRow], _ socks: [Sock]) -> RemoteView {
    var v = RemoteView()
    func norm(_ addrPort: String) -> String {
        guard let dot = addrPort.lastIndex(of: ".") else { return addrPort }
        var a = String(addrPort[..<dot]); if let pct = a.firstIndex(of: "%") { a = String(a[..<pct]) }
        return "\(a).\(addrPort[addrPort.index(after: dot)...])"
    }
    for r in ns where remotePorts[r.lPort] != nil {
        if r.state == "ESTABLISHED" { v.established.insert("\(r.lPort) \(norm(r.remote))") }
        if r.state == "LISTEN" { v.listening.insert(r.lPort) }
    }
    for s in socks where remotePorts[s.lPort] != nil {
        if s.established { v.established.insert("\(s.lPort) \(s.rAddr).\(s.rPort)") }
        if s.listen { v.listening.insert(s.lPort) }
    }
    return v
}

/// Phiên đăng nhập từ xa (utmpx): "user tty (host)" — bỏ phiên tmux/screen, X11 (host bắt đầu bằng ":")
func remoteLogins() -> [String] {
    var out: [String] = []
    setutxent()
    while let u = getutxent() {
        guard u.pointee.ut_type == USER_PROCESS else { continue }
        func s<T>(_ v: T) -> String { withUnsafeBytes(of: v) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) } }
        let host = s(u.pointee.ut_host)
        guard !host.isEmpty, !host.hasPrefix(":"), !host.contains("tmux") else { continue }
        out.append("\(s(u.pointee.ut_user)) \(s(u.pointee.ut_line)) (\(host))")
    }
    endutxent()
    return out
}
