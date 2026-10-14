import Foundation

// MARK: - Thông tin tiến trình (dùng chung cho macsentryd và macsentry-es)
// Đọc qua libproc / sysctl — không fork `ps` / `lsof`.

struct ProcInfo {
    let pid: Int32
    let name: String   // tên của kernel (pbi_name, tối đa 32 ký tự)
    let ppid: Int
    let uid: Int
    let start: Date
}

/// Thông tin cơ bản của tiến trình (nil nếu đã thoát / không đọc được)
func procBSD(_ pid: Int32) -> ProcInfo? {
    var info = proc_bsdinfo()
    let size = Int32(MemoryLayout<proc_bsdinfo>.size)
    guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
    // pbi_name (32 ký tự) đầy đủ hơn pbi_comm (16 ký tự)
    var name = withUnsafeBytes(of: info.pbi_name) { String(cString: $0.bindMemory(to: CChar.self).baseAddress!) }
    if name.isEmpty { name = withUnsafeBytes(of: info.pbi_comm) { String(cString: $0.bindMemory(to: CChar.self).baseAddress!) } }
    return ProcInfo(pid: pid, name: name, ppid: Int(info.pbi_ppid), uid: Int(info.pbi_uid),
                    start: Date(timeIntervalSince1970: TimeInterval(info.pbi_start_tvsec)))
}

/// Tên ngắn và pid cha của tiến trình (nil nếu đã thoát)
func procInfo(_ pid: Int) -> (name: String, ppid: Int)? {
    procBSD(Int32(pid)).map { ($0.name, $0.ppid) }
}

/// Mọi pid đang chạy
func allPids() -> [Int32] {
    let n = proc_listallpids(nil, 0)
    guard n > 0 else { return [] }
    var pids = [Int32](repeating: 0, count: Int(n) + 64)
    let got = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<Int32>.size))
    return pids.prefix(Int(max(got, 0))).filter { $0 > 0 }
}

/// Đường dẫn file thực thi
func procPath(_ pid: Int32) -> String? {
    var buf = [CChar](repeating: 0, count: 4096)
    guard proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 else { return nil }
    return String(cString: buf)
}

/// Dòng lệnh đầy đủ (argv) của tiến trình, đọc từ KERN_PROCARGS2: [argc][đường dẫn exec]\0…\0[argv0]\0[argv1]\0…
func procArgs(_ pid: Int) -> String { procArgv(pid).joined(separator: " ") }

func procArgv(_ pid: Int) -> [String] {
    var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, Int32(pid)]
    var size = 0
    guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 4 else { return [] }
    var buf = [UInt8](repeating: 0, count: size)
    guard sysctl(&mib, 3, &buf, &size, nil, 0) == 0 else { return [] }
    let argc = buf.withUnsafeBytes { $0.load(as: Int32.self) }
    var i = 4
    while i < size && buf[i] != 0 { i += 1 }   // bỏ đường dẫn exec
    while i < size && buf[i] == 0 { i += 1 }   // và phần đệm
    var args: [String] = []
    while args.count < argc && i < size {
        var j = i
        while j < size && buf[j] != 0 { j += 1 }
        args.append(String(decoding: buf[i..<j], as: UTF8.self))
        i = j + 1
    }
    return args
}

func userName(_ uid: Int) -> String {
    guard let pw = getpwuid(uid_t(uid)) else { return "\(uid)" }
    return String(cString: pw.pointee.pw_name)
}

func base(_ s: String) -> String { (s as NSString).lastPathComponent }

/// Chuỗi tiến trình cha (tên(pid) ← …), tối đa 6 cấp, kèm dòng lệnh đầy đủ của từng cấp (để nhận diện
/// tiến trình con của macsentryd: phải nhìn dòng lệnh mới thấy "macsentryd")
func ancestry(_ start: Int?) -> (text: String, commands: [String]) {
    guard var p = start else { return ("?", []) }
    var parts: [String] = [], cmds: [String] = []
    for _ in 0..<6 {
        guard let info = procInfo(p) else { break }
        // Tên hiển thị theo argv[0] giống `ps` (vd Claude Code: argv[0] "claude", còn tên file thực thi là
        // số phiên bản "2.1.296"); không đọc được argv (tiến trình của user khác...) thì dùng tên của kernel
        let argv = procArgv(p)
        let name = argv.first.map { base($0) }.flatMap { $0.isEmpty ? nil : $0 } ?? info.name
        parts.append("\(name)(\(p))")
        cmds.append(argv.joined(separator: " "))
        if info.ppid <= 1 { break }
        p = info.ppid
    }
    return (parts.isEmpty ? "?" : parts.joined(separator: " ← "), cmds)
}
func chain(_ start: Int?) -> String { ancestry(start).text }
