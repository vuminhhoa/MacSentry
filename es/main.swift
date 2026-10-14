// macsentry-es — đọc sự kiện Endpoint Security qua /usr/bin/eslogger (chạy bằng root, LaunchDaemon riêng)
// và đẩy cảnh báo vào hàng đợi của macsentryd (/var/db/macsentry/spool). Không giữ token Telegram.
//
// Cần quyền Full Disk Access cho chính file này (/usr/local/libexec/macsentry-es): eslogger là tiến trình con
// nên macOS tính quyền theo tiến trình chịu trách nhiệm là helper này.
//
// Sự kiện theo dõi:
//   authentication          xác thực thất bại + CHÍNH XÁC tiến trình nào yêu cầu (thay cho đoán qua log)
//   screensharing_attach/…  có người xem / điều khiển màn hình qua Screen Sharing / ARD
//   tcc_modify              cấp quyền Accessibility, Ghi màn hình, Theo dõi bàn phím, Full Disk Access, camera, micro…
//   xp_malware_*            XProtect phát hiện / xử lý mã độc
//   gatekeeper_user_override  cho phép chạy app bị Gatekeeper chặn
//   od_modify_password      đổi mật khẩu tài khoản
//   kextload                nạp kernel extension
//   exec                    lệnh nguy hiểm: reverse shell, dump keychain, tắt bảo vệ, tắt giám sát, cài cửa hậu…

// Mã nguồn chia theo chủ đề: Spool, EventJSON, Processes, Rules, Handlers (thư mục es/).
import Foundation

let stateDir = ProcessInfo.processInfo.environment["STATE"] ?? "/var/db/macsentry"
let spoolDir = stateDir + "/spool"
let samplesDir = stateDir + "/es_samples"
/// ES_EXEC=0 trong /etc/macsentry.conf → bỏ theo dõi exec. exec là phần tốn nhất (~3% một nhân trên máy dev
/// nhiều tiến trình: eslogger phải tuần tự hoá mọi lần chạy chương trình thành JSON, kèm biến môi trường).
let execEnabled = !(((try? String(contentsOfFile: "/etc/macsentry.conf", encoding: .utf8)) ?? "")
    .split(separator: "\n").contains { $0.trimmingCharacters(in: .whitespaces) == "ES_EXEC=0" })
// sudo / su / openssh_login thay cho việc macsentryd đọc `log stream` (log stream tốn ~5% một nhân)
let events = ["authentication", "screensharing_attach", "screensharing_detach", "tcc_modify",
              "xp_malware_detected", "xp_malware_remediated", "gatekeeper_user_override",
              "od_modify_password", "kextload", "sudo", "su", "openssh_login"] + (execEnabled ? ["exec"] : [])

// MARK: - Chạy eslogger

var sampled: Set<String> = []
/// Lưu mẫu JSON đầu tiên của mỗi loại sự kiện (để đối chiếu định dạng khi cần sửa bộ đọc)
func sample(_ type: String, _ line: Data) {
    guard !sampled.contains(type) else { return }
    sampled.insert(type)
    FileManager.default.createFile(atPath: "\(samplesDir)/\(type).json", contents: line, attributes: [.posixPermissions: 0o600])
}

var lastAlive: time_t = 0
func handle(_ raw: UnsafeRawBufferPointer) {
    let now = time(nil)
    if now - lastAlive > 30 { touch(stateDir + "/es_alive"); lastAlive = now }
    if execIrrelevant(raw) { return }   // lọc trên buffer thô, chưa cấp phát gì
    let line = Data(raw)
    guard let msg = (try? JSONSerialization.jsonObject(with: line)) as? JSON,
          let ev = msg["event"] as? JSON, let type = ev.keys.first, let e = ev[type] as? JSON else { return }
    sample(type, line)
    onEvent(type, e, msg)
}

/// Đọc từng dòng bằng getline(3): đệm ở user space và tái dùng một buffer cho mọi dòng — nhanh hơn hàng chục lần
/// so với FileHandle.availableData + Data.removeSubrange (O(n) mỗi dòng) hay readLine() tạo String mỗi dòng
func forEachLine(fd: Int32, _ body: (UnsafeRawBufferPointer) -> Void) {
    guard let fp = fdopen(dup(fd), "r") else { return }   // dup: fclose không đóng fd của Pipe
    var line: UnsafeMutablePointer<CChar>? = nil
    var cap = 0
    defer { free(line); fclose(fp) }
    while true {
        var len = getline(&line, &cap, fp)
        if len < 0 { break }   // EOF / lỗi
        if len > 0 && line![len - 1] == 0x0A { len -= 1 }
        if len > 0 { body(UnsafeRawBufferPointer(start: line, count: len)) }
    }
}

for d in [spoolDir, samplesDir] { try? FileManager.default.createDirectory(atPath: d, withIntermediateDirectories: true) }
// Chạy thử không cần root: STATE=./thu-muc macsentry-es --replay < su-kien.jsonl
if CommandLine.arguments.contains("--replay") {
    forEachLine(fd: 0, handle)
    exit(0)
}
guard getuid() == 0 else { FileHandle.standardError.write(Data("macsentry-es cần chạy bằng root\n".utf8)); exit(1) }
signal(SIGTERM) { _ in exit(0) }   // launchd dừng helper: eslogger con nhận SIGTERM theo nhóm tiến trình

while true {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/eslogger")
    p.arguments = events
    // stderr ghi ra file (không dùng Pipe: không ai đọc trong lúc chạy → pipe đầy sẽ làm eslogger treo)
    let errPath = stateDir + "/eslogger.err"
    FileManager.default.createFile(atPath: errPath, contents: nil)
    let out = Pipe()
    p.standardOutput = out; p.standardError = FileHandle(forWritingAtPath: errPath)
    do { try p.run() } catch {
        writeStatus("Không chạy được /usr/bin/eslogger: \(error.localizedDescription)")
        sleep(60); continue
    }
    writeStatus("eslogger đang chạy (pid \(p.processIdentifier)) từ \(Date())")
    touch(stateDir + "/es_alive"); lastAlive = time(nil)

    // eslogger sống mà không có sự kiện nào (máy rảnh) vẫn phải được coi là còn sống
    let keepAlive = DispatchSource.makeTimerSource(queue: .global())
    keepAlive.schedule(deadline: .now() + 60, repeating: 60)
    keepAlive.setEventHandler { if p.isRunning { touch(stateDir + "/es_alive") } }
    keepAlive.resume()

    forEachLine(fd: out.fileHandleForReading.fileDescriptor, handle)   // trả về khi eslogger thoát (EOF)
    keepAlive.cancel()
    p.waitUntilExit()
    let why = ((try? String(contentsOfFile: errPath, encoding: .utf8)) ?? "")
        .trimmingCharacters(in: .whitespacesAndNewlines)
    let status = "eslogger dừng (mã \(p.terminationStatus)) lúc \(Date()): \(why.prefix(300))"
    writeStatus(why.localizedCaseInsensitiveContains("permit") || why.contains("TCC")
                ? status + "\n→ Chưa có Full Disk Access" : status)
    try? FileManager.default.removeItem(atPath: stateDir + "/es_alive")
    sleep(30)
}
