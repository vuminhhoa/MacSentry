import AppKit

// MARK: - Cài / cài lại macsentryd + macsentry-es ngay trong app: chạy daemon/install.sh --auto bằng quyền root
// qua hộp thoại mật khẩu của macOS (không mở Terminal, không hỏi gì thêm). Cấu hình cũ trong /etc được giữ.

final class DaemonInstaller: ObservableObject {
    static let shared = DaemonInstaller()
    /// Phiên bản app đã tự cài daemon — mỗi phiên bản chỉ tự hỏi mật khẩu một lần (người dùng huỷ thì thôi)
    private static let autoKey = "autoInstalledDaemonVersion"
    /// Daemon được cài khi app chưa có Telegram → lưu Telegram xong thì cài lại để daemon nhận token
    private static let noTokenKey = "daemonInstalledWithoutTelegram"

    @Published private(set) var running = false
    @Published private(set) var lastError: String?

    var installed: Bool { AppDelegate.watched.allSatisfy { FileManager.default.fileExists(atPath: $0.1) } }

    /// Bấm nút "Cài" trong Cài đặt / Tổng quan
    func install(done: ((Bool) -> Void)? = nil) {
        guard !running else { return }
        guard let dir = Updater.sourceDir else { lastError = L("Không tìm thấy thư mục mã nguồn"); done?(false); return }
        running = true; lastError = nil
        DispatchQueue.global(qos: .userInitiated).async {
            var err: String?
            if !Self.binariesBuilt(dir) {
                let r = Shell.run(dir + "/build.sh", ["--no-install"], in: dir)
                if !r.ok { err = L("Build lỗi: %@", r.tail) }
            }
            if err == nil { err = Self.runScript(dir) }
            DispatchQueue.main.async {
                self.running = false
                self.lastError = err
                done?(err == nil)
            }
        }
    }

    /// Lần đầu mở app (hoặc sau khi cập nhật) mà daemon chưa cài → tự cài, không chờ người dùng bấm
    func autoInstallIfNeeded() {
        guard Updater.sourceDir != nil, !installed,
              UserDefaults.standard.string(forKey: Self.autoKey) != Updater.currentVersion else { return }
        UserDefaults.standard.set(Updater.currentVersion, forKey: Self.autoKey)
        install()
    }

    /// Vừa lưu Telegram: daemon đang chạy không có token thì cài lại để nó dùng chung bot của app
    func telegramSaved() {
        guard UserDefaults.standard.bool(forKey: Self.noTokenKey), installed else { return }
        install()
    }

    static func binariesBuilt(_ dir: String) -> Bool {
        ["macsentryd", "macsentry-es"].allSatisfy { FileManager.default.isExecutableFile(atPath: "\(dir)/build/\($0)") }
    }

    /// Chạy install.sh bằng root (chặn tới khi xong — gọi từ luồng nền). Trả về lỗi, nil = thành công
    static func runScript(_ dir: String) -> String? {
        let user = NSUserName()
        let cmd = "SUDO_USER=\(Shell.quote(user)) \(Shell.quote(dir + "/daemon/install.sh")) --auto 2>&1"
        let source = "do shell script \"\(cmd.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\""))\""
            + " with prompt \"\(L("MacSentry cần quyền quản trị để cài daemon giám sát."))\" with administrator privileges"
        var err: NSDictionary?
        // NSAppleScript (không phải osascript) để hộp thoại mang tên MacSentry; do shell script không cần quyền Tự động hoá
        let out = NSAppleScript(source: source)?.executeAndReturnError(&err)
        if let err {
            if (err[NSAppleScript.errorNumber] as? Int) == -128 { return L("Đã huỷ") }
            return err[NSAppleScript.errorMessage] as? String ?? L("Cài daemon lỗi")
        }
        NSLog("MacSentry install.sh:\n\(out?.stringValue ?? "")")
        UserDefaults.standard.set(Telegram.config == nil, forKey: noTokenKey)
        return nil
    }
}

/// Chạy lệnh, gom stdout + stderr
enum Shell {
    struct Result { let ok: Bool; let output: String
        /// Vài dòng cuối — đủ để hiện lý do lỗi
        var tail: String { output.split(separator: "\n").suffix(3).joined(separator: "\n") }
    }

    static func run(_ path: String, _ args: [String], in dir: String) -> Result {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        p.currentDirectoryURL = URL(fileURLWithPath: dir)
        var env = ProcessInfo.processInfo.environment
        env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin"   // app chạy bởi launchd có PATH tối thiểu
        p.environment = env
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = pipe
        guard (try? p.run()) != nil else { return Result(ok: false, output: L("Không chạy được %@", path)) }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return Result(ok: p.terminationStatus == 0, output: String(decoding: data, as: UTF8.self))
    }

    static func quote(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }
}
