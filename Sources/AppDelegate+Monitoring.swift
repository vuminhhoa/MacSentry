import AppKit

// MARK: - Giám sát chéo daemon/helper và camera/micro

extension AppDelegate {
    /// (tên hiển thị, file plist — có cài mới canh, đoạn nhận diện trong dòng lệnh của `ps`)
    static let watched = [
        ("macsentryd (daemon chính)", "/Library/LaunchDaemons/io.github.vuminhhoa.macsentry.daemon.plist", "/usr/local/libexec/macsentryd"),
        ("macsentry-es (Endpoint Security)", "/Library/LaunchDaemons/io.github.vuminhhoa.macsentry.es.plist", "/usr/local/libexec/macsentry-es"),
    ]

    func checkDaemons() {
        DispatchQueue.global().async {
            let p = Process(); p.executableURL = URL(fileURLWithPath: "/bin/ps"); p.arguments = ["-axo", "command="]
            let out = Pipe(); p.standardOutput = out
            guard (try? p.run()) != nil else { return }
            let ps = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            p.waitUntilExit()
            DispatchQueue.main.async {
                Monitor.daemonRunning = Telegram.daemonInstalled && ps.contains("/usr/local/libexec/macsentryd")
                    && FileManager.default.fileExists(atPath: Store.daemonRemotePath)
                // Daemon chạy lại sau gián đoạn → tắt job netstat dự phòng app đã tự bật
                if Monitor.daemonRunning && self.monitor.helperStarted { Monitor.stopHelper(); self.monitor.helperStarted = false }
                for (name, plist, marker) in Self.watched where FileManager.default.fileExists(atPath: plist) {
                    if ps.contains(marker) {
                        if (self.daemonMissing[name] ?? 0) >= 3 {
                            Telegram.send("✅ \(name) đã chạy lại\nLúc: \(timeFmt.string(from: Date()))", silent: true)
                        }
                        self.daemonMissing[name] = 0
                    } else {
                        let n = (self.daemonMissing[name] ?? 0) + 1
                        self.daemonMissing[name] = n
                        if n == 3 {
                            Telegram.send("⚠️ \(name) KHÔNG chạy (~1 phút)\nCó thể đã bị tắt bằng launchctl bootout / kill.\n"
                                          + "Kiểm tra: sudo launchctl print system/\((plist as NSString).lastPathComponent.replacingOccurrences(of: ".plist", with: ""))\n"
                                          + "Lúc: \(timeFmt.string(from: Date()))")
                        }
                    }
                }
            }
        }
    }

    func checkSensors() {
        let now = Set(AVSensors.camerasInUse().map { "📷 Camera: \($0)" } + AVSensors.micsInUse().map { "🎙 Micro đang được dùng bởi: \($0)" })
        let front = NSWorkspace.shared.frontmostApplication?.localizedName ?? "?"
        for s in now.subtracting(sensorsInUse).sorted() {
            // Micro đã biết chính xác app; camera thì chỉ đoán theo app đang mở phía trước
            let who = s.hasPrefix("🎙") ? "" : "\nApp đang mở phía trước: \(front)"
            Telegram.send("\(s) — ĐANG BẬT\(who)\nLúc: \(timeFmt.string(from: Date()))")
        }
        for s in sensorsInUse.subtracting(now).sorted() {
            Telegram.send("\(s) — đã tắt\nLúc: \(timeFmt.string(from: Date()))", silent: true)
        }
        sensorsInUse = now
    }
}
