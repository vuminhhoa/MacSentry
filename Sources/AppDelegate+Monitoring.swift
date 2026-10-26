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
                let comps = Self.watched.map { Component(name: $0.0, installed: FileManager.default.fileExists(atPath: $0.1), running: ps.contains($0.2)) }
                if comps != self.ui.components { self.ui.components = comps }
                for (name, plist, marker) in Self.watched where FileManager.default.fileExists(atPath: plist) {
                    if ps.contains(marker) {
                        if (self.daemonMissing[name] ?? 0) >= 3 {
                            Telegram.send(L("✅ %@ đã chạy lại", L(name)) + atNow(), silent: true)
                        }
                        self.daemonMissing[name] = 0
                    } else {
                        let n = (self.daemonMissing[name] ?? 0) + 1
                        self.daemonMissing[name] = n
                        if n == 3 {
                            let job = (plist as NSString).lastPathComponent.replacingOccurrences(of: ".plist", with: "")
                            Telegram.send(L("⚠️ %@ KHÔNG chạy (~1 phút)", L(name)) + "\n" + L("Có thể đã bị tắt bằng launchctl bootout / kill.")
                                          + "\n" + L("Kiểm tra: %@", "sudo launchctl print system/\(job)") + atNow())
                        }
                    }
                }
            }
        }
    }

    /// Camera / micro đang bật — khoá không phụ thuộc ngôn ngữ ("📷\t<tên>", "🎙\t<app>"); câu chữ ghép lúc gửi
    func sensorsNow() -> Set<String> {
        Set(AVSensors.camerasInUse().map { "📷\t\($0)" } + AVSensors.micsInUse().map { "🎙\t\($0)" })
    }

    func sensorText(_ s: String) -> String {
        let name = String(s.drop { $0 != "\t" }.dropFirst())
        return s.hasPrefix("🎙") ? L("🎙 Micro đang được dùng bởi: %@", name) : L("📷 Camera: %@", name)
    }

    func checkSensors() {
        let now = sensorsNow()
        let front = NSWorkspace.shared.frontmostApplication?.localizedName ?? "?"
        for s in now.subtracting(sensorsInUse).sorted() {
            // Micro đã biết chính xác app; camera thì chỉ đoán theo app đang mở phía trước
            let who = s.hasPrefix("🎙") ? "" : "\n" + L("App đang mở phía trước: %@", front)
            Telegram.send(sensorText(s) + L(" — ĐANG BẬT") + who + atNow())
        }
        for s in sensorsInUse.subtracting(now).sorted() {
            Telegram.send(sensorText(s) + L(" — đã tắt") + atNow(), silent: true)
        }
        sensorsInUse = now
    }
}

/// Dòng "Lúc: <giờ hiện tại>" cuối tin Telegram
func atNow() -> String { "\n" + L("Lúc: %@", timeFmt.string(from: Date())) }
