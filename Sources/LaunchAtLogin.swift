import Foundation

// MARK: - Khởi động cùng máy (LaunchAgent) — bắt buộc, không cho tắt

enum LaunchAtLogin {
    static let label = "io.github.vuminhhoa.macsentry"
    static var plistURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/\(label).plist")
    }
    /// Ghi lại plist mỗi lần chạy: tạo lại nếu bị xoá và cập nhật đường dẫn nếu app bị di chuyển
    static func ensure() {
        let exe = Bundle.main.executablePath ?? CommandLine.arguments[0]
        let plist: [String: Any] = [
            "Label": label,
            "ProgramArguments": [exe],
            "RunAtLoad": true,
            "KeepAlive": ["SuccessfulExit": false],
            "ProcessType": "Interactive",
        ]
        try? FileManager.default.createDirectory(at: plistURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        (plist as NSDictionary).write(to: plistURL, atomically: true)
    }

    /// launchd đặt XPC_SERVICE_NAME = label cho tiến trình do nó chạy
    static var runningUnderLaunchd: Bool { ProcessInfo.processInfo.environment["XPC_SERVICE_NAME"] == label }

    /// Giao app cho launchd quản lý (KeepAlive: bị kill sẽ tự chạy lại), rồi thoát tiến trình hiện tại
    static func handOverToLaunchd() -> Never {
        ensure()
        let domain = "gui/\(getuid())"
        for args in [["bootstrap", domain, plistURL.path], ["kickstart", "\(domain)/\(label)"]] {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
            p.arguments = args
            p.standardError = FileHandle.nullDevice
            try? p.run(); p.waitUntilExit()
        }
        exit(0)
    }
}
