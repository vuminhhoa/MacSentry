import AppKit
import UserNotifications

// MARK: - Cảnh báo kết nối từ xa: Telegram, thông báo, popup

extension AppDelegate {

    func alert(_ c: RemoteConnection, atStartup: Bool = false) {
        // Kết nối từ chính máy này coi như tin cậy (không popup)
        let local = c.ip.hasPrefix("127.") || c.ip == "::1" || c.ip == "localhost"
        let trusted = monitor.trusted.contains(c.ip) || local
        let title = trusted ? "Kết nối \(c.service) (IP tin cậy)" : "⚠️ Có kết nối \(c.service) mới!"
        let body = "Dịch vụ: \(c.service)\nIP: \(c.ip):\(c.remotePort)" + (c.user.map { "\nUser: \($0)" } ?? "")
        // Gửi Telegram trước tiên, trước cả popup (runModal sẽ chặn luồng chính)
        if !Telegram.daemonInstalled {
            Telegram.send("\(trusted ? "✅ Kết nối \(c.service) (IP tin cậy)" : "🚨 Kết nối \(c.service) từ IP LẠ")\n\(body)\nLúc: \(timeFmt.string(from: c.firstSeen))",
                          silent: trusted)
        }

        if notificationsAllowed {
            let content = UNMutableNotificationContent()
            content.title = title
            content.body = body
            content.sound = trusted ? nil : .default
            UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: c.id, content: content, trigger: nil))
        } else {
            // Dự phòng khi chưa cấp quyền thông báo
            let script = "display notification \"\(body.replacingOccurrences(of: "\n", with: " "))\" with title \"\(title)\" sound name \"Sosumi\""
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            p.arguments = ["-e", script]
            try? p.run()
        }

        if !trusted && !alertShowing && !atStartup {
            alertShowing = true
            defer { alertShowing = false }
            NSSound(named: "Sosumi")?.play()
            NSApp.activate(ignoringOtherApps: true)
            let a = NSAlert()
            a.alertStyle = .critical
            a.messageText = "Có kết nối \(c.service) từ IP lạ"
            a.informativeText = body + "\nThời điểm: \(timeFmt.string(from: c.firstSeen))"
            a.addButton(withTitle: "OK")
            a.addButton(withTitle: "Tin cậy IP này")
            a.addButton(withTitle: "Xem danh sách")
            switch a.runModal() {
            case .alertSecondButtonReturn: monitor.toggleTrust(c.ip)
            case .alertThirdButtonReturn: showWindow(.active)
            default: break
            }
        }
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent n: UNNotification,
                                withCompletionHandler h: @escaping (UNNotificationPresentationOptions) -> Void) {
        h([.banner, .sound, .list])
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive r: UNNotificationResponse,
                                withCompletionHandler h: @escaping () -> Void) {
        DispatchQueue.main.async { self.openWindow() }
        h()
    }
}
