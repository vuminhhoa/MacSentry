import AppKit
import UserNotifications

// MARK: - App delegate / status bar

final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate, NSMenuDelegate, NSWindowDelegate {
    let monitor = Monitor()
    let ui = ViewState()
    let eventLog = EventLog()
    var mainWindow: MainWindowController?
    var statusItem: NSStatusItem!
    var window: NSWindow?
    var notificationsAllowed = false
    var alertShowing = false
    var poweringOff = false
    var sleptAt: Date?
    var sensorsInUse: Set<String> = []
    var sensorTimer: Timer?
    var watchdogTimer: Timer?
    var daemonMissing: [String: Int] = [:]

    func applicationDidFinishLaunching(_ note: Notification) {
        // Chỉ cho chạy 1 instance. Bản mở bằng Finder/`open` giao cho launchd rồi mới thoát, nên bản launchd
        // có thể thấy nó còn sống trong giây lát → đợi tối đa 5s. Vẫn trùng → thoát mã lỗi để launchd thử lại sau
        // (thoát mã 0 thì launchd coi là "thoát bình thường" và không chạy lại → không còn bản nào chạy).
        if let bid = Bundle.main.bundleIdentifier {
            var tries = 0
            while NSRunningApplication.runningApplications(withBundleIdentifier: bid).count > 1 {
                if tries == 10 { exit(LaunchAtLogin.runningUnderLaunchd ? 1 : 0) } // không qua applicationWillTerminate
                tries += 1
                Thread.sleep(forTimeInterval: 0.5)
            }
        }
        // Mở bằng Finder/`open` → chuyển cho launchd chạy, để bị kill thì launchd tự mở lại
        if !LaunchAtLogin.runningUnderLaunchd { LaunchAtLogin.handOverToLaunchd() }
        LaunchAtLogin.ensure()

        MainMenu.install()

        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        let menu = NSMenu()
        menu.delegate = self
        statusItem.menu = menu

        let center = UNUserNotificationCenter.current()
        center.delegate = self
        center.requestAuthorization(options: [.alert, .sound, .badge]) { ok, _ in
            DispatchQueue.main.async { self.notificationsAllowed = ok; self.ui.notificationsAllowed = ok }
        }

        monitor.onChange = { [weak self] in self?.refreshStatusItem() }
        monitor.onNewConnection = { [weak self] c, atStartup in self?.alert(c, atStartup: atStartup) }
        monitor.onUserLogin = { [weak self] c in
            if Telegram.daemonInstalled { return }
            let mark = self?.monitor.trusted.contains(c.ip) == true ? "✅" : "⚠️"
            Telegram.send("\(mark) Đã đăng nhập SSH\nIP: \(c.ip):\(c.remotePort)\nUser: \(c.user ?? "?")")
        }
        monitor.onSessionEnd = { e in
            if Telegram.daemonInstalled { return }
            Telegram.send("🔌 Kết thúc phiên \(e.service ?? "SSH")\nIP: \(e.ip)" + (e.user.map { "\nUser: \($0)" } ?? "")
                          + "\nThời lượng: \(durationString(e.start, e.end ?? Date()))", silent: true)
        }
        notifyStartup()
        observeSystemEvents()
        checkDaemons()
        monitor.start()
    }

    /// Đọc lại quyền thông báo từ hệ thống — người dùng có thể bật/tắt trong Cài đặt bất cứ lúc nào
    func refreshNotificationStatus() {
        UNUserNotificationCenter.current().getNotificationSettings { st in
            let ok = [.authorized, .provisional].contains(st.authorizationStatus) && st.alertSetting != .disabled
            DispatchQueue.main.async {
                self.notificationsAllowed = ok
                if self.ui.notificationsAllowed != ok { self.ui.notificationsAllowed = ok }
            }
        }
    }

    // Quay lại app (vd. từ Cài đặt hệ thống) → cập nhật trạng thái quyền thông báo
    func applicationDidBecomeActive(_ note: Notification) { refreshNotificationStatus() }
    func windowDidBecomeKey(_ note: Notification) { refreshNotificationStatus() }

    func observeSystemEvents() {
        let ws = NSWorkspace.shared.notificationCenter
        // Tắt máy / khởi động lại / đăng xuất: macOS báo trước khi đóng các app
        ws.addObserver(forName: NSWorkspace.willPowerOffNotification, object: nil, queue: .main) { [weak self] _ in
            guard let self, !self.poweringOff else { return }
            self.poweringOff = true
            if !Telegram.daemonInstalled { Telegram.send("🔴 Máy đang tắt / khởi động lại / đăng xuất\nLúc: \(timeFmt.string(from: Date()))", wait: true) }
            if self.alertShowing { NSApp.abortModal() } // popup đang mở thì đóng, để không chặn việc tắt máy
        }
        // Ngủ / thức dậy. Lúc ngủ chờ gửi xong (mạng sắp bị ngắt); lúc thức mạng chưa sẵn sàng thì Telegram.send tự thử lại
        ws.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { [weak self] _ in
            self?.sleptAt = Date()
            Telegram.send("😴 Máy đi ngủ\nLúc: \(timeFmt.string(from: Date()))", silent: true, wait: true)
        }
        ws.addObserver(forName: NSWorkspace.didWakeNotification, object: nil, queue: .main) { [weak self] _ in
            let slept = self?.sleptAt.map { "\nĐã ngủ: \(durationString($0, Date()))" } ?? ""
            self?.sleptAt = nil
            if Telegram.daemonInstalled { return }
            Telegram.send("☀️ Máy thức dậy\nLúc: \(timeFmt.string(from: Date()))\(slept)")
        }
        // Khoá / mở khoá màn hình (tin im lặng: xảy ra nhiều lần mỗi ngày)
        let dn = DistributedNotificationCenter.default()
        dn.addObserver(forName: .init("com.apple.screenIsLocked"), object: nil, queue: .main) { _ in
            Telegram.send("🔒 Màn hình đã khoá\nLúc: \(timeFmt.string(from: Date()))", silent: true)
        }
        dn.addObserver(forName: .init("com.apple.screenIsUnlocked"), object: nil, queue: .main) { _ in
            // Mở khoá lúc 0h–6h sáng là bất thường → có chuông
            let night = Calendar.current.component(.hour, from: Date()) < 6
            Telegram.send("\(night ? "🌙 Máy được mở khoá lúc NỬA ĐÊM" : "🔓 Màn hình được mở khoá") (\(NSUserName()))\nLúc: \(timeFmt.string(from: Date()))",
                          silent: !night)
        }
        // Camera / micro bật-tắt: CoreAudio / CoreMediaIO báo ngay khi đổi; quét dự phòng mỗi 30 giây
        sensorsInUse = Set(AVSensors.camerasInUse().map { "📷 Camera: \($0)" } + AVSensors.micsInUse().map { "🎙 Micro đang được dùng bởi: \($0)" })
        AVSensors.observe { [weak self] in self?.checkSensors() }
        let t = Timer(timeInterval: 30, repeats: true) { [weak self] _ in self?.checkSensors() }
        t.tolerance = 5
        RunLoop.main.add(t, forMode: .common)
        sensorTimer = t

        // Giám sát chéo: app (user) canh daemon root và helper Endpoint Security — bị tắt mà không kịp tự báo
        // (kill -9, launchctl bootout) thì app báo thay. Mỗi 20 giây, vắng 3 lần liên tiếp (~1 phút) mới báo.
        let w = Timer(timeInterval: 20, repeats: true) { [weak self] _ in self?.checkDaemons() }
        w.tolerance = 5
        RunLoop.main.add(w, forMode: .common)
        watchdogTimer = w
    }

    /// Thời điểm máy khởi động (kern.boottime)
    static func bootTime() -> Date? {
        var tv = timeval(), size = MemoryLayout<timeval>.size
        var mib: [Int32] = [CTL_KERN, KERN_BOOTTIME]
        guard sysctl(&mib, 2, &tv, &size, nil, 0) == 0 else { return nil }
        return Date(timeIntervalSince1970: TimeInterval(tv.tv_sec))
    }

    /// Lần chạy đầu tiên sau khi bật máy → báo "máy vừa khởi động"/"đã đăng nhập", còn lại → báo app khởi động lại
    func notifyStartup() {
        guard let boot = Self.bootTime() else { Telegram.send("▶️ MacSentry đã khởi động"); return }
        let last = UserDefaults.standard.double(forKey: "lastBootTime")
        UserDefaults.standard.set(boot.timeIntervalSince1970, forKey: "lastBootTime")
        let newBoot = abs(last - boot.timeIntervalSince1970) > 1
        if newBoot && Telegram.daemonInstalled {
            Telegram.send("👤 \(NSUserName()) đã đăng nhập máy\nLúc: \(timeFmt.string(from: Date()))", silent: true)
        } else if newBoot {
            Telegram.send("🟢 Máy vừa khởi động\nBật lúc: \(timeFmt.string(from: boot))\nĐăng nhập: \(NSUserName()) lúc \(timeFmt.string(from: Date()))")
        } else {
            Telegram.send("▶️ MacSentry đã khởi động lại (máy bật từ \(timeFmt.string(from: boot)))", silent: true)
        }
    }

    /// Không cho thoát app, trừ khi đang tắt máy / khởi động lại / đăng xuất (để không chặn việc tắt máy)
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if poweringOff { return .terminateNow }
        let reason = NSAppleEventManager.shared().currentAppleEvent?
            .attributeDescriptor(forKeyword: AEKeyword(kAEQuitReason))?.enumCodeValue
        let systemReasons: [OSType] = [OSType(kAELogOut), OSType(kAEReallyLogOut), OSType(kAEShowRestartDialog),
                                       OSType(kAEShowShutdownDialog), OSType(kAERestart), OSType(kAEShutDown)]
        if let reason, systemReasons.contains(reason) { poweringOff = true; return .terminateNow }
        Telegram.send("⛔️ Có lệnh thoát MacSentry — đã chặn\nLúc: \(timeFmt.string(from: Date()))", silent: true)
        return .terminateCancel
    }

    func applicationWillTerminate(_ note: Notification) {
        if !poweringOff { Telegram.send("⏹ MacSentry (app) đã bị tắt", wait: true) }
        Monitor.stopHelper()
    }
}
