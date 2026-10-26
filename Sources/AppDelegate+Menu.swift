import AppKit
import SwiftUI

// MARK: - Biểu tượng thanh menu, menu và các thao tác

extension AppDelegate {
    func refreshStatusItem() {
        guard let button = statusItem.button else { return }
        let count = monitor.active.count
        let untrusted = monitor.active.contains { !monitor.isTrusted($0.ip) }
        let symbol = count == 0 ? "lock.shield" : (untrusted ? "exclamationmark.shield.fill" : "checkmark.shield.fill")
        // Cỡ ký hiệu khớp với các biểu tượng hệ thống trên thanh menu
        var cfg = NSImage.SymbolConfiguration(pointSize: 15, weight: .regular)
        if count > 0 && untrusted { cfg = cfg.applying(.init(paletteColors: [.white, .systemRed])) }
        let img = NSImage(systemSymbolName: symbol, accessibilityDescription: "MacSentry")?.withSymbolConfiguration(cfg)
        img?.isTemplate = !(count > 0 && untrusted)      // template: tự đổi màu theo thanh menu sáng / tối
        let key = "\(symbol)|\(untrusted)|\(count)"
        guard key != statusKey else { return }          // không vẽ lại thanh menu khi không có gì đổi
        statusKey = key
        button.image = img
        // Không có số → chỉ ảnh, để ảnh nằm giữa ô (imageLeading với tiêu đề rỗng vẫn chừa khoảng bên phải)
        button.imagePosition = count > 0 ? .imageLeading : .imageOnly
        button.font = .monospacedDigitSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
        button.title = count > 0 ? "\(count)" : ""
        button.toolTip = count == 0 ? L("MacSentry: không có truy cập từ xa") : Lplural("MacSentry: %ld kết nối truy cập từ xa", count)
    }

    // Dựng lại menu mỗi lần mở để thời lượng luôn mới
    func menuNeedsUpdate(_ menu: NSMenu) {
        Lang.shared.resolve()
        menu.removeAllItems()
        if monitor.active.isEmpty {
            menu.addItem(NSMenuItem(title: L("Không có truy cập từ xa"), action: nil, keyEquivalent: ""))
        } else {
            menu.addItem(NSMenuItem(title: L("Đang truy cập từ xa:"), action: nil, keyEquivalent: ""))
            for c in monitor.active {
                let mark = monitor.isTrusted(c.ip) ? "✅" : "⚠️"
                let user = c.user.map { " — \($0)" } ?? ""
                let item = NSMenuItem(title: "\(mark) [\(c.serviceName)] \(c.ip):\(c.remotePort)\(user)  (\(durationString(c.firstSeen, Date())))",
                                      action: #selector(copyIP(_:)), keyEquivalent: "")
                item.representedObject = c.ip
                item.target = self
                item.toolTip = L("Bấm để sao chép IP")
                menu.addItem(item)
            }
        }
        menu.addItem(.separator())
        menu.addItem(item(L("Mở MacSentry…"), #selector(openWindow), "l"))
        menu.addItem(item(L("Cài đặt…"), #selector(openSettings), ","))
        menu.addItem(item(Telegram.config == nil ? L("Telegram: chưa cấu hình…") : L("Gửi thử Telegram"), #selector(testTelegram), ""))
        let daemon = NSMenuItem(title: Telegram.daemonInstalled ? L("Daemon macsentryd: đã cài") : L("Daemon macsentryd: CHƯA cài"),
                                action: nil, keyEquivalent: "")
        menu.addItem(daemon)
        menu.addItem(item(L("Cài đặt Chia sẻ (Remote Login)…"), #selector(openSharing), ""))
    }

    func item(_ title: String, _ sel: Selector, _ key: String) -> NSMenuItem {
        let i = NSMenuItem(title: title, action: sel, keyEquivalent: key)
        i.target = self
        return i
    }


    @objc func copyIP(_ sender: NSMenuItem) {
        guard let ip = sender.representedObject as? String else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(ip, forType: .string)
    }

    @objc func openWindow() { showWindow(nil) }
    @objc func openSettings() { showWindow(.settings) }

    /// Mở cửa sổ chính. Khi cửa sổ mở, app tạm hiện như app thường (Dock, ⌘Tab, thanh menu với Sửa/Xem/Cửa sổ);
    /// đóng cửa sổ thì trở lại chỉ còn biểu tượng trên thanh menu.
    func showWindow(_ page: Page?) {
        if let page { ui.page = page }
        if window == nil {
            let wc = MainWindowController(monitor: monitor, ui: ui, log: eventLog)
            let w = wc.window!
            w.isReleasedWhenClosed = false
            w.delegate = self
            w.center()
            w.setFrameAutosaveName("MacSentryMainWindow")   // nhớ kích thước / vị trí
            mainWindow = wc
            window = w
            if navigationMonitor == nil { installNavigationGestures() }
        }
        eventLog.start()
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }

    func windowWillClose(_ note: Notification) {
        guard (note.object as? NSWindow) === window else { return }
        eventLog.stop()
        eventLog.trim()
        NSApp.setActivationPolicy(.accessory)
        // Bỏ hẳn cửa sổ: cây SwiftUI ẩn vẫn vẽ lại mỗi khi Monitor/EventLog đổi. Trạng thái giao diện
        // nằm ở ViewState nên mở lại vẫn như cũ; vị trí/kích thước do frame autosave nhớ
        DispatchQueue.main.async {
            guard let w = self.window, !w.isVisible else { return }
            w.saveFrame(usingName: "MacSentryMainWindow")
            w.setFrameAutosaveName("")      // nhả tên để cửa sổ mới dùng lại được
            self.window = nil; self.mainWindow = nil
        }
    }

    // Lệnh từ main menu (đi theo responder chain tới app delegate)
    @objc func focusSearch(_ sender: Any?) {
        if window?.isKeyWindow != true { showWindow(nil) }
        mainWindow?.focusSearch()
    }
    @objc func selectPage(_ sender: NSMenuItem) {
        showWindow(Page(rawValue: sender.tag))
    }
    @objc func goBack(_ sender: Any?) { ui.goBack() }
    @objc func goForward(_ sender: Any?) { ui.goForward() }

    /// Nút back/forward của chuột (nút 4/5) và vuốt 3 ngón trên trackpad trong cửa sổ chính
    func installNavigationGestures() {
        navigationMonitor = NSEvent.addLocalMonitorForEvents(matching: [.otherMouseUp, .swipe]) { [weak self] e in
            guard let self, e.window != nil, e.window === self.window else { return e }
            switch e.type {
            case .otherMouseUp where e.buttonNumber == 3: self.ui.goBack(); return nil
            case .otherMouseUp where e.buttonNumber == 4: self.ui.goForward(); return nil
            case .swipe where e.deltaX > 0: self.ui.goBack(); return nil
            case .swipe where e.deltaX < 0: self.ui.goForward(); return nil
            default: return e
            }
        }
    }

    @objc func openSharing() {
        NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.Sharing-Settings.extension")!)
    }

    @objc func testTelegram() {
        if Telegram.config == nil {
            NSWorkspace.shared.open(Store.dir)
            let a = NSAlert()
            a.messageText = L("Chưa cấu hình Telegram")
            a.informativeText = L("Tạo file telegram.json trong thư mục vừa mở với nội dung:") + "\n{\"botToken\": \"...\", \"chatId\": \"...\"}"
            NSApp.activate(ignoringOtherApps: true)
            a.runModal()
        } else {
            Telegram.send(L("🔔 Tin nhắn thử từ MacSentry"))
        }
    }
}

// Bật/tắt mục Quay lại / Tiếp trong menu theo lịch sử điều hướng
extension AppDelegate: NSMenuItemValidation {
    func validateMenuItem(_ item: NSMenuItem) -> Bool {
        switch item.action {
        case #selector(goBack(_:)): return window?.isKeyWindow == true && !ui.back.isEmpty
        case #selector(goForward(_:)): return window?.isKeyWindow == true && !ui.forward.isEmpty
        default: return true
        }
    }
}
