import AppKit
import SwiftUI

// MARK: - Biểu tượng thanh menu, menu và các thao tác

extension AppDelegate {
    func refreshStatusItem() {
        let count = monitor.active.count
        let untrusted = monitor.active.contains { !monitor.isTrusted($0.ip) }
        if let button = statusItem.button {
            let symbol = count == 0 ? "lock.shield" : (untrusted ? "exclamationmark.shield.fill" : "checkmark.shield.fill")
            let img = NSImage(systemSymbolName: symbol, accessibilityDescription: "MacSentry")
            if count > 0 && untrusted {
                let cfg = NSImage.SymbolConfiguration(paletteColors: [.white, .systemRed])
                button.image = img?.withSymbolConfiguration(cfg)
                button.image?.isTemplate = false
            } else {
                button.image = img
                button.image?.isTemplate = true
            }
            button.title = count > 0 ? " \(count)" : ""
            button.imagePosition = .imageLeading
            button.toolTip = count == 0 ? "MacSentry: không có truy cập từ xa" : "MacSentry: \(count) kết nối truy cập từ xa"
        }
    }

    // Dựng lại menu mỗi lần mở để thời lượng luôn mới
    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        if monitor.active.isEmpty {
            menu.addItem(NSMenuItem(title: "Không có truy cập từ xa", action: nil, keyEquivalent: ""))
        } else {
            menu.addItem(NSMenuItem(title: "Đang truy cập từ xa:", action: nil, keyEquivalent: ""))
            for c in monitor.active {
                let mark = monitor.isTrusted(c.ip) ? "✅" : "⚠️"
                let user = c.user.map { " — \($0)" } ?? ""
                let item = NSMenuItem(title: "\(mark) [\(c.service)] \(c.ip):\(c.remotePort)\(user)  (\(durationString(c.firstSeen, Date())))",
                                      action: #selector(copyIP(_:)), keyEquivalent: "")
                item.representedObject = c.ip
                item.target = self
                item.toolTip = "Bấm để copy IP"
                menu.addItem(item)
            }
        }
        menu.addItem(.separator())
        menu.addItem(item("Mở MacSentry…", #selector(openWindow), "l"))
        menu.addItem(item("Cài đặt…", #selector(openSettings), ","))
        menu.addItem(item(Telegram.config == nil ? "Telegram: chưa cấu hình…" : "Gửi thử Telegram", #selector(testTelegram), ""))
        let daemon = NSMenuItem(title: Telegram.daemonInstalled ? "Daemon macsentryd: đã cài" : "Daemon macsentryd: CHƯA cài",
                                action: nil, keyEquivalent: "")
        menu.addItem(daemon)
        menu.addItem(item("Cài đặt Chia sẻ (Remote Login)…", #selector(openSharing), ""))
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
            installNavigationGestures()
        }
        eventLog.start()
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }

    func windowWillClose(_ note: Notification) {
        guard (note.object as? NSWindow) === window else { return }
        eventLog.stop()
        NSApp.setActivationPolicy(.accessory)
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
        NSEvent.addLocalMonitorForEvents(matching: [.otherMouseUp, .swipe]) { [weak self] e in
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
            a.messageText = "Chưa cấu hình Telegram"
            a.informativeText = "Tạo file telegram.json trong thư mục vừa mở với nội dung:\n{\"botToken\": \"...\", \"chatId\": \"...\"}"
            NSApp.activate(ignoringOtherApps: true)
            a.runModal()
        } else {
            Telegram.send("🔔 Tin nhắn thử từ MacSentry")
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
