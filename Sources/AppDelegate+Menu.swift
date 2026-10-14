import AppKit
import SwiftUI

// MARK: - Biểu tượng thanh menu, menu và các thao tác

extension AppDelegate {
    func refreshStatusItem() {
        let count = monitor.active.count
        let untrusted = monitor.active.contains { !monitor.trusted.contains($0.ip) }
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
                let mark = monitor.trusted.contains(c.ip) ? "✅" : "⚠️"
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

    @objc func openWindow() {
        if window == nil {
            let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 880, height: 500),
                             styleMask: [.titled, .closable, .resizable, .miniaturizable],
                             backing: .buffered, defer: false)
            w.title = "MacSentry"
            w.contentView = NSHostingView(rootView: ContentView(monitor: monitor, ui: ViewState()))
            w.isReleasedWhenClosed = false
            w.center()
            window = w
        }
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
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
