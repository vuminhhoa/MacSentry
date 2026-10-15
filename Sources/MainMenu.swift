import AppKit

// MARK: - Main menu. App chạy trên thanh menu vẫn cần menu này: thiếu menu "Sửa" thì ⌘A / ⌘C / ⌘V / ⌘Z
// trong ô nhập liệu không hoạt động (AppKit chuyển các phím tắt này qua main menu).

enum MainMenu {
    static func install() {
        let main = NSMenu()

        let app = submenu(main, "MacSentry")
        app.addItem(withTitle: "Giới thiệu MacSentry", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        app.addItem(.separator())
        app.addItem(withTitle: "Cài đặt…", action: #selector(AppDelegate.openSettings), keyEquivalent: ",")
        app.addItem(.separator())
        app.addItem(withTitle: "Ẩn MacSentry", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        add(app, "Ẩn các app khác", #selector(NSApplication.hideOtherApplications(_:)), "h", [.command, .option])

        let edit = submenu(main, "Sửa")
        edit.addItem(withTitle: "Hoàn tác", action: Selector(("undo:")), keyEquivalent: "z")
        add(edit, "Làm lại", Selector(("redo:")), "z", [.command, .shift])
        edit.addItem(.separator())
        edit.addItem(withTitle: "Cắt", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        edit.addItem(withTitle: "Sao chép", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: "Dán", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        add(edit, "Dán và khớp kiểu", #selector(NSTextView.pasteAsPlainText(_:)), "v", [.command, .option, .shift])
        edit.addItem(withTitle: "Xoá", action: #selector(NSText.delete(_:)), keyEquivalent: "")
        edit.addItem(withTitle: "Chọn tất cả", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        // Ctrl+A cũng chọn tất cả (quen tay từ Windows/Linux) — mục thay thế, chỉ hiện khi giữ Control
        let ctrlA = add(edit, "Chọn tất cả", #selector(NSText.selectAll(_:)), "a", [.control])
        ctrlA.isAlternate = true
        edit.addItem(.separator())
        edit.addItem(withTitle: "Tìm…", action: #selector(AppDelegate.focusSearch(_:)), keyEquivalent: "f")

        let view = submenu(main, "Xem")
        for p in Page.allCases {
            let i = view.addItem(withTitle: p.title, action: #selector(AppDelegate.selectPage(_:)), keyEquivalent: "\(p.rawValue + 1)")
            i.tag = p.rawValue
        }

        view.addItem(.separator())
        view.addItem(withTitle: "Quay lại", action: #selector(AppDelegate.goBack(_:)), keyEquivalent: "[")
        view.addItem(withTitle: "Tiếp", action: #selector(AppDelegate.goForward(_:)), keyEquivalent: "]")

        let window = submenu(main, "Cửa sổ")
        window.addItem(withTitle: "Thu nhỏ", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        window.addItem(withTitle: "Phóng to", action: #selector(NSWindow.performZoom(_:)), keyEquivalent: "")
        window.addItem(withTitle: "Đóng", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        NSApp.windowsMenu = window

        // Biểu tượng cho các lệnh chính (macOS 26+). Không ép hiện: từ macOS 27 AppKit tự quyết có vẽ icon hay không
        let icons: [Selector: String] = [
            #selector(AppDelegate.openSettings): "gearshape",
            Selector(("undo:")): "arrow.uturn.backward", Selector(("redo:")): "arrow.uturn.forward",
            #selector(NSText.cut(_:)): "scissors", #selector(NSText.copy(_:)): "doc.on.doc",
            #selector(NSText.paste(_:)): "doc.on.clipboard", #selector(NSText.delete(_:)): "delete.left",
            #selector(NSText.selectAll(_:)): "checkmark.circle", #selector(AppDelegate.focusSearch(_:)): "magnifyingglass",
            #selector(AppDelegate.goBack(_:)): "chevron.backward", #selector(AppDelegate.goForward(_:)): "chevron.forward",
            #selector(NSWindow.performMiniaturize(_:)): "minus.rectangle", #selector(NSWindow.performClose(_:)): "xmark.rectangle",
        ]
        for m in main.items.compactMap(\.submenu) {
            for i in m.items {
                let name = i.action == #selector(AppDelegate.selectPage(_:)) ? Page(rawValue: i.tag)?.icon : i.action.flatMap { icons[$0] }
                if let name { i.image = NSImage(systemSymbolName: name, accessibilityDescription: nil) }
            }
        }

        NSApp.mainMenu = main
    }

    private static func submenu(_ main: NSMenu, _ title: String) -> NSMenu {
        let item = main.addItem(withTitle: title, action: nil, keyEquivalent: "")
        let m = NSMenu(title: title)
        item.submenu = m
        return m
    }

    @discardableResult
    private static func add(_ m: NSMenu, _ title: String, _ sel: Selector, _ key: String, _ mods: NSEvent.ModifierFlags) -> NSMenuItem {
        let i = m.addItem(withTitle: title, action: sel, keyEquivalent: key)
        i.keyEquivalentModifierMask = mods
        return i
    }
}

// MARK: - Logo app. Vẽ bằng code (một nguồn duy nhất): build.sh gọi `MacSentry --render-icon <thư mục>` để xuất
// các cỡ PNG rồi đóng thành AppIcon.icns trong bundle — Finder, System Settings, Dock, popup cảnh báo đều dùng file này.

enum AppIcon {
    /// Vẽ logo vào khung vuông `r` theo lưới icon macOS (canvas 1024, thân 824 cách lề 100)
    static func draw(in r: NSRect) {
        let s = r.width / 1024
        let body = NSRect(x: r.minX + 100 * s, y: r.minY + 100 * s, width: 824 * s, height: 824 * s)
        let path = NSBezierPath(roundedRect: body, xRadius: 185 * s, yRadius: 185 * s)

        NSGraphicsContext.saveGraphicsState()
        let shadow = NSShadow()
        shadow.shadowColor = NSColor.black.withAlphaComponent(0.35)
        shadow.shadowOffset = NSSize(width: 0, height: -10 * s)
        shadow.shadowBlurRadius = 24 * s
        shadow.set()
        NSColor(srgbRed: 0.08, green: 0.25, blue: 0.62, alpha: 1).setFill()
        path.fill()
        NSGraphicsContext.restoreGraphicsState()

        NSGradient(colors: [NSColor(srgbRed: 0.33, green: 0.62, blue: 1.0, alpha: 1),
                            NSColor(srgbRed: 0.13, green: 0.40, blue: 0.92, alpha: 1),
                            NSColor(srgbRed: 0.05, green: 0.20, blue: 0.58, alpha: 1)])?.draw(in: path, angle: -90)
        // Viền sáng mảnh phía trên cho cảm giác nổi khối
        NSGraphicsContext.saveGraphicsState()
        path.addClip()
        NSGradient(starting: NSColor.white.withAlphaComponent(0.22), ending: .clear)?
            .draw(in: NSRect(x: body.minX, y: body.midY, width: body.width, height: body.height / 2), angle: -90)
        NSGraphicsContext.restoreGraphicsState()

        let cfg = NSImage.SymbolConfiguration(pointSize: 580 * s, weight: .bold)
            .applying(.init(paletteColors: [NSColor(srgbRed: 0.10, green: 0.33, blue: 0.82, alpha: 1), .white]))
        if let sym = NSImage(systemSymbolName: "lock.shield.fill", accessibilityDescription: nil)?.withSymbolConfiguration(cfg) {
            let size = sym.size
            NSGraphicsContext.saveGraphicsState()
            let glow = NSShadow()
            glow.shadowColor = NSColor.black.withAlphaComponent(0.25)
            glow.shadowOffset = NSSize(width: 0, height: -6 * s)
            glow.shadowBlurRadius = 14 * s
            glow.set()
            sym.draw(in: NSRect(x: body.midX - size.width / 2, y: body.midY - size.height / 2 - 4 * s, width: size.width, height: size.height))
            NSGraphicsContext.restoreGraphicsState()
        }
    }

    /// Xuất thư mục .iconset (16…1024 px) cho iconutil
    static func renderIconset(to dir: String) throws {
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        for pt in [16, 32, 128, 256, 512] {
            for scale in [1, 2] {
                let px = pt * scale
                guard let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8,
                                                 samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                                                 colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0) else { continue }
                NSGraphicsContext.saveGraphicsState()
                NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
                NSGraphicsContext.current?.imageInterpolation = .high
                draw(in: NSRect(x: 0, y: 0, width: px, height: px))
                NSGraphicsContext.restoreGraphicsState()
                let name = "icon_\(pt)x\(pt)\(scale == 2 ? "@2x" : "").png"
                try rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: dir).appendingPathComponent(name))
            }
        }
    }
}
