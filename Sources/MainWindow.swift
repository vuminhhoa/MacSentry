import AppKit
import SwiftUI
import Combine

// MARK: - Cửa sổ chính kiểu System Settings: NSSplitViewController (thanh bên mờ, cao hết cửa sổ)
// + NSToolbar thật (nút ‹ › điều hướng, tiêu đề trang, ô tìm kiếm của toolbar)

final class MainWindowController: NSWindowController, NSToolbarDelegate, NSSearchFieldDelegate {
    private let ui: ViewState
    private var subs: Set<AnyCancellable> = []
    private var lastPage: Page?

    private static let navID = NSToolbarItem.Identifier("navigation")
    private static let searchID = NSToolbarItem.Identifier("search")
    /// Cụm ‹ › dạng segmented như Finder / System Settings: một khối kính duy nhất, bật/tắt từng nửa
    /// không làm toolbar tính lại cách gộp nút
    private lazy var navItem: NSToolbarItemGroup = {
        let g = NSToolbarItemGroup(
            itemIdentifier: Self.navID,
            images: [NSImage(systemSymbolName: "chevron.backward", accessibilityDescription: "Quay lại")!,
                     NSImage(systemSymbolName: "chevron.forward", accessibilityDescription: "Tiếp")!],
            selectionMode: .momentary, labels: ["Quay lại", "Tiếp"], target: self, action: #selector(navigate(_:)))
        g.controlRepresentation = .expanded
        g.isNavigational = true
        g.autovalidates = false
        g.subitems.forEach { $0.autovalidates = false; $0.isEnabled = false }
        return g
    }()
    private lazy var searchItem: NSSearchToolbarItem = {
        let s = NSSearchToolbarItem(itemIdentifier: Self.searchID)
        s.searchField.delegate = self
        s.preferredWidthForSearchField = 240
        return s
    }()

    init(monitor: Monitor, ui: ViewState, log: EventLog) {
        self.ui = ui
        let sideVC = NSHostingController(rootView: SidebarView(monitor: monitor, ui: ui, log: log))
        let detailVC = NSHostingController(rootView: DetailView(monitor: monitor, ui: ui, log: log))
        sideVC.sizingOptions = []
        detailVC.sizingOptions = []

        let split = NSSplitViewController()
        let side = NSSplitViewItem(sidebarWithViewController: sideVC)
        side.minimumThickness = 215
        side.maximumThickness = 320
        side.canCollapse = false
        let detail = NSSplitViewItem(viewController: detailVC)
        detail.minimumThickness = 640
        // Không bật automaticallyAdjustsSafeAreaInsets: nội dung trang nằm chồng dưới thanh bên thì các vùng con trỏ
        // của nó (bảng, ô nhập) đè lên vùng kéo đổi cỡ ở mép thanh bên → con trỏ nhấp nháy giữa mũi tên và ↔
        split.splitViewItems = [side, detail]

        let w = NSWindow(contentViewController: split)
        w.styleMask = [.titled, .closable, .resizable, .miniaturizable, .fullSizeContentView]
        w.toolbarStyle = .unified
        w.setContentSize(NSSize(width: 1080, height: 680))
        w.contentMinSize = NSSize(width: 880, height: 540)
        super.init(window: w)

        let tb = NSToolbar(identifier: "MacSentryToolbar")
        tb.delegate = self
        tb.displayMode = .iconOnly
        tb.allowsUserCustomization = false
        w.toolbar = tb

        // Mọi thay đổi của ViewState → cập nhật tiêu đề, nút ‹ ›, ô tìm kiếm (sau khi giá trị đã đổi)
        ui.objectWillChange.receive(on: RunLoop.main).sink { [weak self] in self?.sync() }.store(in: &subs)
        sync()
    }

    required init?(coder: NSCoder) { fatalError() }

    private func sync() {
        guard let w = window else { return }
        let p = ui.page
        if w.title != p.title { w.title = p.title }
        // Chỉ gán khi đổi: hàm này chạy ở mọi thay đổi của ViewState (gõ phím, chọn dòng…)
        let nav = navItem.subitems
        set(nav[0], enabled: !ui.back.isEmpty, tip: ui.back.last.map { "Quay lại: \($0.title)" } ?? "Quay lại")
        set(nav[1], enabled: !ui.forward.isEmpty, tip: ui.forward.last.map { "Tiếp: \($0.title)" } ?? "Tiếp")
        guard p != lastPage else { return }
        lastPage = p
        // Ô tìm kiếm luôn hiện và luôn bật: thêm/gỡ, ẩn/hiện hay bật/tắt ô đều làm toolbar (macOS 26+) vẽ lại
        // cả khối kính chứa cụm ‹ › → nhấp nháy khi đổi trang. Trang không có danh sách: gõ là chuyển sang tìm sự kiện
        let field = searchItem.searchField
        let target = p.searchPrompt == nil ? Page.events : p
        let prompt = target.searchPrompt ?? ""
        if field.placeholderString != prompt { field.placeholderString = prompt }
        let q = p.searchPrompt == nil ? "" : ui.queries[p] ?? ""
        if field.stringValue != q { field.stringValue = q }
    }

    private func set(_ item: NSToolbarItem?, enabled: Bool, tip: String) {
        guard let item else { return }
        if item.isEnabled != enabled { item.isEnabled = enabled }
        if item.toolTip != tip { item.toolTip = tip }
    }

    func focusSearch() {
        searchItem.beginSearchInteraction()
    }

    // MARK: NSSearchFieldDelegate
    func controlTextDidChange(_ n: Notification) {
        guard let f = n.object as? NSSearchField else { return }
        if ui.page.searchPrompt == nil {
            // Tổng quan / Cài đặt: gõ vào ô tìm kiếm → mở trang Sự kiện với từ khoá này
            guard !f.stringValue.isEmpty else { return }
            ui.queries[.events] = f.stringValue
            ui.page = .events
        } else {
            ui.queries[ui.page] = f.stringValue
        }
    }

    // MARK: NSToolbarDelegate
    func toolbarDefaultItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        [.sidebarTrackingSeparator, Self.navID, .flexibleSpace, Self.searchID]
    }
    func toolbarAllowedItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        [.sidebarTrackingSeparator, Self.navID, .flexibleSpace, Self.searchID]
    }

    func toolbar(_ toolbar: NSToolbar, itemForItemIdentifier id: NSToolbarItem.Identifier, willBeInsertedIntoToolbar flag: Bool) -> NSToolbarItem? {
        switch id {
        case Self.navID: return navItem
        case Self.searchID: return searchItem
        default: return nil
        }
    }

    @objc private func navigate(_ g: NSToolbarItemGroup) {
        if g.selectedIndex == 0 { ui.goBack() } else { ui.goForward() }
    }
}
