import AppKit
import SwiftUI
import Combine

// MARK: - Cửa sổ chính kiểu System Settings: NSSplitViewController (thanh bên mờ, cao hết cửa sổ)
// + NSToolbar thật (nút ‹ › điều hướng, tiêu đề trang, ô tìm kiếm của toolbar)

final class MainWindowController: NSWindowController, NSToolbarDelegate, NSSearchFieldDelegate {
    private let ui: ViewState
    private var subs: Set<AnyCancellable> = []
    private var lastPage: Page?

    private static let backID = NSToolbarItem.Identifier("back")
    private static let forwardID = NSToolbarItem.Identifier("forward")
    private static let searchID = NSToolbarItem.Identifier("search")
    private var backItem: NSToolbarItem?
    private var forwardItem: NSToolbarItem?
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
        guard let w = window, let tb = w.toolbar else { return }
        let p = ui.page
        if w.title != p.title { w.title = p.title }
        backItem?.isEnabled = !ui.back.isEmpty
        forwardItem?.isEnabled = !ui.forward.isEmpty
        backItem?.toolTip = ui.back.last.map { "Quay lại: \($0.title)" } ?? "Quay lại"
        forwardItem?.toolTip = ui.forward.last.map { "Tiếp: \($0.title)" } ?? "Tiếp"
        guard p != lastPage else { return }
        lastPage = p
        // Ô tìm kiếm chỉ có ở trang có danh sách; mỗi trang giữ từ khoá riêng
        let idx = tb.items.firstIndex { $0.itemIdentifier == Self.searchID }
        if let prompt = p.searchPrompt {
            if idx == nil { tb.insertItem(withItemIdentifier: Self.searchID, at: tb.items.count) }
            searchItem.searchField.placeholderString = prompt
            searchItem.searchField.stringValue = ui.queries[p] ?? ""
        } else if let idx {
            searchItem.endSearchInteraction()
            tb.removeItem(at: idx)
        }
    }

    func focusSearch() {
        guard ui.page.searchPrompt != nil else { return }
        searchItem.beginSearchInteraction()
    }

    // MARK: NSSearchFieldDelegate
    func controlTextDidChange(_ n: Notification) {
        if let f = n.object as? NSSearchField { ui.queries[ui.page] = f.stringValue }
    }

    // MARK: NSToolbarDelegate
    func toolbarDefaultItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        [.sidebarTrackingSeparator, Self.backID, Self.forwardID, .flexibleSpace]
    }
    func toolbarAllowedItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        [.sidebarTrackingSeparator, Self.backID, Self.forwardID, .flexibleSpace, Self.searchID]
    }

    func toolbar(_ toolbar: NSToolbar, itemForItemIdentifier id: NSToolbarItem.Identifier, willBeInsertedIntoToolbar flag: Bool) -> NSToolbarItem? {
        switch id {
        case Self.backID:
            backItem = navItem(id, "chevron.backward", "Quay lại", #selector(goBack))
            return backItem
        case Self.forwardID:
            forwardItem = navItem(id, "chevron.forward", "Tiếp", #selector(goForward))
            return forwardItem
        case Self.searchID:
            return searchItem
        default:
            return nil
        }
    }

    private func navItem(_ id: NSToolbarItem.Identifier, _ symbol: String, _ label: String, _ action: Selector) -> NSToolbarItem {
        let i = NSToolbarItem(itemIdentifier: id)
        i.image = NSImage(systemSymbolName: symbol, accessibilityDescription: label)
        i.label = label
        i.target = self
        i.action = action
        i.isBordered = true
        i.isNavigational = true
        i.autovalidates = false
        i.isEnabled = false
        return i
    }

    @objc private func goBack() { ui.goBack() }
    @objc private func goForward() { ui.goForward() }
}
