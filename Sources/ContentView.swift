import SwiftUI
import AppKit

// MARK: - Nội dung cửa sổ chính: thanh bên + trang chi tiết (khung cửa sổ/toolbar ở MainWindow.swift)

let timeFmt: DateFormatter = { let f = DateFormatter(); f.dateFormat = "dd/MM/yyyy HH:mm:ss"; return f }()

func durationString(_ from: Date, _ to: Date) -> String {
    let s = Int(to.timeIntervalSince(from))
    if s < 60 { return "\(s)s" }
    if s < 3600 { return "\(s / 60)m \(s % 60)s" }
    return "\(s / 3600)h \((s % 3600) / 60)m"
}

func isValidIP(_ s: String) -> Bool {
    var v4 = in_addr(), v6 = in6_addr()
    return inet_pton(AF_INET, s, &v4) == 1 || inet_pton(AF_INET6, s, &v6) == 1
}

enum Page: Int, CaseIterable, Identifiable {
    case overview, active, history, events, trusted, settings
    var id: Int { rawValue }
    var title: String {
        switch self {
        case .overview: "Tổng quan"
        case .active: "Đang kết nối"
        case .history: "Lịch sử kết nối"
        case .events: "Sự kiện"
        case .trusted: "IP tin cậy"
        case .settings: "Cài đặt"
        }
    }
    var icon: String {
        switch self {
        case .overview: "lock.shield.fill"
        case .active: "dot.radiowaves.left.and.right"
        case .history: "clock.arrow.circlepath"
        case .events: "list.bullet.rectangle.fill"
        case .trusted: "checkmark.shield.fill"
        case .settings: "gearshape.fill"
        }
    }
    /// Màu ô biểu tượng trên thanh bên (kiểu System Settings)
    var color: Color {
        switch self {
        case .overview: .blue
        case .active: .green
        case .history: .indigo
        case .events: .red
        case .trusted: .teal
        case .settings: .gray
        }
    }
    /// nil = trang không có ô tìm kiếm trên toolbar
    var searchPrompt: String? {
        switch self {
        case .active, .history: "Tìm IP, dịch vụ, user"
        case .events: "Tìm sự kiện (-từ để loại trừ)"
        case .trusted: "Tìm IP"
        case .overview, .settings: nil
        }
    }
}

/// Thành phần chạy nền được app canh (daemon root, helper Endpoint Security)
struct Component: Hashable {
    let name: String
    let installed: Bool
    let running: Bool
}

enum TimeRange: Int, CaseIterable {
    case all, hour, today, week
    var title: String { switch self { case .all: "Mọi lúc"; case .hour: "1 giờ qua"; case .today: "Hôm nay"; case .week: "7 ngày qua" } }
    func contains(_ d: Date?) -> Bool {
        guard let d else { return self == .all }
        switch self {
        case .all: return true
        case .hour: return d > Date().addingTimeInterval(-3600)
        case .today: return Calendar.current.isDateInToday(d)
        case .week: return d > Date().addingTimeInterval(-7 * 86400)
        }
    }
}

/// Trạng thái giao diện — giữ nguyên khi đóng/mở lại cửa sổ
final class ViewState: ObservableObject {
    @Published var page: Page = .overview {
        didSet {
            guard page != oldValue, !restoring else { return }
            back.append(oldValue); forward.removeAll()
            if back.count > 50 { back.removeFirst() }
        }
    }
    // Điều hướng Quay lại / Tiếp (nút toolbar, ⌘[ ⌘], nút chuột, vuốt trackpad)
    @Published private(set) var back: [Page] = []
    @Published private(set) var forward: [Page] = []
    private var restoring = false

    func goBack() { move(from: &back, to: &forward) }
    func goForward() { move(from: &forward, to: &back) }
    private func move(from: inout [Page], to: inout [Page]) {
        guard let p = from.popLast() else { return }
        to.append(page)
        restoring = true; page = p; restoring = false
    }

    @Published var queries: [Page: String] = [:]
    @Published var toast: String?
    @Published var components: [Component] = []
    @Published var notificationsAllowed = false
    // Trang sự kiện
    @Published var selectedEvent: UInt64?
    @Published var eventLevel: LogEvent.Level?
    @Published var eventRange: TimeRange = .all
    // Trang lịch sử
    @Published var historyService = ""
    // Lựa chọn / sắp xếp của từng bảng (giữ nguyên khi chuyển trang)
    @Published var activeSelection = Set<String>()
    @Published var activeSort = [KeyPathComparator(\RemoteConnection.firstSeen)]
    @Published var historySelection = Set<UUID>()
    @Published var historySort = [KeyPathComparator(\HistoryEntry.start, order: .reverse)]
    @Published var trustedSelection = Set<String>()
    @Published var trustedSort = [KeyPathComparator(\TrustedRow.ip)]
    @Published var newTrustedIP = ""
    /// Từ khoá đã "lắng" 200ms sau lần gõ cuối — lọc theo bản này để gõ không bị giật với bảng lớn
    @Published var settled: [Page: String] = [:]
    let telegramForm = TelegramForm()

    func copy(_ text: String, _ message: String = "Đã sao chép") {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        flash(message)
    }

    func flash(_ message: String) {
        toast = message
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.6) { if self.toast == message { self.toast = nil } }
    }
}

/// Mức bảo vệ tổng hợp — dùng cho ô trạng thái đầu thanh bên và trang Tổng quan
struct Protection {
    let untrusted: [RemoteConnection]
    let missing: [Component]

    init(monitor: Monitor, ui: ViewState) {
        untrusted = monitor.active.filter { !monitor.isTrusted($0.ip) }
        missing = ui.components.filter { !$0.installed || !$0.running }
    }
    var color: Color { !untrusted.isEmpty ? .red : !missing.isEmpty ? .orange : .green }
    var icon: String { !untrusted.isEmpty ? "exclamationmark.shield.fill" : !missing.isEmpty ? "exclamationmark.triangle.fill" : "checkmark.shield.fill" }
    var title: String { !untrusted.isEmpty ? "Có truy cập từ IP lạ" : !missing.isEmpty ? "Bảo vệ chưa đầy đủ" : "Máy đang được bảo vệ" }
    var detail: String {
        !untrusted.isEmpty ? untrusted.map { "\($0.service) từ \($0.ip)" }.joined(separator: ", ")
            : !missing.isEmpty ? missing.map { "\($0.name): \($0.installed ? "không chạy" : "chưa cài")" }.joined(separator: " · ")
            : "Mọi thành phần giám sát đều đang chạy."
    }
}

// MARK: - Thanh bên

/// Ô biểu tượng vuông bo góc có màu, như các mục trong System Settings
struct SettingsIcon: View {
    let symbol: String
    let color: Color
    var size: CGFloat = 20
    var body: some View {
        RoundedRectangle(cornerRadius: size * 0.27, style: .continuous)
            .fill(color.gradient)
            .frame(width: size, height: size)
            .overlay(Image(systemName: symbol).font(.system(size: size * 0.55, weight: .semibold)).foregroundStyle(.white))
    }
}

struct SidebarView: View {
    @ObservedObject var monitor: Monitor
    @ObservedObject var ui: ViewState
    @ObservedObject var log: EventLog

    var alertsToday: Int { log.events.lazy.filter { $0.level == .alert && TimeRange.today.contains($0.date) }.count }

    var body: some View {
        let prot = Protection(monitor: monitor, ui: ui)
        List(selection: Binding(get: { ui.page }, set: { if let p = $0 { ui.page = p } })) {
            // Ô trạng thái đầu thanh bên (giống ô Apple Account) — mở trang Tổng quan
            HStack(spacing: 10) {
                Circle().fill(prot.color.gradient)
                    .frame(width: 34, height: 34)
                    .overlay(Image(systemName: prot.icon).font(.system(size: 16, weight: .semibold)).foregroundStyle(.white))
                VStack(alignment: .leading, spacing: 1) {
                    Text("MacSentry").font(.headline)
                    Text(prot.title).font(.subheadline).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            .padding(.vertical, 5)
            .tag(Page.overview)

            Section {
                row(.active, badge: monitor.active.count)
                row(.history)
                row(.events, badge: alertsToday)
            }
            Section {
                row(.trusted)
                row(.settings)
            }
        }
        .listStyle(.sidebar)
    }

    func row(_ p: Page, badge: Int = 0) -> some View {
        Label { Text(p.title) } icon: { SettingsIcon(symbol: p.icon, color: p.color) }
            .badge(badge)
            .tag(p)
    }
}

// MARK: - Trang chi tiết

struct DetailView: View {
    @ObservedObject var monitor: Monitor
    @ObservedObject var ui: ViewState
    @ObservedObject var log: EventLog

    var body: some View {
        page
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .overlay(alignment: .bottom) {
                if let t = ui.toast {
                    Label(t, systemImage: "checkmark.circle.fill")
                        .padding(.horizontal, 14).padding(.vertical, 8)
                        .background(.regularMaterial, in: Capsule())
                        .overlay(Capsule().strokeBorder(Color.primary.opacity(0.1)))
                        .padding(.bottom, 40)
                        .transition(.move(edge: .bottom).combined(with: .opacity))
                }
            }
            .animation(.easeOut(duration: 0.2), value: ui.toast)
    }

    @ViewBuilder var page: some View {
        switch ui.page {
        case .overview: OverviewPage(monitor: monitor, ui: ui, log: log)
        case .active: ActivePage(monitor: monitor, ui: ui)
        case .history: HistoryPage(monitor: monitor, ui: ui)
        case .events: EventsPage(ui: ui, log: log)
        case .trusted: TrustedPage(monitor: monitor, ui: ui)
        case .settings: SettingsPage(ui: ui, form: ui.telegramForm)
        }
    }
}

// MARK: - Thành phần dùng chung

/// Thanh lọc mảnh phía trên bảng (kiểu thanh lọc của Mail / Console)
struct FilterBar<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) { content }
                .padding(.horizontal, 14).padding(.vertical, 7)
            Divider()
        }
    }
}

struct EmptyState: View {
    let icon: String
    let title: String
    var message = ""

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: icon).font(.system(size: 40, weight: .light)).foregroundStyle(.tertiary)
            Text(title).font(.title3.weight(.medium))
            if !message.isEmpty {
                Text(message).foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 420)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}

/// Dòng trạng thái mảnh ở cuối trang (số dòng, thao tác phụ)
struct StatusBar<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        VStack(spacing: 0) {
            Divider()
            HStack(spacing: 12) { content }
                .font(.callout)
                .foregroundStyle(.secondary)
                .padding(.horizontal, 14).padding(.vertical, 6)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(.bar)
    }
}

/// Trạng thái kiểu System Settings: chấm màu + chữ phụ
struct StatusPill: View {
    let text: String
    let color: Color
    var body: some View {
        HStack(spacing: 6) {
            Circle().fill(color).frame(width: 8, height: 8)
            Text(text).foregroundStyle(.secondary)
        }
    }
}
