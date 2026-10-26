import SwiftUI
import AppKit

// MARK: - Trang Đang kết nối / Lịch sử kết nối / IP tin cậy

extension RemoteConnection {
    var userText: String { user ?? "" }
    var line: String { "\(serviceName)\t\(ip):\(remotePort)\t\(user ?? "-")\t\(timeFmt.string(from: firstSeen))" }
}

extension HistoryEntry {
    var serviceText: String { service ?? "SSH" }
    var serviceName: String { L(serviceText) }
    var userText: String { user ?? "" }
    var endSort: Date { end ?? .distantFuture }
    var duration: TimeInterval { (end ?? Date()).timeIntervalSince(start) }
    var line: String {
        "\(serviceName)\t\(ip):\(remotePort)\t\(user ?? "-")\t\(timeFmt.string(from: start))\t\(end.map { timeFmt.string(from: $0) } ?? L("đang kết nối"))"
    }
}

/// Mục menu chuột phải chung cho các bảng có cột IP
@ViewBuilder func ipMenu(_ ips: [String], lines: [String], monitor: Monitor, ui: ViewState) -> some View {
    if !ips.isEmpty {
        Button(ips.count == 1 ? L("Sao chép IP") : L("Sao chép %ld IP", ips.count), systemImage: "doc.on.doc") { ui.copy(ips.joined(separator: "\n")) }
        Button(lines.count == 1 ? L("Sao chép dòng") : L("Sao chép %ld dòng", lines.count), systemImage: "list.bullet") { ui.copy(lines.joined(separator: "\n")) }
        Divider()
        let allTrusted = ips.allSatisfy { monitor.trusted.contains($0) }
        Button(allTrusted ? L("Bỏ tin cậy") : L("Đánh dấu tin cậy"), systemImage: allTrusted ? "xmark.shield" : "checkmark.shield") { monitor.setTrust(ips, !allTrusted) }
    }
}

struct TrustBadge: View {
    let trusted: Bool
    var body: some View {
        Image(systemName: trusted ? "checkmark.shield.fill" : "exclamationmark.triangle.fill")
            .foregroundStyle(trusted ? .green : .orange)
            .help(trusted ? L("IP tin cậy") : L("IP chưa được tin cậy"))
    }
}

struct ActivePage: View {
    @ObservedObject var monitor: Monitor
    @ObservedObject var ui: ViewState

    var rows: [RemoteConnection] {
        let q = SearchQuery(ui.queries[.active] ?? "")
        return monitor.active.filter { q.isEmpty || q.matches($0.ip, $0.service, $0.remotePort, $0.userText) }.sorted(using: ui.activeSort)
    }
    func picked(_ ids: Set<String>) -> [RemoteConnection] { monitor.active.filter { ids.contains($0.id) } }

    var body: some View {
        Group {
            if monitor.active.isEmpty {
                EmptyState(icon: "lock.shield", title: L("Không có truy cập từ xa"),
                           message: L("Khi có ai kết nối vào máy qua SSH, Screen Sharing, SMB… phiên đó sẽ hiện ở đây và bạn nhận cảnh báo ngay."))
            } else {
                let data = rows
                Table(data, selection: $ui.activeSelection, sortOrder: $ui.activeSort, columnCustomization: $ui.activeColumns) {
                    TableColumn("IP", value: \.ip) { c in
                        HStack(spacing: 6) { TrustBadge(trusted: monitor.isTrusted(c.ip)); Text(c.ip) }
                    }
                    .width(min: 110, ideal: 140)
                    .customizationID("ip")
                    .disabledCustomizationBehavior(.visibility)
                    TableColumn(L("Dịch vụ"), value: \.serviceName).width(min: 80, ideal: 130).customizationID("service")
                    TableColumn(L("Cổng / TTY"), value: \.remotePort).width(min: 50, ideal: 75).customizationID("port")
                    TableColumn("User", value: \.userText) { c in
                        Text(c.user ?? "—").foregroundStyle(c.user == nil ? .secondary : .primary)
                    }
                    .width(min: 50, ideal: 70)
                    .customizationID("user")
                    TableColumn(L("Bắt đầu"), value: \.firstSeen) { DateText(date: $0.firstSeen) }
                        .width(min: 70, ideal: 145)
                        .customizationID("start")
                    // Cột cuối: tự lấp phần còn lại, không kéo mép phải / ẩn
                    TableColumn(L("Thời lượng")) { c in
                        TimelineView(.periodic(from: .now, by: 1)) { ctx in Text(durationString(c.firstSeen, ctx.date)).monospacedDigit() }
                    }
                    .width(min: 70)
                    .customizationID("duration")
                    .disabledCustomizationBehavior([.resize, .visibility])
                }
                .tableStyle(.bordered(alternatesRowBackgrounds: true))
                .contextMenu(forSelectionType: String.self) { ids in
                    let p = picked(ids)
                    ipMenu(Array(Set(p.map(\.ip))).sorted(), lines: p.map(\.line), monitor: monitor, ui: ui)
                } primaryAction: { ids in
                    ui.copy(picked(ids).map(\.ip).joined(separator: "\n"), L("Đã sao chép IP"))
                }
                .onCopyCommand { [NSItemProvider(object: picked(ui.activeSelection).map(\.line).joined(separator: "\n") as NSString)] }
                .overlay { if data.isEmpty { EmptyState(icon: "magnifyingglass", title: L("Không có kết quả"), message: L("Thử từ khoá khác.")) } }
                .safeAreaBar(edge: .bottom) {
                    StatusBar {
                        Text(Lplural("%ld phiên", data.count))
                        let n = monitor.active.filter { !monitor.isTrusted($0.ip) }.count
                        if n > 0 { Label(Lplural("%ld từ IP chưa tin cậy", n), systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange) }
                        Spacer()
                        Text(L("Nhấp đúp để sao chép IP · chuột phải để thêm thao tác"))
                    }
                }
            }
        }
    }
}

struct HistoryPage: View {
    @ObservedObject var monitor: Monitor
    @ObservedObject var ui: ViewState

    var services: [String] { Array(Set(monitor.history.map(\.serviceText))).sorted() }

    /// Lọc + sắp xếp ngoài `body`: chỉ tính lại khi lịch sử / bộ lọc / thứ tự đổi
    var rows: [HistoryEntry] {
        let key = HistoryKey(history: monitor.history, query: ui.settled[.history] ?? "", service: ui.historyService, sort: ui.historySort)
        return ui.historyRows.get(key) {
            let q = SearchQuery(key.query)
            return monitor.history.filter {
                (key.service.isEmpty || $0.serviceText == key.service) && (q.isEmpty || q.matches($0.ip, $0.serviceText, $0.userText, $0.remotePort))
            }.sorted(using: key.sort)
        }
    }
    func picked(_ ids: Set<UUID>) -> [HistoryEntry] { monitor.history.filter { ids.contains($0.id) } }

    var body: some View {
        Group {
            if monitor.history.isEmpty {
                EmptyState(icon: "clock", title: L("Chưa có lịch sử"), message: L("Mỗi phiên truy cập từ xa sẽ được ghi lại tại đây."))
            } else {
                let data = rows
                Table(data, selection: $ui.historySelection, sortOrder: $ui.historySort, columnCustomization: $ui.historyColumns) {
                    TableColumn("IP", value: \.ip) { e in
                        HStack(spacing: 6) { TrustBadge(trusted: monitor.isTrusted(e.ip)); Text(e.ip) }
                    }
                    .width(min: 110, ideal: 140)
                    .customizationID("ip")
                    .disabledCustomizationBehavior(.visibility)
                    TableColumn(L("Dịch vụ"), value: \.serviceName).width(min: 80, ideal: 120).customizationID("service")
                    TableColumn("User", value: \.userText) { e in
                        Text(e.user ?? "—").foregroundStyle(e.user == nil ? .secondary : .primary)
                    }
                    .width(min: 50, ideal: 65)
                    .customizationID("user")
                    TableColumn(L("Bắt đầu"), value: \.start) { DateText(date: $0.start) }
                        .width(min: 70, ideal: 145)
                        .customizationID("start")
                    TableColumn(L("Kết thúc"), value: \.endSort) { e in
                        if let end = e.end { DateText(date: end) }
                        else { StatusPill(text: L("đang mở"), color: .green) }
                    }
                    .width(min: 70, ideal: 145)
                    .customizationID("end")
                    // Cột cuối: tự lấp phần còn lại, không kéo mép phải / ẩn
                    TableColumn(L("Thời lượng"), value: \.duration) { e in
                        if let end = e.end { Text(durationString(e.start, end)).monospacedDigit() }
                        else { TimelineView(.periodic(from: .now, by: 1)) { ctx in Text(durationString(e.start, ctx.date)).monospacedDigit() } }
                    }
                    .width(min: 70)
                    .customizationID("duration")
                    .disabledCustomizationBehavior([.resize, .visibility])
                }
                .tableStyle(.bordered(alternatesRowBackgrounds: true))
                .contextMenu(forSelectionType: UUID.self) { ids in
                    let p = picked(ids)
                    ipMenu(Array(Set(p.map(\.ip))).sorted(), lines: p.map(\.line), monitor: monitor, ui: ui)
                } primaryAction: { ids in
                    ui.copy(picked(ids).map(\.ip).joined(separator: "\n"), L("Đã sao chép IP"))
                }
                .onCopyCommand { [NSItemProvider(object: picked(ui.historySelection).map(\.line).joined(separator: "\n") as NSString)] }
                .overlay { if data.isEmpty { EmptyState(icon: "magnifyingglass", title: L("Không có kết quả"), message: L("Thử từ khoá khác hoặc bỏ lọc dịch vụ.")) } }
                .safeAreaBar(edge: .bottom) {
                    StatusBar {
                        Text(data.count == monitor.history.count ? Lplural("%ld phiên", data.count) : "\(data.count) / " + Lplural("%ld phiên", monitor.history.count))
                        if !ui.historySelection.isEmpty { Text(L("· đã chọn %ld", ui.historySelection.count)) }
                        Spacer()
                        Button(L("Mở thư mục dữ liệu")) { NSWorkspace.shared.open(Store.dir) }.buttonStyle(.link)
                    }
                }
            }
        }
        .topBar {
            FilterBar {
                Picker(L("Dịch vụ:"), selection: $ui.historyService) {
                    Text(L("Mọi dịch vụ")).tag("")
                    Divider()
                    ForEach(services, id: \.self) { Text(L($0)).tag($0) }
                }
                .fixedSize()
                Spacer()
                Text(L("Lưu tối đa 2.000 phiên gần nhất")).foregroundStyle(.secondary)
            }
        }
        .task(id: ui.queries[.history] ?? "") {
            try? await Task.sleep(nanoseconds: 200_000_000)
            ui.settled[.history] = ui.queries[.history] ?? ""
        }
    }
}

/// IP kèm thống kê lấy từ lịch sử kết nối
struct TrustedRow: Identifiable, Hashable {
    let ip: String
    let count: Int
    let last: Date?
    var id: String { ip }

    var detail: String {
        guard let last else { return L("Chưa từng kết nối") }
        return Lplural("%ld lần · gần nhất %@", count, timeFmt.string(from: last))
    }
}

/// Danh sách cho phép kiểu System Settings: Form nhóm, mỗi IP một dòng, ô thêm ở cuối nhóm,
/// gợi ý các IP đã từng kết nối để tin cậy nhanh
struct TrustedPage: View {
    @ObservedObject var monitor: Monitor
    @ObservedObject var ui: ViewState

    /// Số lần / lần gần nhất của mỗi IP trong lịch sử (bỏ kết nối từ chính máy này)
    var stats: [String: (count: Int, last: Date)] {
        var r: [String: (count: Int, last: Date)] = [:]
        for e in monitor.history where !(e.ip.hasPrefix("127.") || e.ip == "::1" || e.ip == "localhost") {
            let s = r[e.ip]
            r[e.ip] = ((s?.count ?? 0) + 1, max(s?.last ?? .distantPast, e.start))
        }
        return r
    }

    var trimmed: String { ui.newTrustedIP.trimmingCharacters(in: .whitespacesAndNewlines) }
    var canAdd: Bool { isValidIP(trimmed) && !monitor.trusted.contains(trimmed) }

    func add() {
        guard canAdd else { return }
        monitor.setTrust([trimmed], true)
        ui.flash(L("Đã thêm %@", trimmed))
        ui.newTrustedIP = ""
    }

    func remove(_ ip: String) {
        monitor.setTrust([ip], false)
        ui.flash(L("Đã bỏ tin cậy %@", ip))
    }

    var body: some View {
        let stats = stats
        let q = SearchQuery(ui.queries[.trusted] ?? "")
        let rows = monitor.trusted.filter { q.isEmpty || q.matches($0) }
            .map { TrustedRow(ip: $0, count: stats[$0]?.count ?? 0, last: stats[$0]?.last) }
            .sorted { ($0.last ?? .distantPast, $1.ip) > ($1.last ?? .distantPast, $0.ip) }
        let suggestions = stats.filter { !monitor.trusted.contains($0.key) && (q.isEmpty || q.matches($0.key)) }
            .map { TrustedRow(ip: $0.key, count: $0.value.count, last: $0.value.last) }
            .sorted { $0.last! > $1.last! }
            .prefix(8)

        Form {
            Section {
                VStack(spacing: 8) {
                    SettingsIcon(symbol: Page.trusted.icon, color: Page.trusted.color, size: 56)
                    Text(L("IP tin cậy")).font(.title2.weight(.semibold))
                    Text(L("Kết nối từ các IP này không bật popup cảnh báo; thông báo và tin Telegram vẫn được gửi nhưng không kêu chuông."))
                        .foregroundStyle(.secondary).multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 8)
            }

            Section {
                if rows.isEmpty {
                    Text(monitor.trusted.isEmpty ? L("Chưa có IP nào.") : L("Không có IP khớp với từ khoá.")).foregroundStyle(.secondary)
                }
                ForEach(rows) { r in
                    HStack(spacing: 10) {
                        Image(systemName: "checkmark.shield.fill").foregroundStyle(.green)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(r.ip).font(.body.monospaced()).textSelection(.enabled)
                            Text(r.detail).font(.callout).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button { ui.copy(r.ip) } label: { Image(systemName: "doc.on.doc") }
                            .buttonStyle(.borderless).help(L("Sao chép IP"))
                        Button { remove(r.ip) } label: { Image(systemName: "minus.circle.fill") }
                            .buttonStyle(.borderless).foregroundStyle(.red).help(L("Bỏ tin cậy"))
                    }
                    .contextMenu {
                        Button(L("Sao chép IP"), systemImage: "doc.on.doc") { ui.copy(r.ip) }
                        Divider()
                        Button(L("Bỏ tin cậy"), systemImage: "xmark.shield", role: .destructive) { remove(r.ip) }
                    }
                }
                // Dòng thêm IP ở cuối nhóm, như các danh sách trong System Settings
                HStack {
                    TextField(L("Thêm IP"), text: $ui.newTrustedIP, prompt: Text(L("IPv4 hoặc IPv6, vd. 192.168.1.10")))
                        .labelsHidden()
                        .textFieldStyle(.roundedBorder)
                        .onSubmit(add)
                    Button(L("Thêm"), action: add).disabled(!canAdd)
                }
            } header: {
                Text(L("Đã tin cậy (%ld)", monitor.trusted.count))
            } footer: {
                if !trimmed.isEmpty && !isValidIP(trimmed) {
                    Text(L("IP không hợp lệ.")).foregroundStyle(.red)
                } else if monitor.trusted.contains(trimmed) {
                    Text(L("IP này đã có trong danh sách.")).foregroundStyle(.secondary)
                }
            }

            if !suggestions.isEmpty {
                Section {
                    ForEach(Array(suggestions)) { r in
                        HStack(spacing: 10) {
                            TrustBadge(trusted: false)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(r.ip).font(.body.monospaced()).textSelection(.enabled)
                                Text(r.detail).font(.callout).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button(L("Tin cậy")) { monitor.setTrust([r.ip], true); ui.flash(L("Đã tin cậy %@", r.ip)) }
                        }
                    }
                } header: {
                    Text(L("Đã từng kết nối, chưa tin cậy"))
                } footer: {
                    Text(L("Chỉ tin cậy IP bạn nhận ra (máy của bạn, mạng nội bộ, VPN công ty).")).foregroundStyle(.secondary)
                }
            }

            Section {
                LabeledContent {
                    Button(L("Hiện trong Finder")) {
                        NSWorkspace.shared.selectFile("/etc/macsentry.trusted", inFileViewerRootedAtPath: "")
                    }
                } label: {
                    Text(L("Máy chủ tin cậy của daemon"))
                    Text(L("Danh sách khác, dùng cho cảnh báo kết nối ra ngoài (reverse shell). Sửa bằng: %@", "sudo nano /etc/macsentry.trusted"))
                }
            }
        }
        .formStyle(.grouped)
    }
}

struct HistoryKey: Equatable {
    let history: [HistoryEntry]
    let query: String
    let service: String
    let sort: [KeyPathComparator<HistoryEntry>]
}
