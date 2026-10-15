import SwiftUI
import AppKit

// MARK: - Trang Đang kết nối / Lịch sử kết nối / IP tin cậy

extension RemoteConnection {
    var userText: String { user ?? "" }
    var line: String { "\(service)\t\(ip):\(remotePort)\t\(user ?? "-")\t\(timeFmt.string(from: firstSeen))" }
}

extension HistoryEntry {
    var serviceText: String { service ?? "SSH" }
    var userText: String { user ?? "" }
    var endSort: Date { end ?? .distantFuture }
    var duration: TimeInterval { (end ?? Date()).timeIntervalSince(start) }
    var line: String {
        "\(serviceText)\t\(ip):\(remotePort)\t\(user ?? "-")\t\(timeFmt.string(from: start))\t\(end.map { timeFmt.string(from: $0) } ?? "đang kết nối")"
    }
}

/// Mục menu chuột phải chung cho các bảng có cột IP
@ViewBuilder func ipMenu(_ ips: [String], lines: [String], monitor: Monitor, ui: ViewState) -> some View {
    if !ips.isEmpty {
        Button(ips.count == 1 ? "Sao chép IP" : "Sao chép \(ips.count) IP") { ui.copy(ips.joined(separator: "\n")) }
        Button(lines.count == 1 ? "Sao chép dòng" : "Sao chép \(lines.count) dòng") { ui.copy(lines.joined(separator: "\n")) }
        Divider()
        let allTrusted = ips.allSatisfy { monitor.trusted.contains($0) }
        Button(allTrusted ? "Bỏ tin cậy" : "Đánh dấu tin cậy") { monitor.setTrust(ips, !allTrusted) }
    }
}

struct TrustBadge: View {
    let trusted: Bool
    var body: some View {
        Image(systemName: trusted ? "checkmark.shield.fill" : "exclamationmark.triangle.fill")
            .foregroundStyle(trusted ? .green : .orange)
            .help(trusted ? "IP tin cậy" : "IP chưa được tin cậy")
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
        VStack(spacing: 0) {
            if monitor.active.isEmpty {
                EmptyState(icon: "lock.shield", title: "Không có truy cập từ xa",
                           message: "Khi có ai kết nối vào máy qua SSH, Screen Sharing, SMB… phiên đó sẽ hiện ở đây và bạn nhận cảnh báo ngay.")
            } else {
                let data = rows
                Table(data, selection: $ui.activeSelection, sortOrder: $ui.activeSort) {
                    TableColumn("IP", value: \.ip) { c in
                        HStack(spacing: 6) { TrustBadge(trusted: monitor.isTrusted(c.ip)); Text(c.ip) }
                    }.width(min: 120, ideal: 160)
                    TableColumn("Dịch vụ", value: \.service).width(min: 90, ideal: 130)
                    TableColumn("Cổng / TTY", value: \.remotePort).width(min: 60, ideal: 80)
                    TableColumn("User", value: \.userText) { c in
                        Text(c.user ?? "—").foregroundStyle(c.user == nil ? .secondary : .primary)
                    }.width(min: 50, ideal: 80)
                    TableColumn("Bắt đầu", value: \.firstSeen) { Text(timeFmt.string(from: $0.firstSeen)).monospacedDigit() }
                        .width(min: 125, ideal: 140)
                    TableColumn("Thời lượng") { c in
                        TimelineView(.periodic(from: .now, by: 1)) { ctx in Text(durationString(c.firstSeen, ctx.date)).monospacedDigit() }
                    }.width(min: 60, ideal: 80)
                }
                .tableStyle(.inset(alternatesRowBackgrounds: true))
                .contextMenu(forSelectionType: String.self) { ids in
                    let p = picked(ids)
                    ipMenu(Array(Set(p.map(\.ip))).sorted(), lines: p.map(\.line), monitor: monitor, ui: ui)
                } primaryAction: { ids in
                    ui.copy(picked(ids).map(\.ip).joined(separator: "\n"), "Đã sao chép IP")
                }
                .onCopyCommand { [NSItemProvider(object: picked(ui.activeSelection).map(\.line).joined(separator: "\n") as NSString)] }
                StatusBar {
                    Text("\(data.count) phiên")
                    let n = monitor.active.filter { !monitor.isTrusted($0.ip) }.count
                    if n > 0 { Label("\(n) từ IP chưa tin cậy", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange) }
                    Spacer()
                    Text("Nhấp đúp để sao chép IP · chuột phải để thêm thao tác")
                }
            }
        }
    }
}

struct HistoryPage: View {
    @ObservedObject var monitor: Monitor
    @ObservedObject var ui: ViewState

    var services: [String] { Array(Set(monitor.history.map(\.serviceText))).sorted() }

    var rows: [HistoryEntry] {
        let q = SearchQuery(ui.settled[.history] ?? "")
        let svc = ui.historyService
        return monitor.history.filter {
            (svc.isEmpty || $0.serviceText == svc) && (q.isEmpty || q.matches($0.ip, $0.serviceText, $0.userText, $0.remotePort))
        }.sorted(using: ui.historySort)
    }
    func picked(_ ids: Set<UUID>) -> [HistoryEntry] { monitor.history.filter { ids.contains($0.id) } }

    var body: some View {
        VStack(spacing: 0) {
            FilterBar {
                Text("Dịch vụ:").foregroundStyle(.secondary)
                Picker("Dịch vụ", selection: $ui.historyService) {
                    Text("Mọi dịch vụ").tag("")
                    Divider()
                    ForEach(services, id: \.self) { Text($0).tag($0) }
                }
                .labelsHidden()
                .fixedSize()
                Spacer()
                Text("Lưu tối đa 2.000 phiên gần nhất").foregroundStyle(.secondary)
            }
            .task(id: ui.queries[.history] ?? "") {
                try? await Task.sleep(nanoseconds: 200_000_000)
                ui.settled[.history] = ui.queries[.history] ?? ""
            }
            if monitor.history.isEmpty {
                EmptyState(icon: "clock", title: "Chưa có lịch sử", message: "Mỗi phiên truy cập từ xa sẽ được ghi lại tại đây.")
            } else {
                let data = rows
                Table(data, selection: $ui.historySelection, sortOrder: $ui.historySort) {
                    TableColumn("IP", value: \.ip) { e in
                        HStack(spacing: 6) { TrustBadge(trusted: monitor.isTrusted(e.ip)); Text(e.ip) }
                    }.width(min: 120, ideal: 160)
                    TableColumn("Dịch vụ", value: \.serviceText).width(min: 90, ideal: 130)
                    TableColumn("User", value: \.userText) { e in
                        Text(e.user ?? "—").foregroundStyle(e.user == nil ? .secondary : .primary)
                    }.width(min: 50, ideal: 80)
                    TableColumn("Bắt đầu", value: \.start) { Text(timeFmt.string(from: $0.start)).monospacedDigit() }
                        .width(min: 125, ideal: 140)
                    TableColumn("Kết thúc", value: \.endSort) { e in
                        if let end = e.end { Text(timeFmt.string(from: end)).monospacedDigit() }
                        else { StatusPill(text: "đang mở", color: .green) }
                    }.width(min: 125, ideal: 140)
                    TableColumn("Thời lượng", value: \.duration) { Text(durationString($0.start, $0.end ?? Date())).monospacedDigit() }
                        .width(min: 60, ideal: 80)
                }
                .tableStyle(.inset(alternatesRowBackgrounds: true))
                .contextMenu(forSelectionType: UUID.self) { ids in
                    let p = picked(ids)
                    ipMenu(Array(Set(p.map(\.ip))).sorted(), lines: p.map(\.line), monitor: monitor, ui: ui)
                } primaryAction: { ids in
                    ui.copy(picked(ids).map(\.ip).joined(separator: "\n"), "Đã sao chép IP")
                }
                .onCopyCommand { [NSItemProvider(object: picked(ui.historySelection).map(\.line).joined(separator: "\n") as NSString)] }
                .overlay { if data.isEmpty { EmptyState(icon: "magnifyingglass", title: "Không có kết quả", message: "Thử từ khoá khác hoặc bỏ lọc dịch vụ.") } }
                StatusBar {
                    Text(data.count == monitor.history.count ? "\(data.count) phiên" : "\(data.count) / \(monitor.history.count) phiên")
                    if !ui.historySelection.isEmpty { Text("· đã chọn \(ui.historySelection.count)") }
                    Spacer()
                    Button("Mở thư mục dữ liệu") { NSWorkspace.shared.open(Store.dir) }.buttonStyle(.link)
                }
            }
        }
    }
}

struct TrustedRow: Identifiable, Hashable {
    let ip: String
    let count: Int
    let last: Date?
    var id: String { ip }
    var lastSort: Date { last ?? .distantPast }
}

struct TrustedPage: View {
    @ObservedObject var monitor: Monitor
    @ObservedObject var ui: ViewState

    var rows: [TrustedRow] {
        let q = SearchQuery(ui.queries[.trusted] ?? "")
        var stats: [String: (Int, Date)] = [:]
        for e in monitor.history where monitor.trusted.contains(e.ip) {
            let s = stats[e.ip]
            stats[e.ip] = ((s?.0 ?? 0) + 1, max(s?.1 ?? .distantPast, e.start))
        }
        return monitor.trusted.filter { q.isEmpty || q.matches($0) }
            .map { TrustedRow(ip: $0, count: stats[$0]?.0 ?? 0, last: stats[$0]?.1) }
            .sorted(using: ui.trustedSort)
    }

    var trimmed: String { ui.newTrustedIP.trimmingCharacters(in: .whitespacesAndNewlines) }
    var canAdd: Bool { isValidIP(trimmed) && !monitor.trusted.contains(trimmed) }

    func add() {
        guard canAdd else { return }
        monitor.setTrust([trimmed], true)
        ui.flash("Đã thêm \(trimmed)")
        ui.newTrustedIP = ""
    }

    var body: some View {
        VStack(spacing: 0) {
            FilterBar {
                TextField("Thêm IP (IPv4 hoặc IPv6)", text: $ui.newTrustedIP)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 320)
                    .onSubmit(add)
                Button("Thêm", action: add).disabled(!canAdd)
                if !trimmed.isEmpty && !isValidIP(trimmed) {
                    Text("IP không hợp lệ").font(.callout).foregroundStyle(.red)
                } else if monitor.trusted.contains(trimmed) {
                    Text("Đã có trong danh sách").font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                Text("Không bật popup cảnh báo cho các IP này").foregroundStyle(.secondary)
            }
            if monitor.trusted.isEmpty {
                EmptyState(icon: "checkmark.shield", title: "Chưa có IP tin cậy",
                           message: "Thêm IP ở trên, hoặc chuột phải vào một kết nối trong Đang kết nối / Lịch sử → Đánh dấu tin cậy.")
            } else {
                Table(rows, selection: $ui.trustedSelection, sortOrder: $ui.trustedSort) {
                    TableColumn("IP", value: \.ip)
                    TableColumn("Số lần kết nối", value: \.count) { Text("\($0.count)").monospacedDigit() }.width(min: 90, ideal: 110)
                    TableColumn("Kết nối gần nhất", value: \.lastSort) { r in
                        Text(r.last.map { timeFmt.string(from: $0) } ?? "—").monospacedDigit()
                            .foregroundStyle(r.last == nil ? .secondary : .primary)
                    }.width(min: 130, ideal: 160)
                }
                .tableStyle(.inset(alternatesRowBackgrounds: true))
                .contextMenu(forSelectionType: String.self) { ids in
                    if !ids.isEmpty {
                        Button("Sao chép") { ui.copy(ids.sorted().joined(separator: "\n")) }
                        Divider()
                        Button("Xoá khỏi danh sách") { monitor.setTrust(Array(ids), false); ui.trustedSelection.subtract(ids) }
                    }
                } primaryAction: { ids in ui.copy(ids.sorted().joined(separator: "\n")) }
                .onCopyCommand { [NSItemProvider(object: ui.trustedSelection.sorted().joined(separator: "\n") as NSString)] }
                .onDeleteCommand { monitor.setTrust(Array(ui.trustedSelection), false); ui.trustedSelection.removeAll() }
                StatusBar {
                    Text("\(monitor.trusted.count) IP")
                    Spacer()
                    Text("Chọn rồi bấm ⌫ để xoá · máy chủ tin cậy cho cảnh báo reverse shell nằm ở /etc/macsentry.trusted")
                        .lineLimit(1).truncationMode(.middle)
                }
            }
        }
    }
}
