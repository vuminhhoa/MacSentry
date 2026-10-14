import SwiftUI
import AppKit

// MARK: - UI danh sách

let timeFmt: DateFormatter = { let f = DateFormatter(); f.dateFormat = "dd/MM/yyyy HH:mm:ss"; return f }()

func durationString(_ from: Date, _ to: Date) -> String {
    let s = Int(to.timeIntervalSince(from))
    if s < 60 { return "\(s)s" }
    if s < 3600 { return "\(s / 60)m \(s % 60)s" }
    return "\(s / 3600)h \((s % 3600) / 60)m"
}

final class ViewState: ObservableObject {
    @Published var tab = 0
    @Published var filter = ""
    @Published var events: [String] = []

    /// Đọc log sự kiện của daemon (mới nhất lên đầu). Log chỉ được ghi thêm, không xoay vòng → có thể rất lớn,
    /// nên chỉ đọc ~1 MB cuối file.
    func loadEvents() {
        guard let h = FileHandle(forReadingAtPath: Store.daemonLogPath) else { events = []; return }
        defer { try? h.close() }
        let size = (try? h.seekToEnd()) ?? 0
        let start = size > 1_000_000 ? size - 1_000_000 : 0
        try? h.seek(toOffset: start)
        var s = String(decoding: h.readDataToEndOfFile(), as: UTF8.self)
        if start > 0, let nl = s.firstIndex(of: "\n") { s = String(s[s.index(after: nl)...]) }   // bỏ dòng bị cắt dở
        events = s.split(separator: "\n").suffix(2000).reversed().map(String.init)
    }
}

struct ContentView: View {
    @ObservedObject var monitor: Monitor
    @ObservedObject var ui: ViewState
    var filter: String { ui.filter }

    var filteredHistory: [HistoryEntry] {
        filter.isEmpty ? monitor.history : monitor.history.filter {
            $0.ip.contains(filter) || ($0.user ?? "").contains(filter) || ($0.service ?? "SSH").contains(filter)
        }
    }
    var filteredEvents: [String] {
        filter.isEmpty ? ui.events : ui.events.filter { $0.localizedCaseInsensitiveContains(filter) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Picker("", selection: $ui.tab) {
                Text("Đang kết nối (\(monitor.active.count))").tag(0)
                Text("Lịch sử kết nối (\(monitor.history.count))").tag(1)
                Text("Sự kiện").tag(3)
                Text("IP tin cậy (\(monitor.trusted.count))").tag(2)
            }
            .pickerStyle(.segmented)
            .labelsHidden()

            switch ui.tab {
            case 0: activeTable
            case 1: historyTable
            case 3: eventsList
            default: trustedList
            }
        }
        .padding(12)
        .frame(minWidth: 760, minHeight: 420)
    }

    var activeTable: some View {
        Group {
            if monitor.active.isEmpty {
                VStack { Spacer(); Text("Không có kết nối truy cập từ xa nào.").foregroundStyle(.secondary); Spacer() }
                    .frame(maxWidth: .infinity)
            } else {
                Table(monitor.active) {
                    TableColumn("IP") { c in
                        HStack {
                            Image(systemName: monitor.trusted.contains(c.ip) ? "checkmark.shield.fill" : "exclamationmark.triangle.fill")
                                .foregroundStyle(monitor.trusted.contains(c.ip) ? .green : .orange)
                            Text(c.ip).textSelection(.enabled)
                        }
                    }
                    TableColumn("Dịch vụ") { Text($0.service) }.width(130)
                    TableColumn("Cổng / TTY") { Text($0.remotePort) }.width(80)
                    TableColumn("User") { Text($0.user ?? "—").foregroundStyle($0.user == nil ? .secondary : .primary) }
                    TableColumn("Bắt đầu") { Text(timeFmt.string(from: $0.firstSeen)) }
                    TableColumn("Thời lượng") { c in
                        TimelineView(.periodic(from: .now, by: 1)) { ctx in Text(durationString(c.firstSeen, ctx.date)) }
                    }.width(80)
                    TableColumn("") { c in
                        Button(monitor.trusted.contains(c.ip) ? "Bỏ tin cậy" : "Tin cậy") { monitor.toggleTrust(c.ip) }
                    }.width(90)
                }
            }
        }
    }

    var historyTable: some View {
        VStack(alignment: .leading) {
            HStack {
                TextField("Lọc theo IP, user hoặc dịch vụ…", text: $ui.filter).textFieldStyle(.roundedBorder)
                Button("Mở thư mục dữ liệu") { NSWorkspace.shared.open(Store.dir) }
            }
            Table(filteredHistory) {
                TableColumn("IP") { Text($0.ip).textSelection(.enabled) }
                TableColumn("Dịch vụ") { Text($0.service ?? "SSH") }.width(130)
                TableColumn("User") { Text($0.user ?? "—") }
                TableColumn("Bắt đầu") { Text(timeFmt.string(from: $0.start)) }
                TableColumn("Kết thúc") { e in
                    if let end = e.end { Text(timeFmt.string(from: end)) } else { Text("đang kết nối").foregroundStyle(.green) }
                }
                TableColumn("Thời lượng") { e in Text(durationString(e.start, e.end ?? Date())) }.width(80)
            }
        }
    }

    var eventsList: some View {
        VStack(alignment: .leading) {
            HStack {
                TextField("Lọc sự kiện…", text: $ui.filter).textFieldStyle(.roundedBorder)
                Button("Làm mới") { ui.loadEvents() }
            }
            if !Telegram.daemonInstalled {
                Text("Chưa cài macsentryd — chạy: sudo ~/MacSentry/daemon/install.sh")
                    .font(.caption).foregroundStyle(.orange)
            }
            // id theo vị trí: log có thể có các dòng trùng nhau (cùng nội dung, cùng giây) → id: \.self làm SwiftUI nhầm hàng
            List(Array(filteredEvents.enumerated()), id: \.offset) { Text($0.element).font(.system(.body, design: .monospaced)).textSelection(.enabled) }
        }
        .onAppear { ui.loadEvents() }
    }

    var trustedList: some View {
        VStack(alignment: .leading) {
            Text("IP tin cậy vẫn được ghi lịch sử, nhưng không bật popup cảnh báo. (Máy chủ tin cậy cho cảnh báo reverse shell của daemon là danh sách khác: sudo nano /etc/macsentry.trusted)")
                .font(.caption).foregroundStyle(.secondary)
            List {
                ForEach(monitor.trusted.sorted(), id: \.self) { ip in
                    HStack { Text(ip); Spacer(); Button("Xoá") { monitor.toggleTrust(ip) } }
                }
            }
        }
    }
}
