import SwiftUI
import AppKit

// MARK: - Trang Sự kiện: bảng log (mới nhất trên cùng) + khung chi tiết, kiểu Console.app

struct LevelIcon: View {
    let level: LogEvent.Level
    var body: some View {
        switch level {
        case .alert: Image(systemName: "exclamationmark.octagon.fill").foregroundStyle(.red)
        case .notice: Image(systemName: "exclamationmark.circle.fill").foregroundStyle(.orange)
        case .info: Image(systemName: "info.circle").foregroundStyle(.secondary)
        }
    }
}

struct EventsPage: View {
    @ObservedObject var ui: ViewState
    @ObservedObject var log: EventLog
    var query: String { ui.settled[.events] ?? "" }

    var rows: [LogEvent] {
        let q = SearchQuery(query)
        let level = ui.eventLevel, range = ui.eventRange
        if q.isEmpty && level == nil && range == .all { return log.events }
        return log.events.filter {
            (level == nil || $0.level == level) && range.contains($0.date) && (q.isEmpty || q.matches($0.key))
        }
    }
    var filtering: Bool { !query.isEmpty || ui.eventLevel != nil || ui.eventRange != .all }
    var selected: LogEvent? { ui.selectedEvent.flatMap { id in log.events.first { $0.id == id } } }

    var body: some View {
        VStack(spacing: 0) {
            filterBar
            .task(id: ui.queries[.events] ?? "") {
                try? await Task.sleep(nanoseconds: 200_000_000)
                ui.settled[.events] = ui.queries[.events] ?? ""
                // Tìm kiếm phải thấy cả phần log cũ chưa tải
                if !query.isEmpty && log.hasOlder { log.loadOlder(all: true) }
            }
            if log.unreadable && log.events.isEmpty {
                EmptyState(icon: "doc.questionmark", title: "Không đọc được log",
                           message: Telegram.daemonInstalled ? "Chưa có file \(Store.daemonLogPath)."
                               : "Chưa cài macsentryd. Cài bằng lệnh: sudo ~/MacSentry/daemon/install.sh")
            } else {
                VSplitView {
                    table.frame(minHeight: 180)
                    detail.frame(minHeight: 90, idealHeight: 170)
                }
            }
            statusBar
        }
    }

    var filterBar: some View {
        FilterBar {
            Picker("Mức độ", selection: $ui.eventLevel) {
                Text("Tất cả").tag(LogEvent.Level?.none)
                ForEach(LogEvent.Level.allCases.reversed(), id: \.self) { Text($0.title).tag(LogEvent.Level?.some($0)) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            Picker("Thời gian", selection: $ui.eventRange) {
                ForEach(TimeRange.allCases, id: \.self) { Text($0.title).tag($0) }
            }
            .labelsHidden()
            .fixedSize()
            if filtering {
                Button("Bỏ lọc") {
                    ui.queries[.events] = ""; ui.eventLevel = nil; ui.eventRange = .all
                }.buttonStyle(.link)
            }
            Spacer()
            Toggle(isOn: $log.live) { Label("Tự cập nhật", systemImage: "dot.radiowaves.up.forward") }
                .toggleStyle(.button)
                .help("Tự hiện sự kiện mới khi daemon ghi log")
            Button { log.refresh() } label: { Image(systemName: "arrow.clockwise") }
                .help("Tải lại ngay")
        }
    }

    var table: some View {
        let data = rows
        let lastID = data.last?.id
        return Table(data, selection: $ui.selectedEvent) {
            TableColumn("") { e in LevelIcon(level: e.level) }.width(18)
            TableColumn("Thời gian") { e in
                Text(e.time).monospacedDigit().foregroundStyle(.secondary)
                    // Cuộn tới dòng cuối → đọc thêm phần log cũ hơn (bảng chỉ dựng các dòng đang hiển thị)
                    .onAppear { if e.id == lastID && log.hasOlder { log.loadOlder() } }
            }.width(min: 130, ideal: 140, max: 160)
            TableColumn("Nội dung") { e in
                Text(e.text).lineLimit(1).help(e.text)
                    .fontWeight(e.level == .alert ? .medium : .regular)
            }
        }
        .tableStyle(.inset(alternatesRowBackgrounds: true))
        .contextMenu(forSelectionType: UInt64.self) { ids in
            if let e = ids.first.flatMap({ id in log.events.first { $0.id == id } }) {
                Button("Sao chép dòng") { ui.copy(e.line) }
                Button("Sao chép nội dung") { ui.copy(e.text) }
                Divider()
                Button("Lọc sự kiện cùng loại") {
                    ui.queries[.events] = String(e.text.prefix { $0 != ":" && $0 != "(" }.prefix(40)).trimmingCharacters(in: .whitespaces)
                }
            }
        }
        .onCopyCommand { selected.map { [NSItemProvider(object: $0.line as NSString)] } ?? [] }
        .overlay {
            if data.isEmpty && !log.events.isEmpty {
                EmptyState(icon: "magnifyingglass", title: "Không có sự kiện phù hợp",
                           message: log.hasOlder ? "Đang đọc thêm phần log cũ…" : "Thử từ khoá khác hoặc nới bộ lọc.")
            }
        }
    }

    @ViewBuilder var detail: some View {
        if let e = selected {
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 8) {
                    LevelIcon(level: e.level)
                    Text(e.level.title).font(.headline)
                    Text(e.time).monospacedDigit().foregroundStyle(.secondary)
                    Spacer()
                    Button { ui.copy(e.line) } label: { Label("Sao chép", systemImage: "doc.on.doc") }
                }
                .padding(.horizontal, 14).padding(.vertical, 8)
                Divider()
                ScrollView {
                    Text(Self.pretty(e.text))
                        .textSelection(.enabled)
                        .lineSpacing(3)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(14)
                }
            }
            .background(Color(nsColor: .textBackgroundColor))
        } else {
            Text("Chọn một sự kiện để xem chi tiết")
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Color(nsColor: .textBackgroundColor))
        }
    }

    var statusBar: some View {
        StatusBar {
            let data = rows
            Text(filtering ? "\(data.count) / \(log.events.count) sự kiện" : "\(log.events.count) sự kiện")
            if log.hasOlder {
                Text("· đã đọc \(ByteCountFormatter.string(fromByteCount: Int64(log.fileSize - log.loadedFrom), countStyle: .file)) / \(ByteCountFormatter.string(fromByteCount: Int64(log.fileSize), countStyle: .file))")
                Button("Tải thêm cũ hơn") { log.loadOlder() }.buttonStyle(.link)
            }
            Spacer()
            Button("Mở bằng Console") { NSWorkspace.shared.open(URL(fileURLWithPath: Store.daemonLogPath)) }.buttonStyle(.link)
        }
    }

    /// Tách các trường trong dòng log ("User: …", "Lệnh: …") ra từng dòng cho dễ đọc
    private static let fieldRegex = try! NSRegularExpression(
        pattern: #"\s+(?:\|\s+)?(?=(?:User|Lệnh|Tiến trình cha|Tiến trình|Chuỗi tiến trình|File chạy|File|Chạy từ|Chạy|Nguồn|IP|Cổng|Chương trình|Chữ ký|Thời lượng|Wazuh [^:]{1,60}):\s)"#)
    static func pretty(_ s: String) -> String {
        fieldRegex.stringByReplacingMatches(in: s, range: NSRange(s.startIndex..., in: s), withTemplate: "\n")
    }
}
