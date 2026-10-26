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

    /// Lọc ngoài `body`: chỉ tính lại khi log / bộ lọc đổi (khoảng thời gian tương đối làm mới mỗi phút)
    var rows: [LogEvent] {
        let key = EventsKey(events: log.events, query: query, level: ui.eventLevel, range: ui.eventRange,
                            minute: ui.eventRange == .all ? 0 : Int(Date().timeIntervalSince1970 / 60))
        return ui.eventRows.get(key) {
            let q = SearchQuery(query)
            let level = ui.eventLevel
            let scope = log.since(ui.eventRange.cutoff)      // khoảng thời gian: chỉ duyệt phần đầu mảng
            if q.isEmpty && level == nil { return scope.count == log.events.count ? log.events : Array(scope) }
            return scope.filter { (level == nil || $0.level == level) && (q.isEmpty || q.matches($0.key)) }
        }
    }
    var filtering: Bool { !query.isEmpty || ui.eventLevel != nil || ui.eventRange != .all }
    var selected: LogEvent? { ui.selectedEvent.flatMap(event) }

    /// `events` xếp theo id (vị trí byte) giảm dần → tìm nhị phân thay vì duyệt cả mảng
    func event(_ id: UInt64) -> LogEvent? {
        let ev = log.events
        var lo = 0, hi = ev.count
        while lo < hi {
            let mid = (lo + hi) / 2
            if ev[mid].id > id { lo = mid + 1 } else { hi = mid }
        }
        return lo < ev.count && ev[lo].id == id ? ev[lo] : nil
    }

    var body: some View {
        Group {
            if log.unreadable && log.events.isEmpty {
                EmptyState(icon: "doc.questionmark", title: L("Không đọc được log"),
                           message: Telegram.daemonInstalled ? L("Chưa có file %@.", Store.daemonLogPath)
                               : L("Chưa cài macsentryd. Cài bằng lệnh: %@", Store.daemonInstallCommand))
                    .safeAreaBar(edge: .bottom) { statusBar(nil) }
            } else {
                let data = rows
                // Thanh trạng thái xếp hẳn bên dưới: VSplitView (NSSplitView) không né safeAreaBar
                // nên khung chi tiết sẽ chạy xuống dưới thanh và bị chữ đè lên
                VStack(spacing: 0) {
                    // Khung chi tiết có trần chiều cao: cửa sổ lớn thì phần thêm dành cho bảng
                    // (VSplitView chia đều phần thêm, bỏ qua idealHeight)
                    VSplitView {
                        table(data).frame(minHeight: 150, maxHeight: .infinity)
                        detail.frame(minHeight: 120, idealHeight: 220, maxHeight: 280)
                    }
                    Divider()
                    statusBar(data.count)
                }
            }
        }
        .topBar { filterBar }
        .task(id: ui.queries[.events] ?? "") {
            try? await Task.sleep(nanoseconds: 200_000_000)
            ui.settled[.events] = ui.queries[.events] ?? ""
            // Tìm kiếm phải thấy cả phần log cũ chưa tải
            if !query.isEmpty && log.hasOlder { log.loadOlder(all: true) }
        }
    }

    /// Thanh lọc co giãn: đủ chỗ thì nút có chữ, thiếu chỗ (cửa sổ hẹp, có thêm "Bỏ lọc") thì nút chỉ còn
    /// icon + tooltip — không để nút bị cắt thành "Tự…"
    var filterBar: some View {
        FilterBar {
            ViewThatFits(in: .horizontal) {
                filterControls(compact: false)
                filterControls(compact: true)
            }
        }
    }

    func filterControls(compact: Bool) -> some View {
        HStack(spacing: 10) {
            Picker(L("Mức độ"), selection: $ui.eventLevel) {
                Text(L("Tất cả")).tag(LogEvent.Level?.none)
                ForEach(LogEvent.Level.allCases.reversed(), id: \.self) { Text($0.title).tag(LogEvent.Level?.some($0)) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            Picker(L("Thời gian"), selection: $ui.eventRange) {
                ForEach(TimeRange.allCases, id: \.self) { Text($0.title).tag($0) }
            }
            .labelsHidden()
            .fixedSize()
            if filtering {
                Button { ui.queries[.events] = ""; ui.eventLevel = nil; ui.eventRange = .all } label: {
                    if compact { Image(systemName: "xmark.circle.fill") } else { Text(L("Bỏ lọc")) }
                }
                .buttonStyle(.link)
                .help(L("Bỏ mọi bộ lọc và từ khoá"))
                .fixedSize()
            }
            Spacer(minLength: 0)
            // Cùng loại control + cùng kiểu với nút tải lại → cùng cỡ, cùng chiều cao (Toggle kiểu nút và
            // borderedProminent đều vẽ thấp hơn). Đang bật thì tô màu nhấn
            Button { log.live.toggle() } label: { Label { Text(L("Tự cập nhật")) } icon: { BarIcon("dot.radiowaves.up.forward") } }
            .buttonStyle(.bordered)
            .tint(log.live ? .accentColor : nil)
            .labelStyle(compact ? AnyLabelStyle(.iconOnly) : AnyLabelStyle(.titleAndIcon))
            .help(log.live ? L("Đang tự hiện sự kiện mới — bấm để tạm dừng") : L("Đã tạm dừng — bấm để tự hiện sự kiện mới"))
            .fixedSize()
            Button { log.refresh() } label: { Label { Text(L("Tải lại")) } icon: { BarIcon("arrow.clockwise") } }
                .buttonStyle(.bordered)
                .labelStyle(.iconOnly)
                .help(L("Tải lại ngay"))
                .fixedSize()
        }
    }

    func table(_ data: [LogEvent]) -> some View {
        let lastID = data.last?.id
        return Table(data, selection: $ui.selectedEvent, columnCustomization: $ui.eventColumns) {
            TableColumn(L("Mức")) { e in LevelIcon(level: e.level).help(e.level.title) }
                .width(44)      // đủ cho tiêu đề "Level" khi dùng tiếng Anh
                .customizationID("level")
            TableColumn(L("Thời gian")) { e in
                Group {
                    if let d = e.date { DateText(date: d) } else { Text(e.time).monospacedDigit() }
                }
                .foregroundStyle(.secondary)
                // Cuộn tới dòng cuối → đọc thêm phần log cũ hơn (bảng chỉ dựng các dòng đang hiển thị)
                .onAppear { if e.id == lastID && log.hasOlder { log.loadOlder() } }
            }
            .width(min: 70, ideal: 155, max: 200)
            .customizationID("time")
            // Cột cuối: không đặt độ rộng → tự lấp phần còn lại; không cho kéo mép phải / ẩn
            TableColumn(L("Nội dung")) { e in
                Text(e.text).lineLimit(1).help(e.text)
                    .fontWeight(e.level == .alert ? .medium : .regular)
            }
            .customizationID("text")
            .disabledCustomizationBehavior([.resize, .visibility])
        }
        .tableStyle(.bordered(alternatesRowBackgrounds: true))
        .contextMenu(forSelectionType: UInt64.self) { ids in
            if let e = ids.first.flatMap(event) {
                Button(L("Sao chép dòng"), systemImage: "doc.on.doc") { ui.copy(e.line) }
                Button(L("Sao chép nội dung"), systemImage: "text.quote") { ui.copy(e.text) }
                Divider()
                Button(L("Lọc sự kiện cùng loại"), systemImage: "line.3.horizontal.decrease") {
                    ui.queries[.events] = String(e.text.prefix { $0 != ":" && $0 != "(" }.prefix(40)).trimmingCharacters(in: .whitespaces)
                }
            }
        }
        .onCopyCommand { selected.map { [NSItemProvider(object: $0.line as NSString)] } ?? [] }
        .overlay {
            if data.isEmpty && !log.events.isEmpty {
                EmptyState(icon: "magnifyingglass", title: L("Không có sự kiện phù hợp"),
                           message: log.hasOlder ? L("Đang đọc thêm phần log cũ…") : L("Thử từ khoá khác hoặc nới bộ lọc."))
            }
        }
    }

    @ViewBuilder var detail: some View {
        if let e = selected {
            let d = Self.details(e.text)
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 8) {
                    LevelIcon(level: e.level)
                    Text(e.level.title).font(.headline)
                    Text(e.time).monospacedDigit().foregroundStyle(.secondary)
                    Spacer()
                    Button { ui.copy(e.line) } label: { Label(L("Sao chép"), systemImage: "doc.on.doc") }
                        .help(L("Sao chép cả dòng log (⌘C)"))
                }
                .padding(.horizontal, 14).padding(.vertical, 8)
                Divider()
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(d.headline)
                            .font(.body.weight(.medium))
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                        if !d.fields.isEmpty {
                            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 6) {
                                ForEach(Array(d.fields.enumerated()), id: \.offset) { _, f in
                                    GridRow {
                                        Text(L(f.key))     // tên trường do daemon ghi (tiếng Việt)
                                            .foregroundStyle(.secondary)
                                            .gridColumnAlignment(.trailing)
                                        Text(f.value)
                                            .font(f.value.hasPrefix("/") || f.value.hasPrefix("file:") ? .body.monospaced() : .body)
                                            .textSelection(.enabled)
                                            .fixedSize(horizontal: false, vertical: true)
                                            .frame(maxWidth: .infinity, alignment: .leading)
                                    }
                                }
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(14)
                }
            }
            .background(Color(nsColor: .textBackgroundColor))
        } else {
            Text(L("Chọn một sự kiện để xem chi tiết"))
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Color(nsColor: .textBackgroundColor))
        }
    }

    func statusBar(_ shown: Int?) -> some View {
        StatusBar {
            Text(filtering ? "\(shown ?? 0) / " + Lplural("%ld sự kiện", log.events.count) : Lplural("%ld sự kiện", log.events.count))
            if log.hasOlder {
                Text(L("· đã đọc %@ / %@", ByteCountFormatter.string(fromByteCount: Int64(log.fileSize - log.loadedFrom), countStyle: .file),
                       ByteCountFormatter.string(fromByteCount: Int64(log.fileSize), countStyle: .file)))
                Button(L("Tải thêm cũ hơn")) { log.loadOlder() }.buttonStyle(.link)
            }
            Spacer()
            Button(L("Mở bằng Console")) { NSWorkspace.shared.open(URL(fileURLWithPath: Store.daemonLogPath)) }.buttonStyle(.link)
        }
    }

    /// Tách các trường trong dòng log ("User: …", "Lệnh: …") ra từng dòng cho dễ đọc
    private static let fieldRegex = try! NSRegularExpression(
        pattern: #"\s+(?:\|\s+)?(?=(?:User|Lệnh|Tiến trình cha|Tiến trình|Chuỗi tiến trình|File chạy|File|Chạy từ|Chạy|Nguồn|IP|Cổng|Chương trình|Chữ ký|Thời lượng|Wazuh [^:]{1,60}):\s)"#)
    static func pretty(_ s: String) -> String {
        fieldRegex.stringByReplacingMatches(in: s, range: NSRange(s.startIndex..., in: s), withTemplate: "\n")
    }

    /// Dòng log → dòng chính + các trường (tên, giá trị). Daemon ghi theo 2 kiểu:
    /// "… User: a Lệnh: b" (tách bằng fieldRegex) và "… — chạy /đường/dẫn — cài bởi /x (pid …)"
    static func details(_ text: String) -> (headline: String, fields: [(key: String, value: String)]) {
        var lines = pretty(text).components(separatedBy: "\n")
        var head = lines.removeFirst()
        var fields: [(key: String, value: String)] = []
        // Các đoạn "— <tên> /giá trị" sau dòng chính
        let parts = head.components(separatedBy: " — ")
        head = parts[0]
        for p in parts.dropFirst() {
            if let r = p.range(of: " /") {
                fields.append((String(p[..<r.lowerBound]).capitalizedFirst, String(p[p.index(after: r.lowerBound)...])))
            } else {
                head += " — " + p
            }
        }
        // "…): /đường/dẫn" ở cuối dòng chính
        if let r = head.range(of: ": /", options: .backwards) {
            fields.insert(("Đường dẫn", String(head[head.index(r.lowerBound, offsetBy: 2)...])), at: 0)
            head = String(head[..<r.lowerBound])
        }
        for l in lines {
            if let c = l.range(of: ": ") {
                fields.append((String(l[..<c.lowerBound]), String(l[c.upperBound...]).trimmingCharacters(in: .whitespaces)))
            } else if !l.isEmpty {
                fields.append(("", l))
            }
        }
        return (head, fields)
    }
}

struct EventsKey: Equatable {
    let events: [LogEvent]
    let query: String
    let level: LogEvent.Level?
    let range: TimeRange
    let minute: Int
}

extension String {
    /// Viết hoa chữ cái đầu ("cài bởi" → "Cài bởi")
    var capitalizedFirst: String { prefix(1).uppercased() + dropFirst() }
}

/// Bọc LabelStyle để chọn kiểu nhãn lúc chạy (iconOnly / titleAndIcon)
struct AnyLabelStyle: LabelStyle {
    private let make: (Configuration) -> AnyView
    init<S: LabelStyle>(_ style: S) { make = { AnyView(style.makeBody(configuration: $0)) } }
    func makeBody(configuration: Configuration) -> some View { make(configuration) }
}

/// Icon trong nút của thanh lọc: khung cố định để mọi nút cao bằng nhau (nút bordered cao theo nội dung,
/// ký hiệu cao như ↻ làm nút cao hơn nút bên cạnh)
struct BarIcon: View {
    let name: String
    init(_ name: String) { self.name = name }
    var body: some View {
        Image(systemName: name).resizable().scaledToFit().frame(width: 14, height: 14)
    }
}
