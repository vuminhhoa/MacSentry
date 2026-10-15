import Foundation

// MARK: - Log sự kiện của daemon: đọc dần từ cuối file, tự cập nhật khi file được ghi thêm

struct LogEvent: Identifiable, Hashable {
    enum Level: Int, CaseIterable, Comparable {
        case info, notice, alert
        static func < (a: Level, b: Level) -> Bool { a.rawValue < b.rawValue }
        var title: String { switch self { case .info: "Thông tin"; case .notice: "Chú ý"; case .alert: "Cảnh báo" } }
    }
    let id: UInt64          // vị trí byte của dòng trong file → không đổi giữa các lần tải lại
    let date: Date?
    let time: String
    let text: String
    let level: Level
    let key: String         // chữ thường, bỏ dấu — dùng cho tìm kiếm

    var line: String { "\(time) \(text)" }

    /// Phân loại theo ký hiệu đầu dòng mà daemon dùng
    private static let alertMarks: Set<Unicode.Scalar> = ["🚨", "⚠", "☠", "⛔", "🔴", "🌙", "🔐", "❌", "🧬", "🛡", "📷", "🎙"]
    private static let noticeMarks: Set<Unicode.Scalar> = ["🔑", "⚡", "🆕", "🧷", "🧩", "🧭", "📝", "🏷", "🐺"]

    init?(offset: UInt64, line: String) {
        guard !line.isEmpty else { return nil }
        let chars = Array(line.prefix(20))
        if chars.count >= 19, chars[2] == "/", chars[10] == " ", let d = timeFmt.date(from: String(chars[0..<19])) {
            date = d
            time = String(chars[0..<19])
            text = String(line.dropFirst(19)).trimmingCharacters(in: .whitespaces)
        } else {
            date = nil; time = ""; text = line
        }
        id = offset
        let first = text.unicodeScalars.first ?? " "
        level = Self.alertMarks.contains(first) ? .alert : Self.noticeMarks.contains(first) ? .notice : .info
        key = fold("\(time) \(text)")
    }
}

func fold(_ s: String) -> String { s.folding(options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive], locale: nil) }

/// Điều kiện tìm: các từ cách nhau bởi khoảng trắng đều phải có; "-từ" để loại trừ
struct SearchQuery {
    var include: [String] = [], exclude: [String] = []
    init(_ raw: String) {
        for t in fold(raw).split(whereSeparator: \.isWhitespace).map(String.init) {
            if t.count > 1, t.hasPrefix("-") { exclude.append(String(t.dropFirst())) } else { include.append(t) }
        }
    }
    var isEmpty: Bool { include.isEmpty && exclude.isEmpty }
    func matches(_ key: String) -> Bool {
        include.allSatisfy { key.contains($0) } && !exclude.contains { key.contains($0) }
    }
    func matches(_ fields: String...) -> Bool { matches(fold(fields.joined(separator: " "))) }
}

final class EventLog: ObservableObject {
    static let chunk: UInt64 = 1_000_000

    @Published private(set) var events: [LogEvent] = []      // mới nhất ở đầu
    @Published private(set) var fileSize: UInt64 = 0
    @Published private(set) var loadedFrom: UInt64 = 0         // byte đầu tiên đã đọc; 0 = đã đọc hết
    @Published private(set) var unreadable = false
    @Published var live = true

    var hasOlder: Bool { loadedFrom > 0 }

    // Trạng thái đọc file — chỉ dùng trên hàng đợi q
    private let q = DispatchQueue(label: "macsentry.eventlog", qos: .userInitiated)
    private var started = false
    private var readTo: UInt64 = 0
    private var readFrom: UInt64 = 0
    private var timer: Timer?

    /// Bắt đầu theo dõi (khi cửa sổ mở); dừng khi đóng để không tốn tài nguyên
    func start() {
        guard timer == nil else { return }
        refresh()
        let t = Timer(timeInterval: 2, repeats: true) { [weak self] _ in if self?.live == true { self?.refresh() } }
        t.tolerance = 0.5
        RunLoop.main.add(t, forMode: .common)
        timer = t
    }
    func stop() { timer?.invalidate(); timer = nil }

    /// Đọc phần mới được ghi thêm (lần đầu: khối cuối file)
    func refresh() {
        q.async { [self] in
            guard let h = FileHandle(forReadingAtPath: Store.daemonLogPath) else {
                DispatchQueue.main.async { self.unreadable = true }
                return
            }
            defer { try? h.close() }
            let size = (try? h.seekToEnd()) ?? 0
            if started && size < readTo { started = false }    // file bị cắt / thay mới → đọc lại từ đầu
            if !started {
                let from = size > Self.chunk ? size - Self.chunk : 0
                let r = Self.parse(h, from: from, to: size, partialStart: from > 0)
                started = true; readFrom = r.start; readTo = r.end
                publish(size: size) { _ in r.events.reversed() }
            } else if size > readTo {
                let r = Self.parse(h, from: readTo, to: size, partialStart: false)
                readTo = r.end
                if !r.events.isEmpty { publish(size: size) { r.events.reversed() + $0 } }
            }
        }
    }

    /// Đọc thêm khối cũ hơn (cuộn tới cuối bảng). `all`: đọc hết phần còn lại (khi đang tìm kiếm)
    func loadOlder(all: Bool = false) {
        q.async { [self] in
            guard started, readFrom > 0, let h = FileHandle(forReadingAtPath: Store.daemonLogPath) else { return }
            defer { try? h.close() }
            let from = all || readFrom <= Self.chunk ? 0 : readFrom - Self.chunk
            let r = Self.parse(h, from: from, to: readFrom, partialStart: from > 0)
            readFrom = r.start
            publish(size: fileSize) { $0 + r.events.reversed() }
        }
    }

    private func publish(size: UInt64, _ update: @escaping ([LogEvent]) -> [LogEvent]) {
        let from = readFrom
        DispatchQueue.main.async {
            self.unreadable = false
            self.events = update(self.events)
            self.fileSize = size
            self.loadedFrom = from
        }
    }

    /// Đọc [from, to): bỏ dòng bị cắt dở ở đầu (nếu partialStart) và dòng chưa ghi xong ở cuối.
    /// Trả về các sự kiện theo thứ tự trong file cùng vị trí bắt đầu / kết thúc thực sự đã dùng.
    private static func parse(_ h: FileHandle, from: UInt64, to: UInt64, partialStart: Bool) -> (events: [LogEvent], start: UInt64, end: UInt64) {
        guard to > from, (try? h.seek(toOffset: from)) != nil,
              let data = try? h.read(upToCount: Int(to - from)), !data.isEmpty else { return ([], from, from) }
        var events: [LogEvent] = []
        var i = data.startIndex
        var start = from
        if partialStart {
            guard let nl = data.firstIndex(of: 0x0A) else { return ([], to, to) }
            i = data.index(after: nl)
            start = from + UInt64(i - data.startIndex)
        }
        var end = start
        while i < data.endIndex, let nl = data[i...].firstIndex(of: 0x0A) {
            let off = from + UInt64(i - data.startIndex)
            if let e = LogEvent(offset: off, line: String(decoding: data[i..<nl], as: UTF8.self)) { events.append(e) }
            i = data.index(after: nl)
            end = from + UInt64(i - data.startIndex)
        }
        return (events, start, end)
    }
}
