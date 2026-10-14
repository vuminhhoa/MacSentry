import Foundation

// MARK: - Store (lưu lịch sử + danh sách IP tin cậy)

final class Store {
    static let dir: URL = {
        let d = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("MacSentry", isDirectory: true)
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }()
    static let historyURL = dir.appendingPathComponent("history.json")
    static let trustedURL = dir.appendingPathComponent("trusted.json")
    static let daemonLogPath = "/var/log/macsentry.log"
    /// Trạng thái kết nối do macsentryd (root) quét và chia sẻ — dòng "conn <cổng> <addr.port>" / "who <user> <tty> (<host>)"
    static let daemonRemotePath = "/var/run/macsentry/remote"

    static func load<T: Decodable>(_ url: URL, as: T.Type) -> T? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        let dec = JSONDecoder(); dec.dateDecodingStrategy = .iso8601
        return try? dec.decode(T.self, from: data)
    }
    static func save<T: Encodable>(_ value: T, to url: URL) {
        let enc = JSONEncoder(); enc.dateEncodingStrategy = .iso8601; enc.outputFormatting = .prettyPrinted
        try? enc.encode(value).write(to: url, options: .atomic)
    }
}
