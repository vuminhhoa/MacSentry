import Foundation

// MARK: - Store (lưu lịch sử + danh sách IP tin cậy)

final class Store {
    static let dir: URL = {
        let d = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("MacSentry", isDirectory: true)
        // Chỉ chủ tài khoản đọc được: thư mục chứa token Telegram, lịch sử kết nối, IP tin cậy
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: d.path)
        return d
    }()
    static let historyURL = dir.appendingPathComponent("history.json")
    static let trustedURL = dir.appendingPathComponent("trusted.json")
    static let daemonLogPath = "/var/log/macsentry.log"
    /// Trạng thái kết nối do macsentryd (root) quét và chia sẻ — dòng "conn <cổng> <addr.port>" / "who <user> <tty> (<host>)"
    static let daemonRemotePath = "/var/run/macsentry/remote"
    /// Lệnh cài / cập nhật daemon: build.sh ghi thư mục mã nguồn vào Info.plist (MacSentrySourceDir)
    static let daemonInstallCommand: String = {
        guard let dir = Bundle.main.object(forInfoDictionaryKey: "MacSentrySourceDir") as? String else { return "sudo ./daemon/install.sh" }
        return "sudo '\(dir.replacingOccurrences(of: "'", with: "'\\''"))/daemon/install.sh'"
    }()

    static func load<T: Decodable>(_ url: URL, as: T.Type) -> T? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        let dec = JSONDecoder(); dec.dateDecodingStrategy = .iso8601
        return try? dec.decode(T.self, from: data)
    }
    /// Ghi nguyên tử với quyền 0600 ngay từ lúc tạo (không có khoảnh khắc file chứa token đọc được bởi user khác)
    static func save<T: Encodable>(_ value: T, to url: URL) {
        let enc = JSONEncoder(); enc.dateEncodingStrategy = .iso8601; enc.outputFormatting = .prettyPrinted
        guard let data = try? enc.encode(value) else { return }
        let tmp = url.appendingPathExtension("tmp")
        guard FileManager.default.createFile(atPath: tmp.path, contents: data, attributes: [.posixPermissions: 0o600]) else { return }
        rename(tmp.path, url.path)
    }
}
