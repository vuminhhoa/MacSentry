import AppKit
import Combine
import UserNotifications

// MARK: - Kiểm tra bản cập nhật qua GitHub Releases. MacSentry build từ mã nguồn (release không kèm file nhị phân),
// nên "cập nhật" là chạy lại git pull + build.sh + daemon/install.sh trong thư mục mã nguồn — mở trong Terminal
// để người dùng thấy lệnh và tự nhập mật khẩu sudo. App không tự tải hay thay file chạy.

final class Updater: ObservableObject {
    static let shared = Updater()
    static let latestURL = URL(string: "https://api.github.com/repos/vuminhhoa/MacSentry/releases/latest")!
    static let releasesURL = URL(string: "https://github.com/vuminhhoa/macsentry/releases")!
    static let notificationID = "update"
    private static let autoKey = "autoCheckUpdates", lastKey = "lastUpdateCheck", notifiedKey = "notifiedUpdateVersion"
    /// Tự kiểm tra tối đa mỗi ngày một lần; đồng hồ chạy mỗi giờ để máy ngủ qua đêm vẫn kiểm tra sớm sau khi thức
    private static let interval: TimeInterval = 24 * 3600

    struct Release: Decodable {
        let tagName: String
        let htmlURL: URL
        let publishedAt: Date?
        var version: String { tagName.hasPrefix("v") ? String(tagName.dropFirst()) : tagName }
        enum CodingKeys: String, CodingKey { case tagName = "tag_name", htmlURL = "html_url", publishedAt = "published_at" }
    }

    enum State { case idle, checking, upToDate, available(Release), failed(String) }

    @Published private(set) var state = State.idle
    @Published private(set) var lastCheck: Date? = UserDefaults.standard.object(forKey: lastKey) as? Date
    /// Tự kiểm tra hằng ngày (mặc định bật)
    @Published var automatic = UserDefaults.standard.object(forKey: autoKey) as? Bool ?? true {
        didSet { UserDefaults.standard.set(automatic, forKey: Self.autoKey) }
    }
    private var timer: Timer?

    static let currentVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0"

    var available: Release? { if case .available(let r) = state { r } else { nil } }

    /// Thư mục mã nguồn mà build.sh đã ghi vào Info.plist, còn là repo git thì mới cập nhật tự động được
    static var sourceDir: String? {
        guard let dir = Bundle.main.object(forInfoDictionaryKey: "MacSentrySourceDir") as? String,
              FileManager.default.fileExists(atPath: dir + "/.git"), FileManager.default.isExecutableFile(atPath: dir + "/build.sh")
        else { return nil }
        return dir
    }

    static var updateCommand: String {
        let cd = sourceDir.map { "cd '\($0.replacingOccurrences(of: "'", with: "'\\''"))' && " } ?? ""
        return cd + "git pull --ff-only && ./build.sh && sudo ./daemon/install.sh"
    }

    func start() {
        let t = Timer(timeInterval: 3600, repeats: true) { [weak self] _ in self?.checkIfDue() }
        t.tolerance = 300
        RunLoop.main.add(t, forMode: .common)
        timer = t
        // Đợi một chút sau khi mở app: lúc đăng nhập mạng có thể chưa sẵn sàng
        DispatchQueue.main.asyncAfter(deadline: .now() + 30) { [weak self] in self?.checkIfDue() }
    }

    private func checkIfDue() {
        guard automatic, Date().timeIntervalSince(lastCheck ?? .distantPast) >= Self.interval else { return }
        check()
    }

    /// `manual` = người dùng bấm kiểm tra: không cần gửi thông báo (kết quả hiện ngay trong Cài đặt)
    func check(manual: Bool = false) {
        if case .checking = state { return }
        state = .checking
        var req = URLRequest(url: Self.latestURL, timeoutInterval: 15)
        req.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        req.setValue("MacSentry/\(Self.currentVersion)", forHTTPHeaderField: "User-Agent")  // GitHub API bắt buộc có User-Agent
        URLSession.shared.dataTask(with: req) { data, resp, err in
            let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
            let dec = JSONDecoder(); dec.dateDecodingStrategy = .iso8601
            let release = code == 200 ? data.flatMap { try? dec.decode(Release.self, from: $0) } : nil
            DispatchQueue.main.async {
                guard let release else {
                    NSLog("MacSentry kiểm tra cập nhật lỗi (HTTP \(code)): \(err?.localizedDescription ?? "")")
                    // 404: repo chưa có bản phát hành nào
                    self.state = code == 404 ? .upToDate : .failed(err?.localizedDescription ?? "HTTP \(code)")
                    return
                }
                let now = Date()
                self.lastCheck = now
                UserDefaults.standard.set(now, forKey: Self.lastKey)
                if Self.isNewer(release.version, than: Self.currentVersion) {
                    self.state = .available(release)
                    if !manual { self.notify(release) }
                } else {
                    self.state = .upToDate
                }
            }
        }.resume()
    }

    /// So sánh phiên bản dạng 1.2.3 (bỏ phần sau dấu "-", vd. 1.2.0-beta). Phần thiếu coi là 0
    static func isNewer(_ a: String, than b: String) -> Bool {
        func parts(_ s: String) -> [Int] {
            s.split(separator: "-").first.map { $0.split(separator: ".").map { Int($0) ?? 0 } } ?? []
        }
        let x = parts(a), y = parts(b)
        for i in 0..<max(x.count, y.count) {
            let l = i < x.count ? x[i] : 0, r = i < y.count ? y[i] : 0
            if l != r { return l > r }
        }
        return false
    }

    /// Mỗi phiên bản chỉ báo một lần, để không làm phiền mỗi ngày
    private func notify(_ r: Release) {
        guard UserDefaults.standard.string(forKey: Self.notifiedKey) != r.version else { return }
        UserDefaults.standard.set(r.version, forKey: Self.notifiedKey)
        let content = UNMutableNotificationContent()
        content.title = L("Có bản cập nhật MacSentry %@", r.version)
        content.body = L("Bạn đang dùng %@. Bấm để xem và cập nhật.", Self.currentVersion)
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: Self.notificationID, content: content, trigger: nil))
    }

    /// Mở Terminal chạy lệnh cập nhật. Dùng file .command (Terminal tự mở) thay cho AppleScript để không cần quyền Tự động hoá
    func runUpdate() {
        guard Self.sourceDir != nil else { NSWorkspace.shared.open(available?.htmlURL ?? Self.releasesURL); return }
        let script = Store.dir.appendingPathComponent("update.command")
        let body = "#!/bin/bash\n# Tạo bởi MacSentry: cập nhật từ mã nguồn rồi cài lại daemon\nset -e\n\(Self.updateCommand)\n"
        try? FileManager.default.removeItem(at: script)
        guard FileManager.default.createFile(atPath: script.path, contents: Data(body.utf8), attributes: [.posixPermissions: 0o700])
        else { return }
        NSWorkspace.shared.open(script)
    }
}
