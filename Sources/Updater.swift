import AppKit
import Combine
import UserNotifications

// MARK: - Kiểm tra bản cập nhật qua GitHub Releases. MacSentry build từ mã nguồn (release không kèm file nhị phân),
// nên "cập nhật" là git pull + build.sh trong thư mục mã nguồn, cài lại daemon (một hộp thoại mật khẩu), thay app
// rồi tự khởi động lại. Cài đặt (UserDefaults, Telegram, /etc/macsentry.conf...) không bị đụng tới.

final class Updater: ObservableObject {
    static let shared = Updater()
    static let latestURL = URL(string: "https://api.github.com/repos/vuminhhoa/MacSentry/releases/latest")!
    static let releasesURL = URL(string: "https://github.com/vuminhhoa/macsentry/releases")!
    static let notificationID = "update"
    private static let autoKey = "autoCheckUpdates", lastKey = "lastUpdateCheck", notifiedKey = "notifiedUpdateVersion"
    private static let updatedFromKey = "updatedFromVersion"
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
    /// Bước đang chạy của lần cập nhật (nil = không cập nhật) và lỗi của lần gần nhất
    @Published private(set) var step: String?
    @Published private(set) var updateError: String?
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
        // Vừa khởi động lại sau khi cập nhật → báo một lần
        if let from = UserDefaults.standard.string(forKey: Self.updatedFromKey) {
            UserDefaults.standard.removeObject(forKey: Self.updatedFromKey)
            if from != Self.currentVersion {
                let content = UNMutableNotificationContent()
                content.title = L("Đã cập nhật MacSentry %@", Self.currentVersion)
                content.body = L("Từ bản %@. Cài đặt được giữ nguyên.", from)
                UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "updated", content: content, trigger: nil))
            }
        }
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

    /// Cập nhật một chạm: git pull → build → cài lại daemon → thay app → khởi động lại. Lỗi ở bước nào thì dừng ở đó,
    /// app đang chạy không bị thay
    func runUpdate() {
        guard let dir = Self.sourceDir else { NSWorkspace.shared.open(available?.htmlURL ?? Self.releasesURL); return }
        guard step == nil else { return }
        updateError = nil
        step = L("Đang tải mã nguồn…")
        DispatchQueue.global(qos: .userInitiated).async {
            let err = self.update(in: dir)
            DispatchQueue.main.async {
                self.step = nil
                if let err { self.updateError = err } else { Self.relaunch() }
            }
        }
    }

    private func update(in dir: String) -> String? {
        func setStep(_ s: String) { DispatchQueue.main.async { self.step = s } }
        var r = Shell.run("/usr/bin/git", ["pull", "--ff-only"], in: dir)
        guard r.ok else { return L("git pull lỗi: %@", r.tail) }
        setStep(L("Đang build…"))
        r = Shell.run(dir + "/build.sh", ["--no-install"], in: dir)
        guard r.ok else { return L("Build lỗi: %@", r.tail) }
        setStep(L("Đang cài daemon…"))
        if let e = DaemonInstaller.runScript(dir) { return e }
        setStep(L("Đang khởi động lại…"))
        return Self.replaceApp(with: dir + "/build/MacSentry.app")
    }

    /// Thay bundle đang chạy bằng bản vừa build (copy ra bên cạnh rồi đổi chỗ, không có lúc nào thiếu app)
    static func replaceApp(with built: String) -> String? {
        let dest = URL(fileURLWithPath: Bundle.main.bundlePath).standardizedFileURL
        let src = URL(fileURLWithPath: built).standardizedFileURL
        guard dest != src else { return nil }
        let fm = FileManager.default
        let tmp = dest.deletingLastPathComponent().appendingPathComponent(".MacSentry-update.app")
        do {
            try? fm.removeItem(at: tmp)
            try fm.copyItem(at: src, to: tmp)
            _ = try fm.replaceItemAt(dest, withItemAt: tmp)
        } catch { return error.localizedDescription }
        // Như build.sh: bỏ bản trong build/ khỏi LaunchServices để hệ thống chỉ biết một app
        let lsregister = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
        _ = Shell.run(lsregister, ["-u", src.path], in: "/")
        _ = Shell.run(lsregister, ["-f", dest.path], in: "/")
        return nil
    }

    /// Thoát mã lỗi để launchd (KeepAlive: SuccessfulExit = false) chạy lại ngay bản mới ở cùng đường dẫn.
    /// Không qua applicationWillTerminate: không gửi tin "app đã bị tắt" cho một lần khởi động lại có chủ đích
    static func relaunch() {
        UserDefaults.standard.set(currentVersion, forKey: updatedFromKey)
        UserDefaults.standard.synchronize()
        Monitor.stopHelper()
        if LaunchAtLogin.runningUnderLaunchd { exit(1) }
        NSWorkspace.shared.openApplication(at: URL(fileURLWithPath: Bundle.main.bundlePath), configuration: .init()) { _, _ in exit(0) }
    }
}
