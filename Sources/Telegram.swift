import Foundation

// MARK: - Telegram (gửi cảnh báo ra ngoài máy để không bị xoá dấu vết tại chỗ)

enum Telegram {
    struct Config: Codable { let botToken: String; let chatId: String }
    static let configURL = Store.dir.appendingPathComponent("telegram.json")
    static var config: Config? { Store.load(configURL, as: Config.self) }
    static let hostName = Host.current().localizedName ?? ProcessInfo.processInfo.hostName
    /// Đã cài macsentryd (daemon root) thì nó lo tin bật/tắt máy, kết nối mở/đóng, đăng nhập, thức dậy → app không gửi trùng
    static var daemonInstalled: Bool {
        FileManager.default.fileExists(atPath: "/Library/LaunchDaemons/io.github.vuminhhoa.macsentry.daemon.plist")
    }

    /// Gửi tin nhắn, thử lại tới ~5 phút nếu lỗi mạng. `silent` = không kêu chuông trên điện thoại (tin thông tin).
    /// `wait` = chờ gửi xong (dùng khi app sắp thoát / máy sắp ngủ).
    /// `done`: báo kết quả lần gửi đầu tiên (dùng cho nút "Gửi thử").
    static func send(_ text: String, silent: Bool = false, wait: Bool = false, attempt: Int = 1, done: ((Bool) -> Void)? = nil) {
        guard let cfg = config,
              let url = URL(string: "https://api.telegram.org/bot\(cfg.botToken)/sendMessage") else { done?(false); return }
        var req = URLRequest(url: url, timeoutInterval: 10)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: [
            "chat_id": cfg.chatId, "text": "🖥 \(hostName)\n\(text)", "disable_notification": silent,
        ])
        let finished = DispatchSemaphore(value: 0)
        URLSession.shared.dataTask(with: req) { data, resp, err in
            defer { finished.signal() }
            let ok = (resp as? HTTPURLResponse)?.statusCode == 200
            done?(ok)
            if ok { return }
            NSLog("MacSentry Telegram lỗi (lần \(attempt)): \(err?.localizedDescription ?? String(decoding: data ?? Data(), as: UTF8.self))")
            if attempt < 12 && !wait {
                DispatchQueue.global().asyncAfter(deadline: .now() + .seconds(min(attempt * 5, 30))) {
                    send(text, silent: silent, attempt: attempt + 1)
                }
            }
        }.resume()
        if wait { _ = finished.wait(timeout: .now() + 5) }
    }
}
