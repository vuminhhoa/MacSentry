// MacSentry — cảnh báo an ninh cho máy Mac, chạy trên thanh menu (status bar).
// App (chạy bằng user): theo dõi kết nối truy cập từ xa + popup, khoá/mở khoá màn hình, ngủ, app bị tắt.
// Daemon macsentryd (chạy bằng root, xem daemon/): bật/tắt máy, đăng nhập sai, thay đổi hệ thống, phần cứng & mạng.
// Mã nguồn chia theo chủ đề trong thư mục Sources/ (Monitor, AVSensors, Telegram, AppDelegate…).
import AppKit

// `MacSentry --scan`: in danh sách kết nối hiện tại rồi thoát (để debug)
if CommandLine.arguments.contains("--scan") {
    for c in Monitor().scan() { print(c.service, c.ip, c.remotePort, c.user ?? "-") }
    exit(0)
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory) // chỉ hiện trên thanh menu, không có icon Dock
app.run()
