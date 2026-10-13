# MacSentry

Cảnh báo an ninh cho máy Mac, gửi về Telegram. Gồm 2 phần:

- **MacSentry.app** (chạy bằng user, trên thanh menu, không thoát được — bị kill thì launchd mở lại):
  kết nối truy cập từ xa (SSH, Screen Sharing/VNC, Remote Desktop, SMB, AFP, Remote Apple Events) kèm popup
  cảnh báo IP lạ, khoá/mở khoá màn hình (mở khoá lúc 0–6h có chuông), camera/micro bật-tắt, máy đi ngủ.
  Lưu lịch sử kết nối, danh sách IP tin cậy, xem log sự kiện của daemon.
- **macsentryd** (LaunchDaemon chạy bằng root, từ lúc bật máy). Log chỉ-được-ghi-thêm tại `/var/log/macsentry.log`:
  - Bật/tắt máy, thức dậy, kết nối từ xa, đăng nhập SSH, cổng mới mở ra mạng, dịch vụ từ xa bật/tắt
  - Nhập sai mật khẩu (màn hình khoá / SSH / sudo), dùng sudo
  - Chống cài cắm: `authorized_keys`, `sshd_config`, `sudoers`, PAM, cron, `/etc/hosts`, shell rc hệ thống
    (kèm nội dung thay đổi), LaunchAgent/Daemon, Login/Background Items, configuration profile,
    system extension, proxy, DNS, app mới, user/admin mới
  - Nghi reverse shell (shell/netcat giữ kết nối mạng ra ngoài)
  - Tư thế bảo mật: firewall, Gatekeeper, SIP, FileVault, tự cập nhật bảo mật; file của MacSentry bị sửa;
    app MacSentry không chạy
  - Phần cứng & mạng: USB, ổ đĩa ngoài, nguồn điện/pin, đổi mạng, ổ đĩa sắp đầy
  - Báo cáo tóm tắt mỗi sáng (không thấy báo cáo → máy/daemon có vấn đề)

## Cài đặt

```sh
./build.sh                       # build + cài ~/Applications/MacSentry.app (tự khởi động cùng máy)
```

Cấu hình Telegram tại `~/Library/Application Support/MacSentry/telegram.json`:

```json
{"botToken": "123456:ABC...", "chatId": "987654321"}
```

Sau đó cài daemon (lấy token từ file trên, lưu vào `/etc/macsentry.conf` chỉ root đọc được):

```sh
sudo ./daemon/install.sh         # gỡ: sudo ./daemon/uninstall.sh
```

## Ghi chú

- macOS ẩn socket TCP với `netstat` khi được gọi từ binary không phải của hệ thống, nên app giao việc chạy
  `netstat` cho một job `launchd` (`io.github.vuminhhoa.macsentry.netstat`) và đọc kết quả từ file.
- Chạy thử daemon không cần root và không gửi Telegram:
  `DRYRUN=1 CONF=./test.conf LOG=./test.log STATE=./state sh daemon/macsentryd.sh`
