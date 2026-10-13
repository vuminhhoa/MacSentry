# MacSentry

Cảnh báo an ninh cho máy Mac, gửi về Telegram. Gồm 2 phần:

- **MacSentry.app** (chạy bằng user, trên thanh menu): theo dõi kết nối truy cập từ xa (SSH, Screen Sharing/VNC,
  Remote Desktop, SMB, AFP) kèm popup cảnh báo IP lạ, khoá/mở khoá màn hình, máy đi ngủ, app bị tắt.
  Lưu lịch sử kết nối, danh sách IP tin cậy, xem log sự kiện của daemon.
- **macsentryd** (LaunchDaemon chạy bằng root, từ lúc bật máy): bật/tắt máy, thức dậy, kết nối từ xa,
  đăng nhập SSH, nhập sai mật khẩu (màn hình khoá / SSH / sudo), dùng sudo, LaunchAgent/Daemon mới,
  user/admin mới, firewall/Gatekeeper bị tắt, dịch vụ từ xa bật/tắt, cổng mới mở ra mạng, USB, ổ đĩa ngoài,
  nguồn điện/pin, đổi mạng, ổ đĩa sắp đầy. Log chỉ-được-ghi-thêm tại `/var/log/macsentry.log`.

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
