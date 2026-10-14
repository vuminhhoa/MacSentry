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
  - App điều khiển từ xa (TeamViewer, AnyDesk, RustDesk, Chrome Remote Desktop...) và tunnel (ngrok, cloudflared...):
    tiến trình chạy + phiên kết nối đến trong log của chúng (các app này đi qua máy chủ trung gian, không lộ qua cổng)
  - **Wazuh agent**: tiến trình dừng, mất kết nối manager, đổi manager, cấu hình đổi (kể cả `agent.conf` manager
    đẩy xuống), bật lệnh từ xa, active response đã chạy trên máy, file thực thi/script bị thay
  - **Agent quan trọng nói chung**: danh mục có sẵn (CrowdStrike, SentinelOne, Defender, Sophos, Jamf, Intune, Santa,
    Little Snitch, LuLu, Tailscale, WARP, OpenVPN, Tunnelblick, TeamViewer, AnyDesk...) + `/etc/macsentry.agents`
    → tiến trình dừng, file cấu hình đổi (kèm nội dung, che giá trị bí mật)
  - Mọi LaunchDaemon/Agent: nội dung plist bị sửa, file chạy đổi chữ ký (bị tráo binary); authorization plugin,
    PrivilegedHelperTools, StartupItems, Root CA được tin cậy, kext, login hook, extension trình duyệt,
    dịch vụ hệ thống bị `launchctl disable`, shell rc / `~/.ssh/config` của user
  - Tư thế bảo mật thêm: tự đăng nhập, Guest, khoá màn hình, Find My, MDM, Remote Management, VNC mật khẩu kiểu cũ,
    XProtect quá cũ
  - Chống bị tắt lén: báo khi daemon bị `kill -9`, heartbeat ra dịch vụ ngoài (`HEARTBEAT_URL`), app canh ngược daemon
  - Báo cáo tóm tắt mỗi sáng (không thấy báo cáo → máy/daemon có vấn đề)
- **macsentry-es** (LaunchDaemon root, cần Full Disk Access): đọc sự kiện Endpoint Security qua `/usr/bin/eslogger`,
  gửi qua hàng đợi của macsentryd (không giữ token):
  - Xác thực thất bại kèm **chính xác tiến trình gọi** (không còn báo nhầm do dịch vụ iCloud/FileVault)
  - Có người xem/điều khiển màn hình (Screen Sharing/ARD), cấp quyền TCC nhạy cảm (Ghi màn hình, Trợ năng,
    Theo dõi bàn phím, Full Disk Access, camera, micro...), XProtect phát hiện mã độc, vượt Gatekeeper,
    đổi mật khẩu tài khoản, nạp kext
  - Lệnh nguy hiểm: reverse shell (mọi ngôn ngữ), đọc mật khẩu keychain, tắt SIP/Gatekeeper/firewall, tắt
    MacSentry/Wazuh/EDR, tạo admin, cài login hook, hộp thoại giả hỏi mật khẩu, `curl | sh`, gỡ quarantine

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
sudo ./daemon/install.sh                 # gỡ: sudo ./daemon/uninstall.sh
sudo ./daemon/install.sh --reconfigure   # đổi bot Telegram riêng cho daemon / URL heartbeat
```

Lần đầu cài, cấp **Full Disk Access** cho `/usr/local/libexec/macsentry-es` (Cài đặt → Quyền riêng tư & Bảo mật →
Truy cập toàn bộ ổ đĩa → `+` → Cmd+Shift+G). Chưa cấp thì daemon nhắc qua Telegram.

Khuyên dùng:
- **Bot Telegram riêng cho daemon** (`--reconfigure`): token của app nằm trong thư mục user; phần mềm độc chạy bằng
  user lấy được token thì xoá được tin bot đó đã gửi (trong 48 giờ). Bot riêng → cảnh báo của daemon không bị xoá.
- **Heartbeat** (healthchecks.io miễn phí): daemon ping mỗi phút; mất ping (daemon bị gỡ, máy bị rút điện) thì
  dịch vụ đó báo cho bạn — trường hợp chính máy không thể tự báo.

## Cấu trúc mã nguồn

```
Sources/            app thanh menu (Swift)
  main.swift          điểm vào
  AppDelegate*.swift  vòng đời app; +Monitoring (canh daemon, camera/micro); +Menu; +Alerts (popup/thông báo)
  Monitor.swift       kết nối truy cập từ xa (đọc kết quả của daemon, tự quét khi không có daemon)
  AVSensors, Telegram, LaunchAtLogin, ContentView, Store, Model
daemon/
  macsentryd.sh       daemon root: cấu hình, nạp module, khởi động, vòng lặp chính (tần suất từng nhóm)
  lib/*.sh            mỗi file một nhóm giám sát: util, detail, auth, remote, system, persistence,
                      posture, remote_tools, wazuh, agents, report, hardware
  install.sh / uninstall.sh
es/                 helper Endpoint Security (Swift)
  main.swift          cấu hình, đọc dòng từ eslogger (getline), vòng lặp chạy lại eslogger
  Handlers.swift      xử lý từng loại sự kiện       Rules.swift  quy tắc exec, Aho–Corasick, danh sách cho phép
  Processes.swift     libproc / sysctl              Spool.swift  gửi qua daemon, che bí mật
  EventJSON.swift     đọc JSON mềm dẻo              schema.py    in cấu trúc mẫu sự kiện thật
```

Thêm một nhóm giám sát mới cho daemon: tạo `daemon/lib/<tên>.sh` (chỉ định nghĩa hàm/hằng), thêm tên vào vòng
nạp module và gọi hàm ở nhịp phù hợp trong vòng lặp của `macsentryd.sh`.

## Hiệu năng

Mục tiêu: không ảnh hưởng máy đang làm việc. Đo trên máy dev (IDE, build, nhiều tiến trình):

| Thành phần | CPU (một nhân) | Ghi chú |
|---|---|---|
| macsentryd | ~3–4% | shell nên tốn chủ yếu ở fork; chỉ băm/quét lại khi dữ liệu đổi (theo ctime) |
| macsentry-es + eslogger | ~3% | gần hết là `exec`; tắt bằng `ES_EXEC=0` trong `/etc/macsentry.conf` |
| MacSentry.app | ~0% | dùng kết quả quét của daemon (`/var/run/macsentry/remote`), không tự chạy netstat/who |

- Daemon và helper chạy với `ProcessType = Background` + `LowPriorityIO`: macOS giới hạn CPU/I/O để ưu tiên
  công việc của người dùng (cảnh báo có thể chậm vài giây khi máy bận).
- Khi helper ES chạy, daemon không đọc `log stream` (~5% một nhân) và giãn các lần quét dự phòng.

## Ghi chú

- macOS ẩn socket TCP với `netstat` khi được gọi từ binary không phải của hệ thống, nên app giao việc chạy
  `netstat` cho một job `launchd` (`io.github.vuminhhoa.macsentry.netstat`) và đọc kết quả từ file.
- Chạy thử helper ES không cần root: `STATE=./state build/macsentry-es --replay < su-kien.jsonl`. Mẫu JSON thật
  của từng loại sự kiện được lưu ở `/var/db/macsentry/es_samples/` (để đối chiếu khi macOS đổi định dạng).
- Chạy thử daemon không cần root và không gửi Telegram:
  `DRYRUN=1 CONF=./test.conf LOG=./test.log STATE=./state sh daemon/macsentryd.sh`
