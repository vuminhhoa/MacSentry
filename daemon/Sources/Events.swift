import CoreServices
import DiskArbitration
import Foundation
import IOKit
import IOKit.ps
import IOKit.pwr_mgt
import SystemConfiguration

// MARK: - Nguồn sự kiện của hệ thống (thay cho quét định kỳ). Mọi callback chỉ đẩy việc sang hàng đợi `q`.

/// Gộp các lần gọi dồn dập (vd cắm USB sinh nhiều sự kiện) thành một lần chạy sau `delay` giây
private var pending: Set<String> = []
func debounce(_ key: String, _ delay: Double = 1, _ work: @escaping () -> Void) {
    q.async {
        guard !pending.contains(key) else { return }
        pending.insert(key)
        q.asyncAfter(deadline: .now() + delay) { pending.remove(key); work() }
    }
}

private var ioPort: IONotificationPortRef?
private var usbIters: [io_iterator_t] = []
private var rootPort: io_connect_t = 0
private var sleptAt: Date?
private var daSession: DASession?
private var fsStream: FSEventStreamRef?
private var spoolSource: DispatchSourceFileSystemObject?

func startEventSources() {
    let rl = CFRunLoopGetMain()

    // USB cắm / rút (IOKit)
    ioPort = IONotificationPortCreate(kIOMainPortDefault)
    if let ioPort {
        CFRunLoopAddSource(rl, IONotificationPortGetRunLoopSource(ioPort).takeUnretainedValue(), .defaultMode)
        for type in [kIOFirstMatchNotification, kIOTerminatedNotification] {
            var it: io_iterator_t = 0
            let cb: IOServiceMatchingCallback = { _, it in
                while case let s = IOIteratorNext(it), s != 0 { IOObjectRelease(s) }   // phải rút hết để nhận lần sau
                debounce("usb") { checkUSB() }
            }
            if IOServiceAddMatchingNotification(ioPort, type, IOServiceMatching("IOUSBHostDevice"), cb, nil, &it) == KERN_SUCCESS {
                while case let s = IOIteratorNext(it), s != 0 { IOObjectRelease(s) }
                usbIters.append(it)
            }
        }
    }

    // Nguồn điện / pin
    if let src = IOPSNotificationCreateRunLoopSource({ _ in debounce("power") { checkPower() } }, nil)?.takeRetainedValue() {
        CFRunLoopAddSource(rl, src, .defaultMode)
    }

    // Ngủ / thức dậy (thay cho đo độ trễ của vòng lặp)
    var notifier: io_object_t = 0
    var notifyPort: IONotificationPortRef?
    rootPort = IORegisterForSystemPower(nil, &notifyPort, { _, _, msg, arg in
        // iokit_common_msg(x) = 0xE0000000 | x
        switch msg {
        case 0xE000_0270:   // kIOMessageCanSystemSleep — không giữ máy thức
            IOAllowPowerChange(rootPort, Int(bitPattern: arg))
        case 0xE000_0280:   // kIOMessageSystemWillSleep
            q.async { sleptAt = Date() }
            IOAllowPowerChange(rootPort, Int(bitPattern: arg))
        case 0xE000_0300:   // kIOMessageSystemHasPoweredOn
            q.async {
                let slept = sleptAt.map { "\nĐã ngủ khoảng: \(dur(Int(Date().timeIntervalSince($0))))" } ?? ""
                sleptAt = nil
                info("☀️ Máy thức dậy\nLúc: \(nowStr())\(slept)")
                // Thức dậy: mạng / USB / nguồn có thể đã đổi trong lúc ngủ
                debounce("wake", 5) { checkNetwork(); checkUSB(); checkVolumes(); checkPower() }
            }
        default: break
        }
    }, &notifier)
    if let notifyPort { CFRunLoopAddSource(rl, IONotificationPortGetRunLoopSource(notifyPort).takeUnretainedValue(), .defaultMode) }

    // Ổ đĩa gắn / tháo (DiskArbitration)
    daSession = DASessionCreate(nil)
    if let daSession {
        DASessionSetDispatchQueue(daSession, q)
        DARegisterDiskAppearedCallback(daSession, nil, { _, _ in debounce("vol", 2) { checkVolumes() } }, nil)
        DARegisterDiskDisappearedCallback(daSession, nil, { _, _ in debounce("vol", 2) { checkVolumes() } }, nil)
        DARegisterDiskDescriptionChangedCallback(daSession, nil, nil, { _, _, _ in debounce("vol", 2) { checkVolumes() } }, nil)
    }

    // Mạng, proxy, DNS (SCDynamicStore)
    if let s = dynStore {
        SCDynamicStoreSetNotificationKeys(s, ["State:/Network/Global/IPv4", "State:/Network/Global/Proxies"] as CFArray,
                                          ["State:/Network/(Global|Service/[^/]+)/DNS", "State:/Network/Interface/[^/]+/IPv4"] as CFArray)
        SCDynamicStoreSetDispatchQueue(s, q)
    }

    startFSEvents()

    // Hàng đợi tin của helper ES: báo ngay khi có file mới (đổi tên vào thư mục)
    let fd = open(sp("spool"), O_EVTONLY)
    if fd >= 0 {
        let src = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fd, eventMask: .write, queue: q)
        src.setEventHandler { checkSpool() }
        src.setCancelHandler { close(fd) }
        src.resume()
        spoolSource = src
    }
}

/// FSEvents trên các thư mục hay bị cài cắm → kiểm tra ngay khi có thay đổi (quét định kỳ vẫn giữ làm dự phòng).
/// Không theo dõi cả thư mục home (quá nhiều sự kiện khi build/IDE), chỉ các thư mục con nhạy cảm.
func startFSEvents() {
    let homes = userHomes()
    let paths = ["/Library/LaunchAgents", "/Library/LaunchDaemons", "/private/etc", "/usr/local/libexec",
                 "/Library/Security/SecurityAgentPlugins", "/Library/PrivilegedHelperTools", "/Library/StartupItems",
                 "/Library/Extensions", "/Library/Ossec/etc", "/Library/Ossec/active-response/bin", "/private/var/root/.ssh"]
        + homes.flatMap { ["\($0)/Library/LaunchAgents", "\($0)/.ssh"] }
    let existing = paths.filter(exists)
    var ctx = FSEventStreamContext()
    let cb: FSEventStreamCallback = { _, _, n, paths, _, _ in
        let list = unsafeBitCast(paths, to: NSArray.self) as? [String] ?? []
        for p in list.prefix(n) { onFSEvent(p) }
    }
    guard let s = FSEventStreamCreate(nil, cb, &ctx, existing as CFArray, FSEventStreamEventId(kFSEventStreamEventIdSinceNow), 1.0,
                                      FSEventStreamCreateFlags(kFSEventStreamCreateFlagUseCFTypes | kFSEventStreamCreateFlagFileEvents)) else { return }
    FSEventStreamSetDispatchQueue(s, q)
    FSEventStreamStart(s)
    fsStream = s
}

private func onFSEvent(_ p: String) {
    if p.contains("/LaunchAgents") || p.contains("/LaunchDaemons") {
        debounce("launch") { checkLaunchItems(); checkDaemonIntegrity() }
    }
    if p.hasPrefix("/private/etc") || p.contains("/.ssh") {
        debounce("files") { checkFiles() }
    }
    if p.hasPrefix("/Library/Security/") || p.hasPrefix("/Library/PrivilegedHelperTools") || p.hasPrefix("/Library/StartupItems")
        || p.hasPrefix("/Library/Extensions") || p.hasPrefix("/private/etc/periodic") {
        debounce("pdirs") { checkPersistDirs() }
    }
    if p.hasPrefix("/usr/local/libexec") || p.contains("io.github.vuminhhoa.macsentry") || p.hasPrefix("/private/etc/macsentry") {
        debounce("self") { checkSelf() }
    }
    if p.hasPrefix("/Library/Ossec") {
        debounce("wazuh", 2) { checkWazuh(processes()) }
    }
}

// MARK: - Hàng đợi tin của helper ES: file "<alert|info|log>\n<nội dung>"

func checkSpool() {
    let dir = sp("spool")
    for f in ((try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []).filter({ $0.hasSuffix(".msg") }).sorted() {
        let p = "\(dir)/\(f)"
        guard let text = readText(p) else { continue }
        try? FileManager.default.removeItem(atPath: p)
        let parts = text.split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: false)
        let body = parts.count > 1 ? String(parts[1]) : ""
        switch parts.first { case "alert": alert(body); case "info": info(body); default: log(body) }
    }
}
