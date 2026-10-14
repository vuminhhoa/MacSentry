import DiskArbitration
import Foundation
import IOKit
import IOKit.ps
import IOKit.pwr_mgt
import SystemConfiguration

// MARK: - Phần cứng & mạng: USB, ổ đĩa ngoài, nguồn điện, mạng, proxy, DNS, ổ đầy.
// Mỗi nhóm có một hàm "đọc trạng thái → so với lần trước"; hàm được gọi ngay khi có sự kiện (IOKit, DiskArbitration,
// SCDynamicStore — xem Events.swift) và quét dự phòng thưa.

/// Tên các thiết bị USB đang cắm (bỏ hub / bộ điều khiển gốc)
func usbDevices() -> [String] {
    var it: io_iterator_t = 0
    guard IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("IOUSBHostDevice"), &it) == KERN_SUCCESS else { return [] }
    defer { IOObjectRelease(it) }
    let skip = try! NSRegularExpression(pattern: #"^(Root|AppleT[0-9]+USBXHCI|USB[0-9.]* (Gen[0-9]+ )?Hub)$"#)
    var out: [String] = []
    while case let s = IOIteratorNext(it), s != 0 {
        defer { IOObjectRelease(s) }
        var buf = [CChar](repeating: 0, count: 128)
        guard IORegistryEntryGetName(s, &buf) == KERN_SUCCESS else { continue }
        let n = String(cString: buf)
        if skip.firstMatch(in: n, range: NSRange(n.startIndex..., in: n)) == nil { out.append(n) }
    }
    return out
}

/// Danh sách "đã từng thấy" + so trạng thái: thiết bị quen → tin im lặng, lần đầu thấy → cảnh báo
private func knownDiff(_ name: String, _ known: String, _ cur: [String], gone: (String) -> String, back: (String) -> String, new: (String) -> String) {
    if !exists(sp(known)) { writeText(sp(known), cur.map { $0 + "\n" }.joined()) }
    let d = diffState(name, cur)
    for n in d.removed { info(gone(n)) }
    var k = Set(lines(readText(sp(known))))
    for n in d.added {
        if k.contains(n) { info(back(n)) } else { k.insert(n); alert(new(n)) }
    }
    if !d.added.isEmpty { writeText(sp(known), k.sorted().map { $0 + "\n" }.joined()) }
}

func checkUSB() {
    knownDiff("usb", "usb_known", usbDevices(), gone: { "🔌 Đã rút thiết bị USB: \($0)" },
              back: { "🔌 Cắm lại thiết bị USB quen: \($0)" }, new: { "🔌 Vừa cắm thiết bị USB MỚI (chưa từng thấy): \($0)" })
}

func checkVolumes() {
    let vols = ((try? FileManager.default.contentsOfDirectory(atPath: "/Volumes")) ?? [])
        .filter { !["Macintosh HD", "Recovery", "Preboot", "VM", "Data"].contains($0) && !$0.hasPrefix(".") }
    knownDiff("volumes", "volumes_known", vols, gone: { "💾 Đã tháo ổ đĩa: \($0)" },
              back: { "💾 Gắn lại ổ đĩa quen: \($0)" }, new: { "💾 Vừa gắn ổ đĩa MỚI (chưa từng thấy): \($0)" })
}

/// Nguồn điện / pin (máy không có pin như Mac mini: không có nguồn pin → bỏ qua)
func checkPower() {
    guard let snap = IOPSCopyPowerSourcesInfo()?.takeRetainedValue(),
          let list = IOPSCopyPowerSourcesList(snap)?.takeRetainedValue() as? [CFTypeRef] else { return }
    let batt = list.compactMap { IOPSGetPowerSourceDescription(snap, $0)?.takeUnretainedValue() as? [String: Any] }
        .first { $0[kIOPSTypeKey] as? String == kIOPSInternalBatteryType }
    guard let batt else { return }
    let src = (IOPSGetProvidingPowerSourceType(snap)?.takeUnretainedValue() as String?) ?? ""
    let pct = batt[kIOPSCurrentCapacityKey] as? Int ?? 100
    for v in diffState("power", [src], nonempty: true).added {
        v == kIOPSBatteryPowerValue ? alert("🔋 Vừa RÚT SẠC (đang chạy pin \(pct)%)") : info("🔌 Đã cắm sạc (\(pct)%)")
    }
    if pct <= 15, src == kIOPSBatteryPowerValue, throttle("battlow", 3600) { alert("🪫 Pin yếu: \(pct)%") }
}

// MARK: Mạng, proxy, DNS — đọc từ SCDynamicStore (cấu hình mạng của hệ thống)

let dynStore = SCDynamicStoreCreate(nil, "macsentryd" as CFString, { _, keys, _ in
    q.asyncAfter(deadline: .now() + 1) { checkNetwork() }   // gộp các thay đổi liên tiếp khi đổi mạng
}, nil)

func storeDict(_ key: String) -> [String: Any]? { dynStore.flatMap { SCDynamicStoreCopyValue($0, key as CFString) as? [String: Any] } }
func hasDefaultRoute() -> Bool { storeDict("State:/Network/Global/IPv4")?["PrimaryInterface"] != nil }

func checkNetwork() {
    // Mạng: interface mặc định + IP + tên Wi-Fi
    let iface = storeDict("State:/Network/Global/IPv4")?["PrimaryInterface"] as? String
    var ip = "", ssid = ""
    if let iface {
        ip = ((storeDict("State:/Network/Interface/\(iface)/IPv4")?["Addresses"] as? [String]) ?? []).first ?? ""
        let netKey = "\(iface) \(ip)"
        // SSID chỉ đọc qua `ipconfig` (cần quyền vị trí với API) → chỉ chạy khi interface/IP đổi
        if readText(sp("network_key")) != netKey {
            writeText(sp("network_key"), netKey)
            ssid = lines(run("/usr/sbin/ipconfig", ["getsummary", iface])).first { $0.contains(" SSID : ") }
                .map { $0.components(separatedBy: " SSID : ").last ?? "" } ?? ""
            writeText(sp("network_ssid"), ssid)
        } else { ssid = readText(sp("network_ssid")) ?? "" }
    }
    let net = "\(iface ?? "không có mạng") \(ip)\(ssid.isEmpty ? "" : " Wi-Fi: \(ssid)")"
    for v in diffState("network", [net]).added { info("🌐 Mạng thay đổi: \(v)") }

    // Proxy lạ có thể dùng để nghe lén traffic
    var proxy: [String] = []
    if let p = dynStore.flatMap({ SCDynamicStoreCopyProxies($0) }) as? [String: Any] {
        for (k, v) in p.sorted(by: { $0.key < $1.key }) {
            if k.hasSuffix("Enable"), (v as? Int) == 1 { proxy.append("\(k) : 1") }
            if k.hasSuffix("Proxy") || k.hasSuffix("Port") || k.hasSuffix("URLString") { proxy.append("\(k) : \(v)") }
        }
    }
    for v in diffState("proxy", proxy).added { alert("🕸 Cấu hình PROXY thay đổi: \(v)\n(proxy lạ có thể dùng để nghe lén traffic)") }

    // DNS server của mọi dịch vụ mạng (cả VPN)
    var dns = Set<String>()
    if let s = dynStore, let keys = SCDynamicStoreCopyKeyList(s, "State:/Network/(Global|Service/[^/]+)/DNS" as CFString) as? [String] {
        for k in keys { for a in (storeDict(k)?["ServerAddresses"] as? [String]) ?? [] { dns.insert(a) } }
    }
    for v in diffState("dns", Array(dns)).added { info("🧭 DNS server mới: \(v)") }
}

/// Ổ đĩa hệ thống sắp đầy
func checkDisk() {
    var s = statfs()
    guard statfs("/System/Volumes/Data", &s) == 0 else { return }
    let used = Double(s.f_blocks - s.f_bfree), avail = Double(s.f_bavail)
    let pct = Int((used / max(used + avail, 1) * 100).rounded(.up))
    if pct >= 90, throttle("diskfull", 21600) { alert("💽 Ổ đĩa sắp đầy: đã dùng \(pct)%") }
}
