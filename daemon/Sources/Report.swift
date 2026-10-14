import Foundation

// MARK: - Báo cáo tóm tắt mỗi sáng (sau 8h). Không thấy báo cáo trong ngày → daemon/máy có vấn đề.

func dailyReport(boot: Int) {
    let today = fmtDate(Int(Date().timeIntervalSince1970), "yyyyMMdd")
    guard Calendar.current.component(.hour, from: Date()) >= 8, readText(sp("last_report")) != today else { return }
    writeText(sp("last_report"), today)

    // Đếm sự kiện theo biểu tượng đầu dòng (từ thứ 3 của dòng log) kể từ vị trí đọc lần trước
    var counts: [String: Int] = [:]
    let off = readText(sp("report_off")).flatMap { UInt64($0.trimmingCharacters(in: .whitespacesAndNewlines)) } ?? 0
    if let h = FileHandle(forReadingAtPath: logPath) {
        let size = (try? h.seekToEnd()) ?? 0
        try? h.seek(toOffset: off <= size ? off : 0)
        let data = (try? h.readToEnd()) ?? Data()
        try? h.close()
        writeText(sp("report_off"), "\(size)\n")
        for l in String(decoding: data, as: UTF8.self).split(separator: "\n") {
            let w = l.split(separator: " ", maxSplits: 3)
            if w.count >= 3 { counts[String(w[2]), default: 0] += 1 }
        }
    }
    let summary = counts.sorted { $0.value > $1.value }.map { "\($0.key)×\($0.value)" }.joined(separator: "  ")
    let conns = lines(readText(sp("remote_conns"))).count
    info("""
        📊 Báo cáo hằng ngày
        Máy bật từ: \(fmtDate(boot, "dd/MM/yyyy HH:mm"))
        Sự kiện từ báo cáo trước: \(summary.isEmpty ? "không có" : summary)
        Kết nối từ xa đang mở: \(conns)
        \((readText(sp("posture_now")) ?? "").trimmingCharacters(in: .newlines))
        Firewall: \(readText(sp("firewall"))?.trimmingCharacters(in: .newlines) ?? "?") | Gatekeeper: \(readText(sp("gatekeeper"))?.trimmingCharacters(in: .newlines) ?? "?")
        Endpoint Security: \(esAlive() ? "đang chạy" : "KHÔNG chạy")
        Agent đang chạy: \(agentsRunning.isEmpty ? "không có" : agentsRunning.joined(separator: ", "))
        \(fimSummary())
        \((readText(sp("wazuh_now")) ?? "").trimmingCharacters(in: .newlines))
        (Ngày nào không thấy báo cáo này → kiểm tra máy)
        """)
}

/// File nhạy cảm nào đang giao cho Wazuh theo dõi (FIM=auto)
func fimSummary() -> String {
    let delegated = glob(sensitivePatterns).filter(wazuhFIMCovers)
    return delegated.isEmpty ? "Giám sát file nhạy cảm: MacSentry tự theo dõi tất cả"
                             : "Giám sát file nhạy cảm: \(delegated.count) file do Wazuh theo dõi thời gian thực (\(delegated.prefix(5).joined(separator: ", "))\(delegated.count > 5 ? "…" : ""))"
}
