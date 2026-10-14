import Foundation

// MARK: - Model

/// Cổng của các dịch vụ truy cập từ xa cần theo dõi (khớp với REMOTE_PORTS trong daemon/macsentryd.sh)
let remoteServices: [String: String] = [
    "22": "SSH", "5900": "Screen Sharing/VNC", "3283": "Apple Remote Desktop", "445": "Chia sẻ file SMB", "548": "AFP", "3031": "Remote Apple Events",
]

struct RemoteConnection: Identifiable, Hashable {
    let ip: String
    let remotePort: String
    let service: String
    var user: String?
    var firstSeen: Date
    var id: String { "\(service)|\(ip):\(remotePort)" }
}

struct HistoryEntry: Codable, Identifiable, Hashable {
    var id = UUID()
    let ip: String
    let remotePort: String
    var service: String? // nil = dữ liệu cũ từ SSHWatch (chỉ có SSH)
    var user: String?
    let start: Date
    var end: Date?
}
