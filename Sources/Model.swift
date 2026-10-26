import Foundation

// MARK: - Model

/// Cổng của các dịch vụ truy cập từ xa cần theo dõi (khớp với remotePorts trong daemon/Sources/Network.swift)
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
    /// Tên dịch vụ để hiển thị (`service` là tên gốc, cũng là khoá nhận diện)
    var serviceName: String { L(service) }
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
