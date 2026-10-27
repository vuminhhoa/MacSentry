import SwiftUI
import AppKit

// MARK: - Trang Tổng quan (Form dạng nhóm như System Settings)

/// Dòng bấm được có mũi tên ›, như các mục điều hướng trong System Settings
struct NavRow: View {
    let icon: String
    let color: Color
    let title: String
    var value = ""
    var valueColor: Color = .secondary
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                SettingsIcon(symbol: icon, color: color)
                Text(title)
                Spacer()
                Text(value).foregroundStyle(valueColor).monospacedDigit()
                Image(systemName: "chevron.right").font(.system(size: 11, weight: .semibold)).foregroundStyle(.tertiary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

struct OverviewPage: View {
    @ObservedObject var monitor: Monitor
    @ObservedObject var ui: ViewState
    @ObservedObject var log: EventLog

    var today: ArraySlice<LogEvent> { log.since(TimeRange.today.cutoff) }
    var recent: [LogEvent] { Array(log.events.lazy.filter { $0.level != .info }.prefix(6)) }

    var body: some View {
        let prot = Protection(monitor: monitor, ui: ui)
        let today = today
        let todayAlerts = today.lazy.filter { $0.level == .alert }.count
        Form {
            // Đầu trang: biểu tượng lớn + mô tả, như đầu các trang trong System Settings
            Section {
                VStack(spacing: 8) {
                    Circle().fill(prot.color.gradient)
                        .frame(width: 64, height: 64)
                        .overlay(Image(systemName: prot.icon).font(.system(size: 30, weight: .semibold)).foregroundStyle(.white))
                    Text(prot.title).font(.title2.weight(.semibold))
                    Text(prot.detail).foregroundStyle(.secondary).multilineTextAlignment(.center)
                    Text(Telegram.hostName).font(.callout).foregroundStyle(.tertiary)
                    if !prot.untrusted.isEmpty {
                        Button(L("Xem kết nối")) { ui.page = .active }.padding(.top, 4)
                    }
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 10)
            }

            Section {
                NavRow(icon: Page.active.icon, color: .green, title: L("Đang kết nối"),
                       value: prot.untrusted.isEmpty ? "\(monitor.active.count)" : "\(monitor.active.count) · " + Lplural("%ld IP lạ", prot.untrusted.count),
                       valueColor: prot.untrusted.isEmpty ? .secondary : .red) { ui.page = .active }
                NavRow(icon: "exclamationmark.octagon.fill", color: .red, title: L("Cảnh báo hôm nay"),
                       value: "\(todayAlerts) / " + Lplural("%ld sự kiện", today.count)) {
                    ui.eventLevel = .alert; ui.eventRange = .today; ui.page = .events
                }
                NavRow(icon: Page.history.icon, color: .indigo, title: L("Phiên đã ghi"),
                       value: "\(monitor.history.count)") { ui.page = .history }
                NavRow(icon: "paperplane.fill", color: .blue, title: L("Cảnh báo Telegram"),
                       value: Telegram.config == nil ? L("Chưa cấu hình") : L("Đang bật"),
                       valueColor: Telegram.config == nil ? .orange : .secondary) { ui.page = .settings }
            }

            Section(L("Thành phần giám sát")) {
                LabeledContent("MacSentry (app)") { StatusPill(text: L("Đang chạy"), color: .green) }
                ForEach(ui.components, id: \.name) { c in
                    LabeledContent(L(c.name)) {
                        StatusPill(text: !c.installed ? L("Chưa cài") : c.running ? L("Đang chạy") : L("Không chạy"),
                                   color: !c.installed ? .orange : c.running ? .green : .red)
                    }
                }
                if ui.components.contains(where: { !$0.installed || !$0.running }) { DaemonInstallRow(ui: ui) }
                LabeledContent(L("Thông báo macOS")) {
                    StatusPill(text: ui.notificationsAllowed ? L("Được phép") : L("Bị tắt"), color: ui.notificationsAllowed ? .green : .orange)
                }
            }

            Section {
                if recent.isEmpty {
                    Text(log.unreadable ? L("Không đọc được log của daemon.") : L("Chưa có sự kiện đáng chú ý.")).foregroundStyle(.secondary)
                } else {
                    ForEach(recent) { e in
                        Button {
                            ui.eventLevel = nil; ui.eventRange = .all; ui.queries[.events] = ""
                            ui.selectedEvent = e.id; ui.page = .events
                        } label: {
                            HStack(spacing: 8) {
                                LevelIcon(level: e.level)
                                Text(e.text).lineLimit(1)
                                Spacer(minLength: 12)
                                Text(e.time).monospacedDigit().foregroundStyle(.secondary)
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                }
            } header: {
                HStack {
                    Text(L("Sự kiện đáng chú ý gần đây"))
                    Spacer()
                    Button(L("Xem tất cả")) { ui.page = .events }.buttonStyle(.link).font(.callout)
                }
            }
        }
        .formStyle(.grouped)
    }
}
