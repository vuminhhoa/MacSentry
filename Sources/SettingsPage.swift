import SwiftUI
import AppKit

// MARK: - Trang Cài đặt: Telegram, thành phần giám sát, dữ liệu

/// Dữ liệu đang sửa trong khung Telegram
final class TelegramForm: ObservableObject {
    @Published var token = Telegram.config?.botToken ?? ""
    @Published var chatId = Telegram.config?.chatId ?? ""
    @Published var showToken = false
    @Published var testOK: Bool?
    @Published var testText = ""
    @Published var testing = false
}

struct SettingsPage: View {
    @ObservedObject var ui: ViewState
    @ObservedObject var form: TelegramForm
    @ObservedObject var lang = Lang.shared

    static let installCommand = Store.daemonInstallCommand

    var dirty: Bool { form.token != (Telegram.config?.botToken ?? "") || form.chatId != (Telegram.config?.chatId ?? "") }
    var valid: Bool { !form.token.trimmingCharacters(in: .whitespaces).isEmpty && !form.chatId.trimmingCharacters(in: .whitespaces).isEmpty }

    var body: some View {
        Form {
                Section(L("Chung")) {
                    Picker(L("Ngôn ngữ"), selection: $lang.choice) {
                        ForEach(AppLanguage.allCases) { Text($0.title).tag($0) }
                    }
                }

                Section {
                    LabeledContent("Bot token") {
                        HStack {
                            Group {
                                if form.showToken { TextField("", text: $form.token, prompt: Text("123456:ABC…")) }
                                else { SecureField("", text: $form.token, prompt: Text("123456:ABC…")) }
                            }
                            .labelsHidden()
                            .textFieldStyle(.roundedBorder)
                            Button { form.showToken.toggle() } label: { Image(systemName: form.showToken ? "eye.slash" : "eye") }
                                .buttonStyle(.borderless)
                                .help(form.showToken ? L("Ẩn token") : L("Hiện token"))
                        }
                    }
                    LabeledContent("Chat ID") {
                        TextField("", text: $form.chatId, prompt: Text(L("-100… hoặc ID người dùng")))
                            .labelsHidden()
                            .textFieldStyle(.roundedBorder)
                    }
                    HStack {
                        if let ok = form.testOK {
                            Label(form.testText, systemImage: ok ? "checkmark.circle.fill" : "xmark.octagon.fill")
                                .foregroundStyle(ok ? .green : .red)
                        } else if Telegram.config == nil {
                            Text(L("Chưa cấu hình — cảnh báo chỉ hiện trên máy này.")).foregroundStyle(.secondary)
                        }
                        Spacer()
                        if form.testing { ProgressView().controlSize(.small) }
                        Button(L("Gửi thử"), action: test).disabled(Telegram.config == nil || dirty || form.testing)
                        Button(L("Lưu"), action: save).keyboardShortcut("s")
                            .buttonStyle(.borderedProminent)    // thao tác chính của nhóm → tô màu nhấn
                            .disabled(!dirty || !valid)
                    }
                } header: {
                    Text("Telegram")
                } footer: {
                    Text(L("Cảnh báo được gửi ra ngoài máy để kẻ xâm nhập không xoá được dấu vết. Lưu tại %@ (chỉ user này đọc được).", Telegram.configURL.path))
                        .font(.callout).foregroundStyle(.secondary)
                }

                Section(L("Thành phần giám sát")) {
                    ForEach(ui.components, id: \.name) { c in
                        LabeledContent(L(c.name)) {
                            StatusPill(text: !c.installed ? L("Chưa cài") : c.running ? L("Đang chạy") : L("Không chạy"),
                                       color: !c.installed ? .orange : c.running ? .green : .red)
                        }
                    }
                    LabeledContent(L("Cài / cập nhật daemon")) {
                        HStack {
                            Text(Self.installCommand).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                            Button { ui.copy(Self.installCommand, L("Đã sao chép lệnh")) } label: { Image(systemName: "doc.on.doc") }
                                .buttonStyle(.borderless).help(L("Sao chép lệnh"))
                        }
                    }
                }

                Section("macOS") {
                    LabeledContent(L("Thông báo")) {
                        HStack {
                            StatusPill(text: ui.notificationsAllowed ? L("Được phép") : L("Bị tắt"), color: ui.notificationsAllowed ? .green : .orange)
                            Button(L("Mở cài đặt")) { open("x-apple.systempreferences:com.apple.Notifications-Settings.extension") }
                        }
                    }
                    LabeledContent(L("Chia sẻ (Remote Login, Screen Sharing…)")) {
                        Button(L("Mở cài đặt")) { open("x-apple.systempreferences:com.apple.Sharing-Settings.extension") }
                    }
                }

                Section(L("Dữ liệu")) {
                    LabeledContent(L("Lịch sử, IP tin cậy, cấu hình")) {
                        Button(L("Mở thư mục")) { NSWorkspace.shared.open(Store.dir) }
                    }
                    LabeledContent(L("Log của daemon")) {
                        Button(L("Mở bằng Console")) { NSWorkspace.shared.open(URL(fileURLWithPath: Store.daemonLogPath)) }
                    }
                }
        }
        .formStyle(.grouped)
    }

    func open(_ url: String) { if let u = URL(string: url) { NSWorkspace.shared.open(u) } }

    func save() {
        let cfg = Telegram.Config(botToken: form.token.trimmingCharacters(in: .whitespacesAndNewlines),
                                  chatId: form.chatId.trimmingCharacters(in: .whitespacesAndNewlines))
        Store.save(cfg, to: Telegram.configURL)
        form.token = cfg.botToken; form.chatId = cfg.chatId
        form.testOK = nil
        ui.flash(L("Đã lưu cấu hình Telegram"))
    }

    func test() {
        form.testing = true; form.testOK = nil
        Telegram.send(L("🔔 Tin nhắn thử từ MacSentry")) { ok in
            DispatchQueue.main.async {
                form.testing = false
                form.testOK = ok
                form.testText = ok ? L("Đã gửi — kiểm tra Telegram") : L("Gửi thất bại — kiểm tra token, chat ID, mạng")
            }
        }
    }
}
