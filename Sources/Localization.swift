import AppKit
import SwiftUI
import Combine

// MARK: - Đa ngôn ngữ. Chuỗi trong mã nguồn là tiếng Việt (ngôn ngữ gốc) và cũng là khoá tra cứu;
// bản dịch nằm ở Resources/<mã>.lproj/Localizable.strings. Không dùng cơ chế tra cứu mặc định của Bundle
// (chỉ đọc ngôn ngữ một lần lúc mở app) để đổi ngôn ngữ là cả app đổi theo ngay, không cần mở lại.

enum AppLanguage: String, CaseIterable, Identifiable {
    case system, vi, en
    var id: String { rawValue }
    /// Tên ngôn ngữ viết bằng chính ngôn ngữ đó, như danh sách ngôn ngữ của macOS
    var title: String {
        switch self {
        case .system: L("Theo hệ thống (%@)", Lang.systemCode() == "vi" ? AppLanguage.vi.title : AppLanguage.en.title)
        case .vi: "Tiếng Việt"
        case .en: "English"
        }
    }
}

final class Lang: ObservableObject {
    static let shared = Lang()
    static let supported = ["vi", "en"]
    private static let key = "language"

    /// Lựa chọn trong Cài đặt (mặc định: theo hệ thống)
    @Published var choice: AppLanguage {
        didSet {
            UserDefaults.standard.set(choice.rawValue, forKey: Self.key)
            resolve()
        }
    }
    /// Ngôn ngữ đang dùng thật sự ("vi" / "en")
    @Published private(set) var code = ""
    private(set) var locale = Locale(identifier: "vi")
    private var bundle: Bundle?
    private var observers: [Any] = []

    private init() {
        choice = AppLanguage(rawValue: UserDefaults.standard.string(forKey: Self.key) ?? "") ?? .system
        resolve()
        // Đổi ngôn ngữ hệ thống (Cài đặt hệ thống › Chung › Ngôn ngữ & Khu vực) khi app đang chạy
        let refresh: (Notification) -> Void = { [weak self] _ in self?.resolve() }
        observers = [
            DistributedNotificationCenter.default().addObserver(forName: .init("AppleLanguagePreferencesChangedNotification"),
                                                                object: nil, queue: .main, using: refresh),
            NotificationCenter.default.addObserver(forName: NSLocale.currentLocaleDidChangeNotification, object: nil, queue: .main, using: refresh),
        ]
    }

    /// Ngôn ngữ hệ thống đầu tiên mà app hỗ trợ; không có thì dùng tiếng Anh. Đọc lại mỗi lần
    /// (Locale.preferredLanguages bị nhớ đệm trong tiến trình). UserDefaults xét cả ngôn ngữ đặt riêng cho app
    static func systemCode() -> String {
        CFPreferencesAppSynchronize(kCFPreferencesAnyApplication)
        let prefs = UserDefaults.standard.stringArray(forKey: "AppleLanguages") ?? Locale.preferredLanguages
        for p in prefs {
            let c = Locale(identifier: p).language.languageCode?.identifier ?? p
            if supported.contains(c) { return c }
        }
        return "en"
    }

    /// Tính lại ngôn ngữ đang dùng — gọi được nhiều lần, chỉ phát thay đổi khi ngôn ngữ thật sự đổi
    func resolve() {
        let c = choice == .system ? Self.systemCode() : choice.rawValue
        guard c != code else { return }
        bundle = c == "vi" ? nil : Bundle.main.path(forResource: c, ofType: "lproj").flatMap(Bundle.init(path:))
        locale = Locale(identifier: c)
        code = c
    }

    func lookup(_ key: String) -> String {
        bundle?.localizedString(forKey: key, value: key, table: nil) ?? key
    }
}

/// Chuỗi giao diện theo ngôn ngữ đang chọn
func L(_ key: String) -> String { Lang.shared.lookup(key) }

/// Chuỗi có tham số kiểu printf: `L("Đã thêm %@", ip)`, `L("%ld phiên", n)`
func L(_ key: String, _ args: CVarArg...) -> String {
    String(format: Lang.shared.lookup(key), locale: Lang.shared.locale, arguments: args)
}

/// Chuỗi có số đếm: tiếng Anh cần dạng số ít — bản dịch đặt ở khoá "<khoá>#one" (vd. "1 session")
func Lplural(_ key: String, _ n: Int, _ args: CVarArg...) -> String {
    var format = Lang.shared.lookup(key)
    if n == 1 {
        let one = Lang.shared.lookup(key + "#one")
        if one != key + "#one" { format = one }
    }
    return String(format: format, locale: Lang.shared.locale, arguments: [n as CVarArg] + args)
}

/// Gốc của mỗi cây SwiftUI trong cửa sổ: đổi ngôn ngữ → dựng lại toàn bộ cây với chuỗi mới.
/// Trạng thái giao diện nằm ở ViewState nên không mất trang, lựa chọn, bộ lọc
struct LocalizedRoot<Content: View>: View {
    @ObservedObject private var lang = Lang.shared
    let content: Content
    init(_ content: Content) { self.content = content }
    var body: some View {
        content
            .id(lang.code)
            .environment(\.locale, lang.locale)
    }
}
