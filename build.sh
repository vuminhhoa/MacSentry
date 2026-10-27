#!/bin/bash
# Build MacSentry.app, macsentryd và macsentry-es; mặc định cài app vào ~/Applications và chạy.
#   ./build.sh               build + cài app (app tự cài daemon khi mở lần đầu, hỏi mật khẩu quản trị)
#   ./build.sh --no-install  chỉ build vào build/ (dùng cho CI)
# Biến môi trường:
#   ARCHS="arm64 x86_64"   kiến trúc cần build (mặc định: kiến trúc của máy đang build)
#   SIGN_ID="..."          danh tính ký mã (mặc định: chứng chỉ "Apple Development" đầu tiên, không có thì ký ad-hoc)
#   SWIFT_OPT=-Onone       mức tối ưu của swiftc (mặc định -O; CodeQL dùng -Onone cho nhanh)
set -euo pipefail
cd "$(dirname "$0")"

INSTALL=1
for arg in "$@"; do
  case $arg in
    --no-install) INSTALL=0 ;;
    -h|--help) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Tham số không hợp lệ: $arg" >&2; exit 2 ;;
  esac
done

BUNDLE_ID=io.github.vuminhhoa.macsentry
VERSION=$(tr -d '[:space:]' < VERSION)
BUILD_NUMBER=$(git rev-list --count HEAD 2>/dev/null || echo 1)
MACOS_MIN=26.0
SWIFT_OPT=${SWIFT_OPT:--O}
read -r -a ARCH_LIST <<< "${ARCHS:-$(uname -m)}"
APP="build/MacSentry.app"
rm -rf build && mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" build/obj

# compile <output> <swiftc args...>: build từng kiến trúc rồi gộp bằng lipo
compile() {
  local out=$1; shift
  local parts=()
  for arch in "${ARCH_LIST[@]}"; do
    swiftc "$SWIFT_OPT" -target "$arch-apple-macos$MACOS_MIN" -o "build/obj/$(basename "$out")-$arch" "$@"
    parts+=("build/obj/$(basename "$out")-$arch")
  done
  lipo -create -output "$out" "${parts[@]}"
}

compile "$APP/Contents/MacOS/MacSentry" Sources/*.swift \
  -framework AppKit -framework SwiftUI -framework UserNotifications -framework CoreAudio -framework CoreMediaIO
compile build/macsentryd daemon/Sources/*.swift shared/*.swift
compile build/macsentry-es es/*.swift shared/*.swift

# Bản dịch giao diện (Resources/<mã>.lproj). Tiếng Việt là ngôn ngữ gốc — xem Sources/Localization.swift
plutil -lint -s Resources/*.lproj/*.strings
cp -R Resources/*.lproj "$APP/Contents/Resources/"

# Logo: app tự vẽ ra các cỡ PNG → đóng thành AppIcon.icns (Finder, System Settings, Dock đọc icon từ file này).
# Dùng bản đúng kiến trúc của máy đang build để chạy được cả khi build chéo.
ICON_RENDERER="$APP/Contents/MacOS/MacSentry"
[ -x "build/obj/MacSentry-$(uname -m)" ] && ICON_RENDERER="build/obj/MacSentry-$(uname -m)"
"$ICON_RENDERER" --render-icon build/AppIcon.iconset
iconutil -c icns build/AppIcon.iconset -o "$APP/Contents/Resources/AppIcon.icns"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
  <key>CFBundleName</key><string>MacSentry</string>
  <key>CFBundleDisplayName</key><string>MacSentry</string>
  <key>CFBundleExecutable</key><string>MacSentry</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundleDevelopmentRegion</key><string>vi</string>
  <key>CFBundleLocalizations</key><array><string>vi</string><string>en</string></array>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$BUILD_NUMBER</string>
  <key>LSMinimumSystemVersion</key><string>$MACOS_MIN</string>
  <key>LSUIElement</key><true/>
  <key>NSHighResolutionCapable</key><true/>
  <key>MacSentrySourceDir</key><string>$(pwd | sed 's/&/\&amp;/g; s/</\&lt;/g')</string>
  <key>NSHumanReadableCopyright</key><string>Copyright © 2026 Vũ Minh Hoà. MIT License.</string>
</dict></plist>
PLIST

# Ký bằng chứng chỉ Apple Development (nếu có) để macOS giữ quyền "Mạng cục bộ" và Full Disk Access qua các lần
# build. Ký ad-hoc (-) thì mỗi lần build là một danh tính mới → quyền cũ không còn áp dụng, netstat bị ẩn socket.
SIGN_ID=${SIGN_ID:-$(security find-identity -v -p codesigning 2>/dev/null | awk -F'"' '/Apple Development/ {print $2; exit}')}
codesign --force -s "${SIGN_ID:--}" "$APP"
codesign --force -s "${SIGN_ID:--}" --identifier "$BUNDLE_ID.daemon" build/macsentryd
codesign --force -s "${SIGN_ID:--}" --identifier "$BUNDLE_ID.es" build/macsentry-es
rm -rf build/obj build/AppIcon.iconset
echo "Đã build MacSentry $VERSION ($BUILD_NUMBER) cho ${ARCH_LIST[*]} → build/"
[ "$INSTALL" = 1 ] || exit 0

DEST="$HOME/Applications/MacSentry.app"
mkdir -p "$HOME/Applications"
# Gỡ job launchd trước khi thay app (job có KeepAlive, kill thường sẽ bị chạy lại ngay)
launchctl bootout "gui/$(id -u)/$BUNDLE_ID" 2>/dev/null || true
# Bản cũ dùng label khác: gỡ LaunchAgent và job netstat của chúng để không chạy song song hai bản
for plist in "$HOME"/Library/LaunchAgents/*.macsentry.plist; do
  [ -e "$plist" ] || continue
  label=$(basename "$plist" .plist)
  [ "$label" = "$BUNDLE_ID" ] && continue
  launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
  rm -f "$plist"
done
launchctl list | awk -v keep="$BUNDLE_ID.netstat" '$3 ~ /\.macsentry\.netstat$/ && $3 != keep {print $3}' |
  while read -r label; do launchctl remove "$label" 2>/dev/null || true; done
pkill -x MacSentry || true
rm -rf "$DEST" && cp -R "$APP" "$DEST"
# Báo LaunchServices đọc lại bundle (icon mới hiện trong Finder / System Settings)
LSREGISTER=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
"$LSREGISTER" -u "$APP" 2>/dev/null || true   # bỏ bản trong build/ để hệ thống chỉ biết một app (tránh lấy nhầm icon / quyền)
"$LSREGISTER" -f "$DEST" || true
open "$DEST"   # app tự giao lại cho launchd
echo "Đã cài và chạy: $DEST"
