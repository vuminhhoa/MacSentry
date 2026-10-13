#!/bin/bash
# Build MacSentry.app và cài vào ~/Applications
set -euo pipefail
cd "$(dirname "$0")"
APP="build/MacSentry.app"
rm -rf build && mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

swiftc -O -o "$APP/Contents/MacOS/MacSentry" Sources/main.swift \
  -framework AppKit -framework SwiftUI -framework UserNotifications -framework CoreAudio -framework CoreMediaIO 2>&1 | grep -v "^$" || true
test -x "$APP/Contents/MacOS/MacSentry"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>io.github.vuminhhoa.macsentry</string>
  <key>CFBundleName</key><string>MacSentry</string>
  <key>CFBundleDisplayName</key><string>MacSentry</string>
  <key>CFBundleExecutable</key><string>MacSentry</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>LSUIElement</key><true/>
  <key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST

# Ký bằng chứng chỉ Apple Development (nếu có) để macOS giữ quyền "Mạng cục bộ" qua các lần build.
# Ký ad-hoc (-) thì mỗi lần build là một danh tính mới → quyền cũ không còn áp dụng, netstat bị ẩn socket.
SIGN_ID=$(security find-identity -v -p codesigning | awk -F'"' '/Apple Development/ {print $2; exit}')
codesign --force --deep -s "${SIGN_ID:--}" "$APP"

DEST="$HOME/Applications/MacSentry.app"
mkdir -p "$HOME/Applications"
# Gỡ job launchd trước khi thay app (job có KeepAlive, kill thường sẽ bị chạy lại ngay)
launchctl bootout "gui/$(id -u)/io.github.vuminhhoa.macsentry" 2>/dev/null || true
pkill -x MacSentry || true
rm -rf "$DEST" && cp -R "$APP" "$DEST"
open "$DEST"   # app tự giao lại cho launchd
echo "Đã cài và chạy: $DEST"
