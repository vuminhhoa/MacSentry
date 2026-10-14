import AppKit
import CoreAudio
import CoreMediaIO
import Foundation

// MARK: - Camera / micro đang được dùng

enum AVSensors {
    /// Các app đang thu âm từ micro (API theo từng tiến trình — không nhầm với thiết bị chỉ đang phát âm thanh)
    static let micIgnored: Set<String> = [
        "com.apple.CoreSpeech",               // "Hey Siri" — luôn nghe theo thiết kế
        "com.apple.accessibility.heard",      // Nhận diện âm thanh (Trợ năng)
    ]
    static func micsInUse() -> [String] {
        var addr = AudioObjectPropertyAddress(mSelector: kAudioHardwarePropertyProcessObjectList,
                                              mScope: kAudioObjectPropertyScopeGlobal, mElement: kAudioObjectPropertyElementMain)
        var size: UInt32 = 0
        guard AudioObjectGetPropertyDataSize(AudioObjectID(kAudioObjectSystemObject), &addr, 0, nil, &size) == noErr else { return [] }
        var ids = [AudioObjectID](repeating: 0, count: Int(size) / MemoryLayout<AudioObjectID>.size)
        AudioObjectGetPropertyData(AudioObjectID(kAudioObjectSystemObject), &addr, 0, nil, &size, &ids)
        return ids.compactMap { id in
            guard let input: UInt32 = prop(id, kAudioProcessPropertyIsRunningInput), input != 0 else { return nil }
            let bundle: Unmanaged<CFString>? = prop(id, kAudioProcessPropertyBundleID)
            let bid = (bundle?.takeRetainedValue() as String?) ?? ""
            if micIgnored.contains(bid) { return nil }
            let pid: pid_t = prop(id, kAudioProcessPropertyPID) ?? 0
            return NSRunningApplication(processIdentifier: pid)?.localizedName ?? (bid.isEmpty ? "pid \(pid)" : bid)
        }
    }

    private static func prop<T>(_ id: AudioObjectID, _ sel: AudioObjectPropertySelector) -> T? {
        var addr = AudioObjectPropertyAddress(mSelector: sel, mScope: kAudioObjectPropertyScopeGlobal, mElement: kAudioObjectPropertyElementMain)
        var size = UInt32(MemoryLayout<T>.size)
        let buf = UnsafeMutablePointer<T>.allocate(capacity: 1); defer { buf.deallocate() }
        return AudioObjectGetPropertyData(id, &addr, 0, nil, &size, buf) == noErr ? buf.pointee : nil
    }

    /// Tên các camera đang được app nào đó dùng
    static func camerasInUse() -> [String] {
        func addr(_ sel: Int) -> CMIOObjectPropertyAddress {
            CMIOObjectPropertyAddress(mSelector: CMIOObjectPropertySelector(sel),
                                      mScope: CMIOObjectPropertyScope(kCMIOObjectPropertyScopeGlobal),
                                      mElement: CMIOObjectPropertyElement(kCMIOObjectPropertyElementMain))
        }
        var a = addr(kCMIOHardwarePropertyDevices)
        var size: UInt32 = 0, used: UInt32 = 0
        guard CMIOObjectGetPropertyDataSize(CMIOObjectID(kCMIOObjectSystemObject), &a, 0, nil, &size) == noErr else { return [] }
        var ids = [CMIOObjectID](repeating: 0, count: Int(size) / MemoryLayout<CMIOObjectID>.size)
        CMIOObjectGetPropertyData(CMIOObjectID(kCMIOObjectSystemObject), &a, 0, nil, size, &used, &ids)
        return ids.compactMap { id in
            var ra = addr(kCMIODevicePropertyDeviceIsRunningSomewhere)
            var running: UInt32 = 0
            CMIOObjectGetPropertyData(id, &ra, 0, nil, UInt32(MemoryLayout<UInt32>.size), &used, &running)
            guard running != 0 else { return nil }
            var na = addr(kCMIOObjectPropertyName)
            var name: Unmanaged<CFString>?
            CMIOObjectGetPropertyData(id, &na, 0, nil, UInt32(MemoryLayout<Unmanaged<CFString>?>.size), &used, &name)
            return (name?.takeRetainedValue() as String?) ?? "Camera"
        }
    }
}
