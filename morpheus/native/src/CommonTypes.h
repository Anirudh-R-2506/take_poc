#ifndef COMMON_TYPES_H
#define COMMON_TYPES_H

#include <string>
#include <vector>

struct InputDeviceInfo {
    std::string name;
    std::string type;
    bool isExternal;
    std::string deviceId;
};

struct StorageDeviceInfo {
    std::string id;
    std::string type;
    std::string name;
    std::string path;
    bool isExternal;

    StorageDeviceInfo(const std::string& deviceId, const std::string& deviceType,
                      const std::string& deviceName, const std::string& devicePath, bool external = true)
        : id(deviceId), type(deviceType), name(deviceName), path(devicePath), isExternal(external) {}

    bool operator==(const StorageDeviceInfo& other) const {
        return id == other.id && path == other.path;
    }
};

struct ProcessInfo {
    int pid;
    std::string name;
    std::string path;
    std::vector<std::string> loadedModules;
    std::vector<std::string> evidence;

    ProcessInfo(int p, const std::string& n, const std::string& pt = "")
        : pid(p), name(n), path(pt) {}
};

struct OverlayWindow {
    std::string windowHandle;
    int pid;
    std::string processName;
    struct {
        int x, y, w, h;
    } bounds;
    int zOrder;
    double alpha;
    std::vector<std::string> extendedStyles;

    OverlayWindow(const std::string& handle, int p, const std::string& name)
        : windowHandle(handle), pid(p), processName(name), zOrder(0), alpha(1.0) {}
};

struct RecordingDetectionResult {
    bool isRecording;
    std::vector<ProcessInfo> recordingSources;
    std::vector<std::string> virtualCameras;
    std::vector<OverlayWindow> overlayWindows;
    double recordingConfidence;
    double overlayConfidence;
    std::string eventType;
};

#endif // COMMON_TYPES_H