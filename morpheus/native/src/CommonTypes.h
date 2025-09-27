#ifndef COMMON_TYPES_H
#define COMMON_TYPES_H

#include <string>
#include <vector>

struct InputDeviceInfo {
    std::string name;
    std::string type;
    bool isExternal;
    std::string deviceId;
    std::string manufacturer;
    std::string model;
    std::string vendorId;
    std::string productId;
    bool isVirtual;
    bool isSpoofed;
    bool isBluetooth;
    bool isWireless;
    int threatLevel;        // 0=SAFE, 1=SUSPICIOUS, 2=HIGH_RISK, 3=CRITICAL
    std::string threatReason;
    bool isAllowed;
    std::chrono::milliseconds detectionTime;

    InputDeviceInfo() : isExternal(false), isVirtual(false), isSpoofed(false),
                       isBluetooth(false), isWireless(false), threatLevel(0),
                       isAllowed(true), detectionTime(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())) {}
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

    // Process classification fields
    int threatLevel = 0;      // 0=NONE, 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL
    int category = 0;         // 0=SAFE, 1=AI_TOOL, 2=BROWSER, etc.
    double confidence = 0.0;
    std::string riskReason;
    bool flagged = false;
    bool suspicious = false;
    bool blacklisted = false;

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
    double confidence;
    std::vector<std::string> extendedStyles;

    // Default constructor
    OverlayWindow() : pid(0), bounds{0, 0, 0, 0}, zOrder(0), alpha(1.0), confidence(1.0) {}

    OverlayWindow(const std::string& handle, int p, const std::string& name)
        : windowHandle(handle), pid(p), processName(name), bounds{0, 0, 0, 0}, zOrder(0), alpha(1.0), confidence(1.0) {}
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