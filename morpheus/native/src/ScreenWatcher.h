#ifndef SCREEN_WATCHER_H
#define SCREEN_WATCHER_H

#include <napi.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <functional>
#include <set>
#include "CommonTypes.h"

#ifdef _WIN32
#include <windows.h>
#include <setupapi.h>
#include <devguid.h>
#include <cfgmgr32.h>
#pragma comment(lib, "setupapi.lib")
#elif __APPLE__
#include <CoreGraphics/CoreGraphics.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/hid/IOHIDLib.h>
#include <ApplicationServices/ApplicationServices.h>
#endif

struct DisplayInfo {
    std::string name;
    bool isPrimary;
    bool isExternal;
    bool isMirrored;
    int width;
    int height;
};

struct ScreenStatus {
    bool mirroring;
    bool splitScreen;
    std::vector<DisplayInfo> displays;
    std::vector<DisplayInfo> externalDisplays;
    std::vector<InputDeviceInfo> externalKeyboards;
    std::vector<InputDeviceInfo> externalDevices;
    
    // Recording/Overlay detection results
    RecordingDetectionResult recordingResult;
};

class ScreenWatcher {
public:
    ScreenWatcher();
    ~ScreenWatcher();
    
    // Start monitoring with callback
    bool startWatching(std::function<void(const std::string&)> callback, int intervalMs = 3000);
    
    // Stop monitoring
    void stopWatching();
    
    // Get current screen status
    ScreenStatus getCurrentStatus();
    
    // Recording/Overlay detection methods
    RecordingDetectionResult detectRecordingAndOverlays();
    void setRecordingBlacklist(const std::vector<std::string>& recordingBlacklist);
    std::vector<std::string> getVirtualCameras();
    std::vector<OverlayWindow> getOverlayWindows();
    
    // Check if platform is supported
    bool isPlatformSupported();

private:
    std::atomic<bool> isRunning;
    std::thread watcherThread;
    std::function<void(const std::string&)> eventCallback;
    int checkIntervalMs;
    
    // Recording/Overlay detection state
    std::set<std::string> recordingBlacklist_;
    bool lastRecordingState_;
    std::vector<OverlayWindow> lastOverlayWindows_;
    double recordingConfidenceThreshold_;
    double overlayConfidenceThreshold_;
    
    // Platform-specific implementations
    ScreenStatus detectScreenStatus();
    
#ifdef _WIN32
    // Windows-specific methods
    std::vector<DisplayInfo> getWindowsDisplays();
    std::vector<InputDeviceInfo> getWindowsInputDevices();
    bool isWindowsMirroring();
    bool isWindowsSplitScreen();
#elif __APPLE__
    // macOS-specific methods
    std::vector<DisplayInfo> getMacOSDisplays();
    std::vector<InputDeviceInfo> getMacOSInputDevices();
    bool isMacOSMirroring();
    bool isMacOSSplitScreen();
#endif
    
    // Recording/Overlay detection methods
    std::vector<ProcessInfo> detectRecordingProcesses();
    std::vector<OverlayWindow> detectOverlayWindows();
    double calculateRecordingConfidence(const std::vector<ProcessInfo>& recordingProcesses, const std::vector<std::string>& virtualCameras);
    double calculateOverlayConfidence(const std::vector<OverlayWindow>& overlayWindows);
    void initializeRecordingBlacklist();
    std::vector<ProcessInfo> getRunningProcesses();
    
    // Platform-specific recording detection methods
#ifdef _WIN32
    std::vector<std::string> getProcessModules(DWORD processID);
    std::vector<OverlayWindow> enumerateWindowsForOverlays();
    std::vector<std::string> enumerateVirtualCameras();
#elif __APPLE__
    std::vector<std::string> getProcessLibraries(int pid);
    std::vector<OverlayWindow> enumerateWindowsForOverlays();
    std::vector<std::string> enumerateVirtualCameras();
#endif
    
    // Helper methods
    std::string statusToJson(const ScreenStatus& status);
    void watcherLoop();
    std::string sanitizeDeviceName(const std::string& name);
    std::string createRecordingOverlayEventJson(const RecordingDetectionResult& result);
    std::string escapeJson(const std::string& str);
};

#endif // SCREEN_WATCHER_H