#ifndef SCREEN_WATCHER_H
#define SCREEN_WATCHER_H

#include <napi.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <functional>
#include <set>
#include <map>
#include <chrono>
#include "CommonTypes.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif
#include <windows.h>
#include <setupapi.h>
#include <devguid.h>
#include <cfgmgr32.h>
#include <dxgi.h>
#include <d3d11.h>
#include <winuser.h>
#include <psapi.h>
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d3d11.lib")
#elif __APPLE__
#include <CoreGraphics/CoreGraphics.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/hid/IOHIDLib.h>
#include <ApplicationServices/ApplicationServices.h>
#include <CoreFoundation/CoreFoundation.h>
// Forward declarations for Objective-C types
#ifdef __OBJC__
@class AVCaptureDevice;
@class SCShareableContent;
#endif
#endif

// Enhanced screen sharing detection for 2025
enum class ScreenSharingMethod {
    NONE = 0,
    BROWSER_WEBRTC = 1,
    DESKTOP_DUPLICATION = 2,
    SCREENCAPTUREKIT = 3,
    APPLICATION_SHARING = 4,
    VIRTUAL_CAMERA = 5,
    DISPLAY_MIRRORING = 6,
    REMOTE_DESKTOP = 7
};

// Screen sharing session information
struct ScreenSharingSession {
    ScreenSharingMethod method;
    std::string processName;
    int pid;
    std::string targetUrl;
    std::string description;
    double confidence;
    bool isActive;
};

// Enhanced display information
struct DisplayInfo {
    std::string name;
    std::string deviceId;
    bool isPrimary;
    bool isExternal;
    bool isMirrored;
    bool isBeingCaptured;
    bool hasActiveSessions;
    int width;
    int height;
    int refreshRate;
    std::vector<ScreenSharingSession> activeSessions;
};

// Comprehensive screen status for 2025
struct ScreenStatus {
    bool mirroring;
    bool splitScreen;
    bool screenSharing;
    bool hasActiveCaptureSession;
    std::vector<DisplayInfo> displays;
    std::vector<DisplayInfo> externalDisplays;
    std::vector<InputDeviceInfo> externalKeyboards;
    std::vector<InputDeviceInfo> externalDevices;
    std::vector<ScreenSharingSession> activeSharingSessions;
    RecordingDetectionResult recordingResult;
    double overallThreatLevel;
};

class ScreenWatcher {
public:
    ScreenWatcher();
    ~ScreenWatcher();

    bool startWatching(std::function<void(const std::string&)> callback, int intervalMs = 3000);
    void stopWatching();
    ScreenStatus getCurrentStatus();
    RecordingDetectionResult detectRecordingAndOverlays();
    void setRecordingBlacklist(const std::vector<std::string>& recordingBlacklist);
    std::vector<std::string> getVirtualCameras();
    std::vector<OverlayWindow> getOverlayWindows();
    bool isPlatformSupported();

    // Enhanced 2025 screen sharing detection methods
    std::vector<ScreenSharingSession> detectScreenSharingSessions();
    std::vector<ScreenSharingSession> detectBrowserScreenSharing();
    std::vector<ScreenSharingSession> detectDesktopDuplication();
    std::vector<ScreenSharingSession> detectScreenCaptureKit();
    bool isScreenBeingCaptured();
    double calculateScreenSharingThreatLevel();

    // Advanced overlay and mirroring detection
    bool detectAdvancedScreenMirroring();
    std::vector<DisplayInfo> getEnhancedDisplayInfo();
    bool detectSplitScreenConfiguration();
    std::vector<ScreenSharingSession> detectApplicationSharing();

private:
    std::atomic<bool> isRunning;
    std::thread watcherThread;
    std::function<void(const std::string&)> eventCallback;
    int checkIntervalMs;
    std::set<std::string> recordingBlacklist_;
    bool lastRecordingState_;
    std::vector<OverlayWindow> lastOverlayWindows_;
    double recordingConfidenceThreshold_;
    double overlayConfidenceThreshold_;
    int checkCount_;

    // Enhanced 2025 detection state
    std::vector<ScreenSharingSession> lastSharingSessions_;
    bool lastScreenSharingState_;
    double screenSharingConfidenceThreshold_;
    std::chrono::steady_clock::time_point lastDetectionTime_;
    std::map<int, ScreenSharingMethod> processMethodCache_;

    ScreenStatus detectScreenStatus();

#ifdef _WIN32
    std::vector<DisplayInfo> getWindowsDisplays();
    std::vector<InputDeviceInfo> getWindowsInputDevices();
    bool isWindowsMirroring();
    bool isWindowsSplitScreen();

    // Windows 2025 screen sharing detection
    std::vector<ScreenSharingSession> detectWindowsDesktopDuplication();
    std::vector<ScreenSharingSession> detectWindowsGraphicsCapture();
    bool isDesktopDuplicationActive();
    std::vector<ScreenSharingSession> scanWindowsBrowserScreenSharing();

#elif __APPLE__
    std::vector<DisplayInfo> getMacOSDisplays();
    std::vector<InputDeviceInfo> getMacOSInputDevices();
    bool isMacOSMirroring();
    bool isMacOSSplitScreen();

    // macOS 2025 screen sharing detection
    std::vector<ScreenSharingSession> detectMacOSScreenCaptureKit();
    std::vector<ScreenSharingSession> detectMacOSCoreGraphicsCapture();
    bool isScreenCaptureKitActive();
    std::vector<ScreenSharingSession> scanMacOSBrowserScreenSharing();

#endif

    std::vector<ProcessInfo> detectRecordingProcesses();
    std::vector<OverlayWindow> detectOverlayWindows();
    double calculateRecordingConfidence(const std::vector<ProcessInfo>& recordingProcesses, const std::vector<std::string>& virtualCameras);
    double calculateOverlayConfidence(const std::vector<OverlayWindow>& overlayWindows);
    void initializeRecordingBlacklist();
    std::vector<ProcessInfo> getRunningProcesses();

    // Enhanced 2025 analysis methods
    double calculateScreenSharingConfidence(const std::vector<ScreenSharingSession>& sessions);
    ScreenSharingMethod identifyScreenSharingMethod(const ProcessInfo& process);
    bool isProcessScreenSharing(const ProcessInfo& process);
    std::vector<ScreenSharingSession> analyzeProcessForScreenSharing(const ProcessInfo& process);

    // Browser-specific screen sharing detection
    std::vector<ScreenSharingSession> detectChromeScreenSharing();
    std::vector<ScreenSharingSession> detectFirefoxScreenSharing();
    std::vector<ScreenSharingSession> detectSafariScreenSharing();
    std::vector<ScreenSharingSession> detectEdgeScreenSharing();
    bool isBrowserProcessScreenSharing(const ProcessInfo& process);

#ifdef _WIN32
    std::vector<std::string> getProcessModules(DWORD processID);
    std::vector<OverlayWindow> enumerateWindowsForOverlays();
    std::vector<std::string> enumerateVirtualCameras();
    bool isExternalInputDevice(const std::string& deviceName, const std::string& deviceType);
#elif __APPLE__
    std::vector<std::string> getProcessLibraries(int pid);
    std::vector<OverlayWindow> enumerateWindowsForOverlays();
    std::vector<std::string> enumerateVirtualCameras();
#endif

    std::string statusToJson(const ScreenStatus& status);
    void watcherLoop();
    std::string sanitizeDeviceName(const std::string& name);
    std::string createRecordingOverlayEventJson(const RecordingDetectionResult& result);
    std::string escapeJson(const std::string& str);
};

#endif // SCREEN_WATCHER_H