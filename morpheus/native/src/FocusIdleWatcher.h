#ifndef FOCUS_IDLE_WATCHER_H
#define FOCUS_IDLE_WATCHER_H

#include <napi.h>
#include <thread>
#include <chrono>
#include <atomic>
#include <string>
#include <functional>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "psapi.lib")
#elif __APPLE__
#include <ApplicationServices/ApplicationServices.h>
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#ifdef __OBJC__
#import <Cocoa/Cocoa.h>
#import <Foundation/Foundation.h>
#endif
#endif

struct FocusIdleEventDetails {
    int idleDuration;               // Seconds, only for idle-end events
    std::string activeApp;          // Name of app that took focus (for focus-lost)
    std::string windowTitle;        // Title of foreign window (optional)
    std::string reason;             // Reason for focus change (optional)
    
    FocusIdleEventDetails() : idleDuration(0) {}
};

struct FocusIdleEvent {
    std::string eventType;          // "idle-start", "idle-end", "focus-lost", "focus-gained", "minimized", "restored"
    int64_t timestamp;              // Milliseconds since epoch
    FocusIdleEventDetails details;  // Event-specific details
    
    FocusIdleEvent() : timestamp(0) {}
    
    FocusIdleEvent(const std::string& type, int64_t ts)
        : eventType(type), timestamp(ts) {}
};

struct FocusIdleConfig {
    int idleThresholdSec;           // Idle threshold in seconds (default: 30)
    int pollIntervalMs;             // Polling interval in milliseconds (default: 1000)
    int focusDebounceMs;            // Focus change debounce time (default: 200)
    std::string examAppTitle;       // Exam app window title for identification
    bool enableIdleDetection;       // Enable idle time monitoring
    bool enableFocusDetection;      // Enable focus monitoring
    bool enableMinimizeDetection;   // Enable minimize monitoring
    
    FocusIdleConfig() : idleThresholdSec(30), pollIntervalMs(1000), focusDebounceMs(200),
                       enableIdleDetection(true), enableFocusDetection(true), 
                       enableMinimizeDetection(true) {}
};

class FocusIdleWatcher {
public:
    FocusIdleWatcher();
    ~FocusIdleWatcher();
    
    // Main interface - follows ProcessWatcher pattern
    void Start(Napi::Function callback, int intervalMs = 1000);
    void Stop();
    bool IsRunning() const;
    void SetConfig(const FocusIdleConfig& config);
    void SetExamWindowHandle(void* windowHandle);  // For focus tracking
    
    // Immediate status check for testing
    FocusIdleEvent GetCurrentStatus();

private:
    std::atomic<bool> running_;
    std::atomic<int> counter_;
    std::thread worker_thread_;
    Napi::FunctionReference callback_;
    Napi::ThreadSafeFunction tsfn_;
    int intervalMs_;
    FocusIdleConfig config_;
    
    // State tracking
    bool isIdle_;
    bool hasFocus_;
    bool isMinimized_;
    bool lastIdleState_;
    bool lastFocusState_;
    bool lastMinimizeState_;
    int64_t lastActivityTime_;
    int64_t idleStartTime_;
    int64_t lastFocusChangeTime_;
    void* examWindowHandle_;        // Platform-specific window handle
    std::string lastActiveApp_;
    
    // Main worker loop
    void WatcherLoop();
    void EmitFocusIdleEvent(const FocusIdleEvent& event);
    void EmitHeartbeat();
    std::string CreateEventJson(const FocusIdleEvent& event);
    std::string EscapeJson(const std::string& str);
    
    // State detection methods
    void CheckIdleState();
    void CheckFocusState();
    void CheckMinimizeState();
    bool ShouldEmitFocusChange(const std::string& newActiveApp, int64_t currentTime);
    
    // Utility methods
    int64_t GetCurrentTimestamp();
    std::string GenerateEventId();
    
#ifdef _WIN32
    // Windows-specific implementation
    HWND examHwnd_;
    
    bool initializeWindows();
    void cleanupWindows();
    
    // Windows idle detection
    int64_t GetWindowsIdleTime();
    bool IsSystemIdle(int thresholdSec);
    
    // Windows focus detection
    std::string GetForegroundWindowInfo(HWND& outHwnd, std::string& outTitle);
    bool IsExamWindowFocused();
    std::string GetProcessNameFromWindow(HWND hwnd);
    std::string GetWindowTitleSafe(HWND hwnd);
    
    // Windows minimize detection
    bool IsExamWindowMinimized();
    
#elif __APPLE__
    // macOS-specific implementation
    bool hasAccessibilityPermission_;
    
    bool initializeMacOS();
    void cleanupMacOS();
    
    // macOS permissions
    bool CheckAccessibilityPermission();
    void RequestAccessibilityPermission();
    void EmitPermissionWarning();
    
    // macOS idle detection
    double GetMacOSIdleTime();
    bool IsSystemIdle(int thresholdSec);
    
    // macOS focus detection
    std::string GetFrontmostApplication(std::string& outTitle);
    bool IsExamWindowFocused();
    
    // macOS minimize detection
    bool IsExamWindowMinimized();
    CFArrayRef GetWindowList();
    bool FindExamWindowInList(CFArrayRef windowList);
    
#endif
    
    // Cross-platform helpers
    void UpdateIdleState(bool currentlyIdle);
    void UpdateFocusState(bool currentlyFocused, const std::string& activeApp, const std::string& windowTitle);
    void UpdateMinimizeState(bool currentlyMinimized);
};

#endif // FOCUS_IDLE_WATCHER_H