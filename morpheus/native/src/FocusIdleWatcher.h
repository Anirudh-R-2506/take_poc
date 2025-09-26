#ifndef FOCUS_IDLE_WATCHER_H
#define FOCUS_IDLE_WATCHER_H

#include <napi.h>
#include <thread>
#include <chrono>
#include <atomic>
#include <string>
#include <functional>

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
    int idleDuration;
    std::string activeApp;
    std::string windowTitle;
    std::string reason;

    FocusIdleEventDetails() : idleDuration(0) {}
};

struct FocusIdleEvent {
    std::string eventType;
    int64_t timestamp;
    FocusIdleEventDetails details;

    FocusIdleEvent() : timestamp(0) {}

    FocusIdleEvent(const std::string& type, int64_t ts)
        : eventType(type), timestamp(ts) {}
};

struct FocusIdleConfig {
    int idleThresholdSec;
    int pollIntervalMs;
    int focusDebounceMs;
    std::string examAppTitle;
    bool enableIdleDetection;
    bool enableFocusDetection;
    bool enableMinimizeDetection;

    FocusIdleConfig() : idleThresholdSec(30), pollIntervalMs(1000), focusDebounceMs(200),
                       enableIdleDetection(true), enableFocusDetection(true),
                       enableMinimizeDetection(true) {}
};

class FocusIdleWatcher {
public:
    FocusIdleWatcher();
    ~FocusIdleWatcher();

    void Start(Napi::Function callback, int intervalMs = 1000);
    void Stop();
    bool IsRunning() const;
    void SetConfig(const FocusIdleConfig& config);
    void SetExamWindowHandle(void* windowHandle);
    FocusIdleEvent GetCurrentStatus();

private:
    std::atomic<bool> running_;
    std::atomic<int> counter_;
    std::thread worker_thread_;
    Napi::FunctionReference callback_;
    Napi::ThreadSafeFunction tsfn_;
    int intervalMs_;
    FocusIdleConfig config_;
    bool isIdle_;
    bool hasFocus_;
    bool isMinimized_;
    bool lastIdleState_;
    bool lastFocusState_;
    bool lastMinimizeState_;
    int64_t lastActivityTime_;
    int64_t idleStartTime_;
    int64_t lastFocusChangeTime_;
    void* examWindowHandle_;
    std::string lastActiveApp_;

    void WatcherLoop();
    void EmitFocusIdleEvent(const FocusIdleEvent& event);
    void EmitHeartbeat();
    std::string CreateEventJson(const FocusIdleEvent& event);
    std::string EscapeJson(const std::string& str);
    void CheckIdleState();
    void CheckFocusState();
    void CheckMinimizeState();
    bool ShouldEmitFocusChange(const std::string& newActiveApp, int64_t currentTime);
    int64_t GetCurrentTimestamp();
    std::string GenerateEventId();
#ifdef _WIN32
    HWND examHwnd_;

    bool initializeWindows();
    void cleanupWindows();
    int64_t GetWindowsIdleTime();
    bool IsSystemIdle(int thresholdSec);
    std::string GetForegroundWindowInfo(HWND& outHwnd, std::string& outTitle);
    bool IsExamWindowFocused();
    std::string GetProcessNameFromWindow(HWND hwnd);
    std::string GetWindowTitleSafe(HWND hwnd);
    bool IsExamWindowMinimized();

#elif __APPLE__
    bool hasAccessibilityPermission_;

    bool initializeMacOS();
    void cleanupMacOS();
    bool CheckAccessibilityPermission();
    void RequestAccessibilityPermission();
    void EmitPermissionWarning();
    double GetMacOSIdleTime();
    bool IsSystemIdle(int thresholdSec);
    std::string GetFrontmostApplication(std::string& outTitle);
    bool IsExamWindowFocused();
    bool IsExamWindowMinimized();
    CFArrayRef GetWindowList();
    bool FindExamWindowInList(CFArrayRef windowList);
#endif

    void UpdateIdleState(bool currentlyIdle);
    void UpdateFocusState(bool currentlyFocused, const std::string& activeApp, const std::string& windowTitle);
    void UpdateMinimizeState(bool currentlyMinimized);
};

#endif // FOCUS_IDLE_WATCHER_H