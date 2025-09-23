#ifndef NOTIFICATION_WATCHER_H
#define NOTIFICATION_WATCHER_H

#include <napi.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <map>
#include <set>
#include <functional>

#ifdef _WIN32
#include <windows.h>
#include <comdef.h>
#include <uiautomation.h>
#include <oleacc.h>
#include <psapi.h>
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "oleacc.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "psapi.lib")
#elif __APPLE__
#include <ApplicationServices/ApplicationServices.h>
#include <CoreFoundation/CoreFoundation.h>
// Forward declarations for Objective-C classes
#ifdef __OBJC__
@class NSUserNotificationCenter;
@class NSUserNotification;
@class NSString;
#else
typedef struct objc_object NSUserNotificationCenter;
typedef struct objc_object NSUserNotification; 
typedef struct objc_object NSString;
#endif
#endif

struct NotificationInfo {
    std::string eventType;          // "notification-arrived" or "notification-dismissed"
    std::string sourceApp;          // App name or bundle ID
    int pid;                        // Process ID (-1 if unknown)
    std::string title;              // Notification title
    std::string body;               // Notification body (may be redacted)
    std::string notificationId;     // Unique identifier
    int64_t timestamp;              // Milliseconds since epoch
    double confidence;              // Detection confidence (0.0-1.0)
    
    NotificationInfo() : pid(-1), timestamp(0), confidence(1.0) {}
    
    NotificationInfo(const std::string& type, const std::string& app, int processId,
                    const std::string& titleText, const std::string& bodyText,
                    const std::string& id, int64_t ts, double conf = 1.0)
        : eventType(type), sourceApp(app), pid(processId), title(titleText),
          body(bodyText), notificationId(id), timestamp(ts), confidence(conf) {}
};

struct NotificationConfig {
    bool redactBody;                // Privacy mode - redact notification body
    bool redactTitle;               // Privacy mode - redact notification title  
    int pollingIntervalMs;          // Fallback polling interval
    int rateLimit;                  // Max events per second per source
    int minEventInterval;           // Minimum ms between events from same source
    
    NotificationConfig() : redactBody(false), redactTitle(false), 
                          pollingIntervalMs(1000), rateLimit(2), minEventInterval(500) {}
};

class NotificationWatcher {
public:
    NotificationWatcher();
    ~NotificationWatcher();
    
    // Main interface - follows ProcessWatcher pattern
    void Start(Napi::Function callback, int intervalMs = 1000);
    void Stop();
    bool IsRunning() const;
    void SetConfig(const NotificationConfig& config);
    
    // Immediate detection for testing
    std::vector<NotificationInfo> GetCurrentNotifications();

private:
    std::atomic<bool> running_;
    std::atomic<int> counter_;
    std::thread worker_thread_;
    Napi::FunctionReference callback_;
    Napi::ThreadSafeFunction tsfn_;
    int intervalMs_;
    NotificationConfig config_;
    
    // Rate limiting and deduplication
    std::map<std::string, int64_t> lastEventTime_;  // sourceApp -> last event timestamp
    std::set<std::string> seenNotifications_;       // For deduplication
    
    // Main worker loop
    void WatcherLoop();
    void EmitNotificationEvent(const NotificationInfo& notification);
    void EmitHeartbeat();
    std::string CreateEventJson(const NotificationInfo& notification);
    std::string EscapeJson(const std::string& str);
    
    // Rate limiting and dedup
    bool ShouldEmitEvent(const NotificationInfo& notification);
    std::string CreateNotificationFingerprint(const NotificationInfo& notification);
    
    // Utility methods
    std::string GenerateNotificationId();
    int64_t GetCurrentTimestamp();
    
#ifdef _WIN32
    // Windows-specific implementation
    HWINEVENTHOOK eventHook_;
    IUIAutomation* uiAutomation_;
    bool initializeWindows();
    void cleanupWindows();
    
    // Windows event hook callback
    static void CALLBACK WinEventProc(HWINEVENTHOOK hWinEventHook, DWORD event,
                                     HWND hwnd, LONG idObject, LONG idChild,
                                     DWORD dwEventThread, DWORD dwmsEventTime);
    void HandleWindowEvent(HWND hwnd, DWORD event);
    
    // Windows notification extraction
    std::vector<NotificationInfo> DetectWindowsNotifications();
    NotificationInfo ExtractNotificationFromWindow(HWND hwnd);
    bool IsNotificationWindow(HWND hwnd);
    std::string GetWindowProcessName(HWND hwnd);
    std::string GetNotificationTitle(HWND hwnd);
    std::string GetNotificationBody(HWND hwnd);
    
    // Windows fallback polling
    std::vector<NotificationInfo> PollWindowsNotifications();
    
#elif __APPLE__
    // macOS-specific implementation
    bool hasAccessibilityPermission_;
    CFRunLoopObserverRef runLoopObserver_;
    
    bool initializeMacOS();
    void cleanupMacOS();
    
    // macOS accessibility and window detection
    std::vector<NotificationInfo> DetectMacOSNotifications();
    bool CheckAccessibilityPermission();
    void RequestAccessibilityPermission();
    
    // macOS notification extraction using CGWindowList
    std::vector<NotificationInfo> GetNotificationsFromWindowList();
    NotificationInfo ExtractNotificationFromWindow(CFDictionaryRef windowInfo);
    bool IsNotificationWindow(CFDictionaryRef windowInfo);
    std::string GetWindowOwnerName(CFDictionaryRef windowInfo);
    std::string GetWindowTitle(CFDictionaryRef windowInfo);
    
    // macOS Accessibility API methods
    std::vector<NotificationInfo> GetNotificationsFromAccessibility();
    
    // macOS fallback polling
    std::vector<NotificationInfo> PollMacOSNotifications();
#endif
    
    // Cross-platform helper
    std::string SanitizeText(const std::string& text);
    static NotificationWatcher* instance_;  // For static callbacks
};

#endif // NOTIFICATION_WATCHER_H