#ifndef CLIPBOARD_WATCHER_H
#define CLIPBOARD_WATCHER_H

#include <napi.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <functional>
#include <unordered_map>
#include <chrono>

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
#include <tlhelp32.h>
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "user32.lib")
#elif __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#include <ApplicationServices/ApplicationServices.h>
#include <objc/objc-runtime.h>
// Forward declarations for Objective-C classes and types
#ifdef __OBJC__
@class NSPasteboard;
@class NSString;
#else
typedef struct objc_object NSPasteboard;
typedef struct objc_object NSString;
typedef long NSInteger;
#endif
#endif

// Privacy modes for clipboard content handling
enum class PrivacyMode {
    METADATA_ONLY = 0,  // Only capture formats, attribution, timestamp
    REDACTED = 1,       // Capture metadata + short hashed preview
    FULL = 2            // Capture full content (requires explicit consent)
};

struct ClipboardEvent {
    std::string eventType;
    std::string sourceApp;
    int pid;
    std::vector<std::string> clipFormats;
    std::string contentPreview;
    std::string contentHash;
    bool isSensitive;
    std::chrono::milliseconds timestamp;
    
    ClipboardEvent() : pid(-1), isSensitive(false), timestamp(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())) {}
};

class ClipboardWatcher {
public:
    ClipboardWatcher();
    ~ClipboardWatcher();
    
    // Main API methods (following ProcessWatcher pattern)
    void Start(Napi::Function callback, int heartbeatIntervalMs = 5000);
    void Stop();
    bool IsRunning() const;
    
    // Privacy and control methods
    void SetPrivacyMode(PrivacyMode mode);
    PrivacyMode GetPrivacyMode() const;
    ClipboardEvent GetCurrentSnapshot();
    
    // Check if platform is supported
    bool isPlatformSupported();

private:
    // Cross-platform methods used by both platforms
    std::string GetActiveWindowProcessName();
    int GetActiveWindowPID();
    std::vector<std::string> GetClipboardFormats();
    std::string ReadClipboardText(int maxLength = 256);
    void CheckClipboardChanges();

    // Platform-specific implementations
#ifdef _WIN32
    // Windows-specific methods
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    void InitializeWindowsClipboardListener();
    void CleanupWindowsClipboardListener();
    void HandleClipboardUpdate();
    
    HWND messageWindow_;
    UINT clipboardFormatListener_;
#elif __APPLE__
    // macOS-specific methods
    void InitializeMacOSClipboardListener();
    void CleanupMacOSClipboardListener();
    std::string GetFrontmostApplication();
    int GetFrontmostApplicationPID();
    std::vector<std::string> GetPasteboardTypes();
    std::string ReadPasteboardText(int maxLength = 256);
    
    void* pasteboardObserver_;
    NSInteger lastChangeCount_;
#endif
    
    // Cross-platform methods
    void WatcherLoop();
    void EmitClipboardEvent(const ClipboardEvent& event);
    void EmitHeartbeat();
    void EmitErrorEvent(const std::string& message);
    std::string CreateEventJson(const ClipboardEvent& event);
    std::string CreateHeartbeatJson();
    std::string CreateErrorJson(const std::string& message);
    std::string EscapeJson(const std::string& str);
    
    // Privacy and content analysis
    bool IsContentSensitive(const std::string& content);
    std::string HashContent(const std::string& content);
    std::string CreateContentPreview(const std::string& content, int maxLength = 32);
    
    // Deduplication and rate limiting
    std::string CreateEventFingerprint(const ClipboardEvent& event);
    bool ShouldEmitEvent(const std::string& fingerprint);
    void UpdateFingerprintCache(const std::string& fingerprint);
    
    // Thread management (following ProcessWatcher pattern)
    std::atomic<bool> running_;
    std::atomic<int> counter_;
    std::thread worker_thread_;
    Napi::FunctionReference callback_;
    Napi::ThreadSafeFunction tsfn_;
    int heartbeatIntervalMs_;
    
    // Privacy settings
    std::atomic<PrivacyMode> privacyMode_;
    
    // Rate limiting and deduplication
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> fingerprintCache_;
    std::chrono::milliseconds minEventInterval_;
    std::chrono::steady_clock::time_point lastEventTime_;
    
    // Content sensitivity patterns
    std::vector<std::string> sensitivePatterns_;
    void InitializeSensitivePatterns();
    
    // Current clipboard state
    ClipboardEvent lastEvent_;
    std::atomic<bool> hasNewData_;
    
    // Helper methods
    void ProcessClipboardChange();
    std::string GetCurrentTimestamp();
    void CleanupOldFingerprints();
};

#endif // CLIPBOARD_WATCHER_H