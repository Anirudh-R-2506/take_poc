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
#ifdef __OBJC__
@class NSPasteboard;
@class NSString;
#else
typedef struct objc_object NSPasteboard;
typedef struct objc_object NSString;
typedef long NSInteger;
#endif
#endif

enum class PrivacyMode {
    METADATA_ONLY = 0,
    REDACTED = 1,
    FULL = 2
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

    void Start(Napi::Function callback, int heartbeatIntervalMs = 5000);
    void Stop();
    bool IsRunning() const;
    void SetPrivacyMode(PrivacyMode mode);
    PrivacyMode GetPrivacyMode() const;
    ClipboardEvent GetCurrentSnapshot();
    bool ClearClipboard();
    bool isPlatformSupported();

private:
    std::string GetActiveWindowProcessName();
    int GetActiveWindowPID();
    std::vector<std::string> GetClipboardFormats();
    std::string ReadClipboardText(int maxLength = 256);
    void CheckClipboardChanges();

#ifdef _WIN32
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    void InitializeWindowsClipboardListener();
    void CleanupWindowsClipboardListener();
    void HandleClipboardUpdate();
    HWND messageWindow_;
    UINT clipboardFormatListener_;
#elif __APPLE__
    void InitializeMacOSClipboardListener();
    void CleanupMacOSClipboardListener();
    std::string GetFrontmostApplication();
    int GetFrontmostApplicationPID();
    std::vector<std::string> GetPasteboardTypes();
    std::string ReadPasteboardText(int maxLength = 256);
    void* pasteboardObserver_;
    NSInteger lastChangeCount_;
#endif

    void WatcherLoop();
    void EmitClipboardEvent(const ClipboardEvent& event);
    void EmitHeartbeat();
    void EmitErrorEvent(const std::string& message);
    std::string CreateEventJson(const ClipboardEvent& event);
    std::string CreateHeartbeatJson();
    std::string CreateErrorJson(const std::string& message);
    std::string EscapeJson(const std::string& str);
    bool IsContentSensitive(const std::string& content);
    std::string HashContent(const std::string& content);
    std::string CreateContentPreview(const std::string& content, int maxLength = 32);
    std::string CreateEventFingerprint(const ClipboardEvent& event);
    bool ShouldEmitEvent(const std::string& fingerprint);
    void UpdateFingerprintCache(const std::string& fingerprint);
    std::atomic<bool> running_;
    std::atomic<int> counter_;
    std::thread worker_thread_;
    Napi::FunctionReference callback_;
    Napi::ThreadSafeFunction tsfn_;
    int heartbeatIntervalMs_;
    std::atomic<PrivacyMode> privacyMode_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> fingerprintCache_;
    std::chrono::milliseconds minEventInterval_;
    std::chrono::steady_clock::time_point lastEventTime_;
    std::vector<std::string> sensitivePatterns_;
    ClipboardEvent lastEvent_;
    std::atomic<bool> hasNewData_;

    void InitializeSensitivePatterns();
    void ProcessClipboardChange();
    std::string GetCurrentTimestamp();
    void CleanupOldFingerprints();
};

#endif // CLIPBOARD_WATCHER_H