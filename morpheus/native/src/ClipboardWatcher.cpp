#include "ClipboardWatcher.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <sstream>
#include <regex>
#include <unordered_set>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "psapi.lib")

// Helper function for wide string to UTF-8 conversion (2025 best practice)
static std::string WideStringToUtf8(const wchar_t* wideStr) {
    if (!wideStr) return "";

    int utf8Length = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, nullptr, 0, nullptr, nullptr);
    if (utf8Length <= 0) return "";

    std::vector<char> utf8Buffer(utf8Length);
    WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, utf8Buffer.data(), utf8Length, nullptr, nullptr);
    return std::string(utf8Buffer.data());
}

static std::string WideStringToUtf8(const std::wstring& wideStr) {
    return WideStringToUtf8(wideStr.c_str());
}
#elif __APPLE__
#ifdef __OBJC__
#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#else
#include <CoreFoundation/CoreFoundation.h>
#include <ApplicationServices/ApplicationServices.h>
// Forward declarations for Objective-C interaction
extern "C" {
    void* objc_autoreleasepool_create();
    void objc_autoreleasepool_release(void* pool);
    void* objc_msgSend(void* self, void* selector, ...);
    void* objc_getClass(const char* name);
    void* sel_getUid(const char* name);
}
#endif
#endif

ClipboardWatcher::ClipboardWatcher()
    : running_(false), counter_(0), privacyMode_(PrivacyMode::METADATA_ONLY),
      minEventInterval_(std::chrono::milliseconds(500)), heartbeatIntervalMs_(5000),
      hasNewData_(false)
#ifdef _WIN32
    , messageWindow_(nullptr), clipboardFormatListener_(0)
#elif __APPLE__
    , pasteboardObserver_(nullptr), lastChangeCount_(0)
#endif
{
    lastEventTime_ = std::chrono::steady_clock::now();
    InitializeSensitivePatterns();
}

ClipboardWatcher::~ClipboardWatcher() {
    Stop();
}

void ClipboardWatcher::Start(Napi::Function callback, int heartbeatIntervalMs) {
    if (running_) return;

    heartbeatIntervalMs_ = heartbeatIntervalMs;
    running_ = true;

    // Store callback using ThreadSafeFunction
    tsfn_ = Napi::ThreadSafeFunction::New(
        callback.Env(),
        callback,
        "ClipboardWatcher",
        0,
        1
    );

#ifdef _WIN32
    InitializeWindowsClipboardListener();
#elif __APPLE__
    InitializeMacOSClipboardListener();
#endif

    // Start worker thread
    worker_thread_ = std::thread(&ClipboardWatcher::WatcherLoop, this);

    std::cout << "[ClipboardWatcher] Started with heartbeat interval " << heartbeatIntervalMs << "ms" << std::endl;
}

void ClipboardWatcher::Stop() {
    if (!running_) return;

    running_ = false;

#ifdef _WIN32
    CleanupWindowsClipboardListener();
#elif __APPLE__
    CleanupMacOSClipboardListener();
#endif

    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }

    // Release thread-safe function
    if (tsfn_) {
        tsfn_.Release();
    }

    std::cout << "[ClipboardWatcher] Stopped" << std::endl;
}

bool ClipboardWatcher::IsRunning() const {
    return running_;
}

void ClipboardWatcher::SetPrivacyMode(PrivacyMode mode) {
    privacyMode_ = mode;
    std::cout << "[ClipboardWatcher] Privacy mode set to " << static_cast<int>(mode) << std::endl;
}

PrivacyMode ClipboardWatcher::GetPrivacyMode() const {
    return privacyMode_;
}

ClipboardEvent ClipboardWatcher::GetCurrentSnapshot() {
    ClipboardEvent event;

    try {
        event.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        );
        event.eventType = "clipboard-snapshot";

        // Get current clipboard content
        ProcessClipboardChange();
        event = lastEvent_;
        event.eventType = "clipboard-snapshot";

    } catch (const std::exception& e) {
        event.eventType = "error";
        event.sourceApp = "";
        event.pid = -1;
        std::cerr << "[ClipboardWatcher] Error getting clipboard snapshot: " << e.what() << std::endl;
    }

    return event;
}

bool ClipboardWatcher::isPlatformSupported() {
#ifdef _WIN32
    return true;
#elif __APPLE__
    return true;
#else
    return false;
#endif
}

void ClipboardWatcher::WatcherLoop() {
    auto lastHeartbeat = std::chrono::steady_clock::now();

    while (running_) {
        try {
            // Check for clipboard changes
            CheckClipboardChanges();

            // Send heartbeat periodically
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - lastHeartbeat).count() >= heartbeatIntervalMs_) {
                EmitHeartbeat();
                lastHeartbeat = now;
            }

        } catch (const std::exception& e) {
            std::cerr << "[ClipboardWatcher] Error in worker loop: " << e.what() << std::endl;
        }

        // Sleep for a short interval
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void ClipboardWatcher::ProcessClipboardChange() {
    ClipboardEvent event;
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    );

    event.timestamp = now;
    event.eventType = "clipboard-changed";

    // Get clipboard formats
    event.clipFormats = GetClipboardFormats();

    // Get source application
    event.sourceApp = GetActiveWindowProcessName();
    event.pid = GetActiveWindowPID();

    // Get clipboard content based on privacy mode
    std::string content = ReadClipboardText(1024); // Read up to 1KB

    if (!content.empty()) {
        event.isSensitive = IsContentSensitive(content);
        event.contentHash = HashContent(content);

        switch (privacyMode_) {
            case PrivacyMode::METADATA_ONLY:
                // Only metadata, no content
                break;
            case PrivacyMode::REDACTED:
                event.contentPreview = CreateContentPreview(content, 32);
                break;
            case PrivacyMode::FULL:
                event.contentPreview = content.length() > 256 ? content.substr(0, 256) : content;
                break;
        }
    }

    lastEvent_ = event;
}

void ClipboardWatcher::EmitClipboardEvent(const ClipboardEvent& event) {
    if (!tsfn_) return;

    // Check if we should emit this event (rate limiting)
    std::string fingerprint = CreateEventFingerprint(event);
    if (!ShouldEmitEvent(fingerprint)) {
        return;
    }

    std::string jsonData = CreateEventJson(event);

    // Use ThreadSafeFunction to safely call JavaScript from worker thread
    auto callback = [](Napi::Env env, Napi::Function jsCallback, std::string* data) {
        jsCallback.Call({Napi::String::New(env, *data)});
        delete data;
    };

    napi_status status = tsfn_.BlockingCall(new std::string(jsonData), callback);
    if (status != napi_ok) {
        std::cerr << "[ClipboardWatcher] Error calling JavaScript callback" << std::endl;
    }

    UpdateFingerprintCache(fingerprint);
}

void ClipboardWatcher::EmitHeartbeat() {
    if (!tsfn_) return;

    std::string jsonData = CreateHeartbeatJson();

    auto callback = [](Napi::Env env, Napi::Function jsCallback, std::string* data) {
        jsCallback.Call({Napi::String::New(env, *data)});
        delete data;
    };

    tsfn_.BlockingCall(new std::string(jsonData), callback);
}

std::string ClipboardWatcher::CreateEventJson(const ClipboardEvent& event) {
    std::stringstream ss;

    ss << "{";
    ss << "\"module\":\"clipboard-worker\",";
    ss << "\"eventType\":\"" << EscapeJson(event.eventType) << "\",";
    ss << "\"timestamp\":" << event.timestamp.count() << ",";
    ss << "\"ts\":" << event.timestamp.count() << ",";
    ss << "\"count\":" << counter_++ << ",";
    ss << "\"source\":\"native\",";

    if (!event.sourceApp.empty()) {
        ss << "\"sourceApp\":\"" << EscapeJson(event.sourceApp) << "\",";
    } else {
        ss << "\"sourceApp\":null,";
    }

    if (event.pid != -1) {
        ss << "\"pid\":" << event.pid << ",";
    } else {
        ss << "\"pid\":null,";
    }

    // Clipboard formats
    ss << "\"clipFormats\":[";
    for (size_t i = 0; i < event.clipFormats.size(); i++) {
        if (i > 0) ss << ",";
        ss << "\"" << EscapeJson(event.clipFormats[i]) << "\"";
    }
    ss << "],";

    if (!event.contentPreview.empty()) {
        ss << "\"contentPreview\":\"" << EscapeJson(event.contentPreview) << "\",";
    } else {
        ss << "\"contentPreview\":null,";
    }

    if (!event.contentHash.empty()) {
        ss << "\"contentHash\":\"" << EscapeJson(event.contentHash) << "\",";
    } else {
        ss << "\"contentHash\":null,";
    }

    ss << "\"isSensitive\":" << (event.isSensitive ? "true" : "false") << ",";
    ss << "\"privacyMode\":" << static_cast<int>(privacyMode_.load());
    ss << "}";

    return ss.str();
}

std::string ClipboardWatcher::CreateHeartbeatJson() {
    std::stringstream ss;
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    );

    ss << "{";
    ss << "\"module\":\"clipboard-worker\",";
    ss << "\"eventType\":\"heartbeat\",";
    ss << "\"timestamp\":" << now.count() << ",";
    ss << "\"ts\":" << now.count() << ",";
    ss << "\"count\":" << counter_++ << ",";
    ss << "\"source\":\"native\",";
    ss << "\"privacyMode\":" << static_cast<int>(privacyMode_.load());
    ss << "}";

    return ss.str();
}

std::string ClipboardWatcher::EscapeJson(const std::string& str) {
    std::string escaped;
    for (char c : str) {
        switch (c) {
            case '"': escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\b': escaped += "\\b"; break;
            case '\f': escaped += "\\f"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default:
                if (c >= 0 && c < 32) {
                    // Escape other control characters
                    std::stringstream ss;
                    ss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                    escaped += ss.str();
                } else {
                    escaped += c;
                }
                break;
        }
    }
    return escaped;
}

bool ClipboardWatcher::IsContentSensitive(const std::string& content) {
    // Check against sensitive patterns
    for (const auto& pattern : sensitivePatterns_) {
        try {
            std::regex re(pattern, std::regex_constants::icase);
            if (std::regex_search(content, re)) {
                return true;
            }
        } catch (const std::exception& e) {
            // If regex fails, continue with other patterns
            continue;
        }
    }

    return false;
}

std::string ClipboardWatcher::HashContent(const std::string& content) {
    // Simple hash function for content identification
    std::hash<std::string> hasher;
    size_t hash = hasher(content);

    std::stringstream ss;
    ss << std::hex << hash;
    return ss.str();
}

std::string ClipboardWatcher::CreateContentPreview(const std::string& content, int maxLength) {
    if (content.length() <= maxLength) {
        return content;
    }

    // Create a safe preview
    std::string preview = content.substr(0, maxLength);

    // If it contains sensitive data, redact it
    if (IsContentSensitive(preview)) {
        return "[REDACTED]";
    }

    return preview + "...";
}

std::string ClipboardWatcher::CreateEventFingerprint(const ClipboardEvent& event) {
    std::stringstream ss;
    ss << event.contentHash << "_" << event.sourceApp << "_" << event.pid;
    return ss.str();
}

bool ClipboardWatcher::ShouldEmitEvent(const std::string& fingerprint) {
    auto now = std::chrono::steady_clock::now();

    // Clean up old fingerprints
    CleanupOldFingerprints();

    // Check if we've seen this fingerprint recently
    auto it = fingerprintCache_.find(fingerprint);
    if (it != fingerprintCache_.end()) {
        auto timeDiff = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second);
        if (timeDiff < minEventInterval_) {
            return false; // Too soon, skip this event
        }
    }

    // Check overall rate limiting
    auto timeSinceLastEvent = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastEventTime_);
    if (timeSinceLastEvent < std::chrono::milliseconds(100)) {
        return false; // Rate limited
    }

    return true;
}

void ClipboardWatcher::UpdateFingerprintCache(const std::string& fingerprint) {
    auto now = std::chrono::steady_clock::now();
    fingerprintCache_[fingerprint] = now;
    lastEventTime_ = now;
}

void ClipboardWatcher::CleanupOldFingerprints() {
    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - std::chrono::minutes(5); // Keep fingerprints for 5 minutes

    auto it = fingerprintCache_.begin();
    while (it != fingerprintCache_.end()) {
        if (it->second < cutoff) {
            it = fingerprintCache_.erase(it);
        } else {
            ++it;
        }
    }
}

void ClipboardWatcher::InitializeSensitivePatterns() {
    sensitivePatterns_ = {
        R"(\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b)", // Credit card
        R"(\b\d{3}-\d{2}-\d{4}\b)",                      // SSN
        R"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b)", // Email
        R"(password|passwd|pwd)",                         // Password fields
        R"(token|api[_-]?key|secret)",                   // API keys/tokens
    };
}

#ifdef _WIN32

void ClipboardWatcher::InitializeWindowsClipboardListener() {
    // Create a message-only window for clipboard monitoring
    WNDCLASSW wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = L"ClipboardWatcherWindow";
    RegisterClassW(&wc);

    messageWindow_ = CreateWindowW(
        L"ClipboardWatcherWindow", L"", 0, 0, 0, 0, 0,
        HWND_MESSAGE, nullptr, GetModuleHandle(nullptr), this);

    if (messageWindow_) {
        // Store this instance in window user data
        SetWindowLongPtr(messageWindow_, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));

        // Add clipboard format listener (Windows Vista+)
        if (AddClipboardFormatListener(messageWindow_)) {
            clipboardFormatListener_ = 1;
            std::cout << "[ClipboardWatcher] Windows clipboard format listener registered successfully" << std::endl;
        } else {
            DWORD error = GetLastError();
            std::cout << "[ClipboardWatcher] Failed to add clipboard format listener (error " << error << "), using polling" << std::endl;
        }
    } else {
        DWORD error = GetLastError();
        std::cout << "[ClipboardWatcher] Failed to create message window (error " << error << ")" << std::endl;
    }
}

void ClipboardWatcher::CleanupWindowsClipboardListener() {
    if (clipboardFormatListener_ && messageWindow_) {
        RemoveClipboardFormatListener(messageWindow_);
        clipboardFormatListener_ = 0;
    }

    if (messageWindow_) {
        DestroyWindow(messageWindow_);
        messageWindow_ = nullptr;
    }
}

LRESULT CALLBACK ClipboardWatcher::WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    ClipboardWatcher* instance = reinterpret_cast<ClipboardWatcher*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));

    switch (uMsg) {
        case WM_CLIPBOARDUPDATE:
            if (instance && instance->running_) {
                instance->HandleClipboardUpdate();
            }
            return 0;

        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
}

void ClipboardWatcher::HandleClipboardUpdate() {
    try {
        ProcessClipboardChange();
        hasNewData_ = true;

        // Emit the event
        EmitClipboardEvent(lastEvent_);

    } catch (const std::exception& e) {
        std::cerr << "[ClipboardWatcher] Error handling clipboard update: " << e.what() << std::endl;
    }
}

void ClipboardWatcher::CheckClipboardChanges() {
    // Windows: Clipboard changes are handled via WM_CLIPBOARDUPDATE messages
    // This method is used as a fallback for polling mode
    static DWORD lastSequenceNumber = 0;
    DWORD currentSequenceNumber = GetClipboardSequenceNumber();

    if (currentSequenceNumber != lastSequenceNumber && lastSequenceNumber != 0) {
        HandleClipboardUpdate();
    }

    lastSequenceNumber = currentSequenceNumber;
}

std::vector<std::string> ClipboardWatcher::GetClipboardFormats() {
    std::vector<std::string> formats;

    // Retry mechanism for clipboard access (2025 thread safety enhancement)
    for (int retry = 0; retry < 3; retry++) {
        if (OpenClipboard(nullptr)) {
            UINT format = 0;
            while ((format = EnumClipboardFormats(format)) != 0) {
                wchar_t formatName[256];

                switch (format) {
                    case CF_TEXT: formats.push_back("CF_TEXT"); break;
                    case CF_BITMAP: formats.push_back("CF_BITMAP"); break;
                    case CF_METAFILEPICT: formats.push_back("CF_METAFILEPICT"); break;
                    case CF_SYLK: formats.push_back("CF_SYLK"); break;
                    case CF_DIF: formats.push_back("CF_DIF"); break;
                    case CF_TIFF: formats.push_back("CF_TIFF"); break;
                    case CF_OEMTEXT: formats.push_back("CF_OEMTEXT"); break;
                    case CF_DIB: formats.push_back("CF_DIB"); break;
                    case CF_PALETTE: formats.push_back("CF_PALETTE"); break;
                    case CF_PENDATA: formats.push_back("CF_PENDATA"); break;
                    case CF_RIFF: formats.push_back("CF_RIFF"); break;
                    case CF_WAVE: formats.push_back("CF_WAVE"); break;
                    case CF_UNICODETEXT: formats.push_back("CF_UNICODETEXT"); break;
                    case CF_ENHMETAFILE: formats.push_back("CF_ENHMETAFILE"); break;
                    case CF_HDROP: formats.push_back("CF_HDROP"); break;
                    case CF_LOCALE: formats.push_back("CF_LOCALE"); break;
                    case CF_DIBV5: formats.push_back("CF_DIBV5"); break;
                    default:
                        // Use Unicode version for 2025 compatibility
                        if (GetClipboardFormatNameW(format, formatName, sizeof(formatName) / sizeof(wchar_t)) > 0) {
                            formats.push_back(WideStringToUtf8(formatName));
                        } else {
                            formats.push_back("UNKNOWN_" + std::to_string(format));
                        }
                        break;
                }
            }

            CloseClipboard();
            break; // Success, exit retry loop
        } else {
            // Clipboard is locked, wait and retry
            std::this_thread::sleep_for(std::chrono::milliseconds(10 * (retry + 1)));
        }
    }

    return formats;
}

std::string ClipboardWatcher::ReadClipboardText(int maxLength) {
    std::string result;

    // Retry mechanism for clipboard access (2025 thread safety enhancement)
    for (int retry = 0; retry < 3; retry++) {
        if (OpenClipboard(nullptr)) {
            // Try Unicode text first
            HANDLE hData = GetClipboardData(CF_UNICODETEXT);
            if (hData) {
                wchar_t* pszText = static_cast<wchar_t*>(GlobalLock(hData));
                if (pszText) {
                    result = WideStringToUtf8(pszText);
                    GlobalUnlock(hData);
                }
            } else {
                // Fallback to ANSI text
                hData = GetClipboardData(CF_TEXT);
                if (hData) {
                    char* pszText = static_cast<char*>(GlobalLock(hData));
                    if (pszText) {
                        result = std::string(pszText);
                        GlobalUnlock(hData);
                    }
                }
            }

            CloseClipboard();
            break; // Success, exit retry loop
        } else {
            // Clipboard is locked, wait and retry
            std::this_thread::sleep_for(std::chrono::milliseconds(10 * (retry + 1)));
        }
    }

    // Truncate if necessary
    if (static_cast<int>(result.length()) > maxLength) {
        result = result.substr(0, static_cast<size_t>(maxLength));
    }

    return result;
}

std::string ClipboardWatcher::GetActiveWindowProcessName() {
    HWND hwnd = GetForegroundWindow();
    if (!hwnd) return "";

    DWORD processId;
    if (!GetWindowThreadProcessId(hwnd, &processId)) {
        return "";
    }

    // Use minimal permissions for security (2025 best practice)
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!hProcess) return "";

    wchar_t processName[MAX_PATH];
    DWORD size = MAX_PATH;

    // Use Unicode version for proper 2025 compatibility
    if (QueryFullProcessImageNameW(hProcess, 0, processName, &size)) {
        CloseHandle(hProcess);

        // Convert to UTF-8
        std::string result = WideStringToUtf8(processName);

        // Extract just the filename
        size_t lastSlash = result.find_last_of("\\/");
        return (lastSlash != std::string::npos) ? result.substr(lastSlash + 1) : result;
    }

    CloseHandle(hProcess);
    return "";
}

int ClipboardWatcher::GetActiveWindowPID() {
    HWND hwnd = GetForegroundWindow();
    if (!hwnd) return -1;

    DWORD processId;
    GetWindowThreadProcessId(hwnd, &processId);
    return static_cast<int>(processId);
}

#elif __APPLE__

void ClipboardWatcher::InitializeMacOSClipboardListener() {
    @autoreleasepool {
        NSPasteboard* pasteboard = [NSPasteboard generalPasteboard];
        lastChangeCount_ = [pasteboard changeCount];

        std::cout << "[ClipboardWatcher] macOS clipboard monitoring initialized (change count: " << lastChangeCount_ << ")" << std::endl;
    }
}

void ClipboardWatcher::CleanupMacOSClipboardListener() {
    // No special cleanup needed for macOS
}

void ClipboardWatcher::CheckClipboardChanges() {
    @autoreleasepool {
        NSPasteboard* pasteboard = [NSPasteboard generalPasteboard];
        NSInteger currentChangeCount = [pasteboard changeCount];

        if (currentChangeCount != lastChangeCount_) {
            lastChangeCount_ = currentChangeCount;

            ProcessClipboardChange();
            hasNewData_ = true;

            // Emit the event
            EmitClipboardEvent(lastEvent_);
        }
    }
}

std::vector<std::string> ClipboardWatcher::GetPasteboardTypes() {
    std::vector<std::string> types;

    @autoreleasepool {
        NSPasteboard* pasteboard = [NSPasteboard generalPasteboard];
        NSArray* pasteboardTypes = [pasteboard types];

        for (NSString* type in pasteboardTypes) {
            types.push_back(std::string([type UTF8String]));
        }
    }

    return types;
}

std::string ClipboardWatcher::ReadPasteboardText(int maxLength) {
    std::string result;

    @autoreleasepool {
        NSPasteboard* pasteboard = [NSPasteboard generalPasteboard];
        NSString* text = [pasteboard stringForType:NSPasteboardTypeString];

        if (text) {
            result = std::string([text UTF8String]);

            // Truncate if necessary
            if (result.length() > maxLength) {
                result = result.substr(0, maxLength);
            }
        }
    }

    return result;
}

std::vector<std::string> ClipboardWatcher::GetClipboardFormats() {
    return GetPasteboardTypes();
}

std::string ClipboardWatcher::ReadClipboardText(int maxLength) {
    return ReadPasteboardText(maxLength);
}

std::string ClipboardWatcher::GetFrontmostApplication() {
    std::string appName;

    @autoreleasepool {
        NSWorkspace* workspace = [NSWorkspace sharedWorkspace];
        NSRunningApplication* frontApp = [workspace frontmostApplication];

        if (frontApp) {
            NSString* localizedName = [frontApp localizedName];
            if (localizedName) {
                appName = std::string([localizedName UTF8String]);
            }
        }
    }

    return appName;
}

int ClipboardWatcher::GetFrontmostApplicationPID() {
    int pid = -1;

    @autoreleasepool {
        NSWorkspace* workspace = [NSWorkspace sharedWorkspace];
        NSRunningApplication* frontApp = [workspace frontmostApplication];

        if (frontApp) {
            pid = static_cast<int>([frontApp processIdentifier]);
        }
    }

    return pid;
}

std::string ClipboardWatcher::GetActiveWindowProcessName() {
    return GetFrontmostApplication();
}

int ClipboardWatcher::GetActiveWindowPID() {
    return GetFrontmostApplicationPID();
}

#endif