#include "ClipboardWatcher.h"
#include <sstream>
#include <algorithm>
#include <regex>
#include <iomanip>

#ifdef _WIN32
#include <combaseapi.h>
#include <shlobj.h>
#elif __APPLE__
#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
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
    InitializeSensitivePatterns();
}

ClipboardWatcher::~ClipboardWatcher() {
    Stop();
}

void ClipboardWatcher::Start(Napi::Function callback, int heartbeatIntervalMs) {
    if (running_.load()) {
        return; // Already running
    }
    
    running_.store(true);
    heartbeatIntervalMs_ = heartbeatIntervalMs;
    callback_ = Napi::Persistent(callback);
    
    // Create thread-safe function for callbacks
    tsfn_ = Napi::ThreadSafeFunction::New(
        callback.Env(),
        callback,
        "ClipboardWatcher",
        0,
        1,
        [this](Napi::Env) {
            // Finalize callback
        }
    );
    
    // Initialize platform-specific clipboard listener
#ifdef _WIN32
    InitializeWindowsClipboardListener();
#elif __APPLE__
    InitializeMacOSClipboardListener();
#endif
    
    // Start worker thread
    worker_thread_ = std::thread([this]() {
        WatcherLoop();
    });
}

void ClipboardWatcher::Stop() {
    if (!running_.load()) {
        return; // Not running
    }
    
    running_.store(false);
    
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
    
#ifdef _WIN32
    CleanupWindowsClipboardListener();
#elif __APPLE__
    CleanupMacOSClipboardListener();
#endif
    
    if (tsfn_) {
        tsfn_.Release();
    }
    
    callback_.Reset();
}

bool ClipboardWatcher::IsRunning() const {
    return running_.load();
}

void ClipboardWatcher::SetPrivacyMode(PrivacyMode mode) {
    privacyMode_.store(mode);
}

PrivacyMode ClipboardWatcher::GetPrivacyMode() const {
    return privacyMode_.load();
}

bool ClipboardWatcher::isPlatformSupported() {
#if defined(_WIN32) || defined(__APPLE__)
    return true;
#else
    return false;
#endif
}

void ClipboardWatcher::WatcherLoop() {
    auto lastHeartbeat = std::chrono::steady_clock::now();
    
    while (running_.load()) {
        try {
#ifdef __APPLE__
            // On macOS, we need to actively check for clipboard changes
            CheckClipboardChanges();
#endif
            
            // Send heartbeat periodically
            auto now = std::chrono::steady_clock::now();
            if (now - lastHeartbeat >= std::chrono::milliseconds(heartbeatIntervalMs_)) {
                EmitHeartbeat();
                lastHeartbeat = now;
            }
            
            // Clean up old fingerprints periodically
            CleanupOldFingerprints();
            
            counter_++;
        } catch (const std::exception& e) {
            EmitErrorEvent(std::string("ClipboardWatcher error: ") + e.what());
        }
        
        // Sleep for a short interval
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

#ifdef _WIN32
void ClipboardWatcher::InitializeWindowsClipboardListener() {
    // Create a message-only window for receiving clipboard notifications
    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = L"ClipboardWatcherWindow";
    
    RegisterClass(&wc);
    
    messageWindow_ = CreateWindow(
        L"ClipboardWatcherWindow",
        L"ClipboardWatcher",
        0, 0, 0, 0, 0,
        HWND_MESSAGE,
        nullptr,
        GetModuleHandle(nullptr),
        this
    );
    
    if (messageWindow_) {
        // Store this pointer in window user data
        SetWindowLongPtr(messageWindow_, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
        
        // Add clipboard format listener
        if (AddClipboardFormatListener(messageWindow_)) {
            clipboardFormatListener_ = 1;
        } else {
            EmitErrorEvent("Failed to register clipboard format listener");
        }
    } else {
        EmitErrorEvent("Failed to create message window for clipboard monitoring");
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
    if (uMsg == WM_CLIPBOARDUPDATE) {
        ClipboardWatcher* watcher = reinterpret_cast<ClipboardWatcher*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
        if (watcher && watcher->running_.load()) {
            watcher->HandleClipboardUpdate();
        }
        return 0;
    }
    
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

void ClipboardWatcher::HandleClipboardUpdate() {
    ProcessClipboardChange();
}

std::string ClipboardWatcher::GetActiveWindowProcessName() {
    HWND foregroundWindow = GetForegroundWindow();
    if (!foregroundWindow) return "";
    
    DWORD processId;
    GetWindowThreadProcessId(foregroundWindow, &processId);
    
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!processHandle) return "";
    
    char processName[MAX_PATH];
    DWORD size = sizeof(processName);
    
    if (QueryFullProcessImageNameA(processHandle, 0, processName, &size)) {
        CloseHandle(processHandle);
        std::string fullPath(processName);
        size_t lastSlash = fullPath.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            return fullPath.substr(lastSlash + 1);
        }
        return fullPath;
    }
    
    CloseHandle(processHandle);
    return "";
}

int ClipboardWatcher::GetActiveWindowPID() {
    HWND foregroundWindow = GetForegroundWindow();
    if (!foregroundWindow) return -1;
    
    DWORD processId;
    GetWindowThreadProcessId(foregroundWindow, &processId);
    return static_cast<int>(processId);
}

std::vector<std::string> ClipboardWatcher::GetClipboardFormats() {
    std::vector<std::string> formats;
    
    if (!OpenClipboard(messageWindow_)) {
        return formats;
    }
    
    UINT format = 0;
    while ((format = EnumClipboardFormats(format)) != 0) {
        switch (format) {
            case CF_TEXT:
            case CF_UNICODETEXT:
                formats.push_back("text/plain");
                break;
            case CF_HTML:
                formats.push_back("text/html");
                break;
            case CF_BITMAP:
            case CF_DIB:
                formats.push_back("image/bitmap");
                break;
            case CF_HDROP:
                formats.push_back("file-list");
                break;
            default:
                // Custom format - try to get name
                char formatName[256];
                if (GetClipboardFormatNameA(format, formatName, sizeof(formatName))) {
                    formats.push_back(std::string("custom/") + formatName);
                }
                break;
        }
    }
    
    CloseClipboard();
    return formats;
}

std::string ClipboardWatcher::ReadClipboardText(int maxLength) {
    if (!OpenClipboard(messageWindow_)) {
        return "";
    }
    
    std::string text;
    HANDLE hData = GetClipboardData(CF_UNICODETEXT);
    if (hData) {
        wchar_t* pszText = static_cast<wchar_t*>(GlobalLock(hData));
        if (pszText) {
            // Convert wide string to UTF-8
            int utf8Length = WideCharToMultiByte(CP_UTF8, 0, pszText, -1, nullptr, 0, nullptr, nullptr);
            if (utf8Length > 0) {
                std::vector<char> utf8Buffer(utf8Length);
                WideCharToMultiByte(CP_UTF8, 0, pszText, -1, utf8Buffer.data(), utf8Length, nullptr, nullptr);
                text = utf8Buffer.data();
            }
            GlobalUnlock(hData);
        }
    }
    
    CloseClipboard();
    
    if (text.length() > static_cast<size_t>(maxLength)) {
        text = text.substr(0, maxLength) + "...";
    }
    
    return text;
}

#elif __APPLE__

void ClipboardWatcher::InitializeMacOSClipboardListener() {
    @autoreleasepool {
        NSPasteboard* pb = [NSPasteboard generalPasteboard];
        lastChangeCount_ = [pb changeCount];
    }
}

void ClipboardWatcher::CleanupMacOSClipboardListener() {
    // Cleanup handled automatically by ARC
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

std::string ClipboardWatcher::GetFrontmostApplication() {
    @autoreleasepool {
        NSRunningApplication* frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
        if (frontApp && frontApp.bundleIdentifier) {
            return std::string([frontApp.bundleIdentifier UTF8String]);
        }
        return "";
    }
}

int ClipboardWatcher::GetFrontmostApplicationPID() {
    @autoreleasepool {
        NSRunningApplication* frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
        if (frontApp) {
            return static_cast<int>(frontApp.processIdentifier);
        }
        return -1;
    }
}

std::vector<std::string> ClipboardWatcher::GetPasteboardTypes() {
    std::vector<std::string> formats;
    
    @autoreleasepool {
        NSPasteboard* pb = [NSPasteboard generalPasteboard];
        NSArray* types = [pb types];
        
        for (NSString* type in types) {
            std::string typeStr = [type UTF8String];
            
            if ([type isEqualToString:NSPasteboardTypeString]) {
                formats.push_back("text/plain");
            } else if ([type isEqualToString:NSPasteboardTypeHTML]) {
                formats.push_back("text/html");
            } else if ([type isEqualToString:NSPasteboardTypePNG]) {
                formats.push_back("image/png");
            } else if ([type isEqualToString:NSPasteboardTypeFileURL]) {
                formats.push_back("file-list");
            } else {
                formats.push_back("custom/" + typeStr);
            }
        }
    }
    
    return formats;
}

std::string ClipboardWatcher::ReadPasteboardText(int maxLength) {
    @autoreleasepool {
        NSPasteboard* pb = [NSPasteboard generalPasteboard];
        NSString* text = [pb stringForType:NSPasteboardTypeString];
        
        if (text) {
            std::string result = [text UTF8String];
            if (result.length() > static_cast<size_t>(maxLength)) {
                result = result.substr(0, maxLength) + "...";
            }
            return result;
        }
        
        return "";
    }
}

#endif

void ClipboardWatcher::ProcessClipboardChange() {
    ClipboardEvent event;
    event.eventType = "clipboard-changed";
    event.sourceApp = GetActiveWindowProcessName();
    event.pid = GetActiveWindowPID();
    event.clipFormats = GetClipboardFormats();
    
    PrivacyMode currentMode = privacyMode_.load();
    
    // Read clipboard content based on privacy mode
    std::string fullContent;
    if (currentMode != PrivacyMode::METADATA_ONLY) {
        fullContent = ReadClipboardText(1024); // Read up to 1KB for analysis
    }
    
    // Set content preview and hash based on privacy mode
    if (currentMode == PrivacyMode::FULL) {
        event.contentPreview = CreateContentPreview(fullContent, 128);
        event.isSensitive = IsContentSensitive(fullContent);
        
        // If content is sensitive, redact even in FULL mode unless explicit consent
        if (event.isSensitive) {
            event.contentPreview = CreateContentPreview(fullContent, 32);
            event.contentHash = HashContent(fullContent);
        }
    } else if (currentMode == PrivacyMode::REDACTED) {
        event.contentPreview = CreateContentPreview(fullContent, 32);
        event.contentHash = HashContent(fullContent);
        event.isSensitive = IsContentSensitive(fullContent);
    } else {
        // METADATA_ONLY
        event.contentPreview = "";
        event.contentHash = "";
        event.isSensitive = false;
    }
    
    // Check rate limiting and deduplication
    std::string fingerprint = CreateEventFingerprint(event);
    if (ShouldEmitEvent(fingerprint)) {
        UpdateFingerprintCache(fingerprint);
        EmitClipboardEvent(event);
        lastEvent_ = event;
    }
}

#ifdef __APPLE__
std::string ClipboardWatcher::GetActiveWindowProcessName() {
    return GetFrontmostApplication();
}

int ClipboardWatcher::GetActiveWindowPID() {
    return GetFrontmostApplicationPID();
}

std::vector<std::string> ClipboardWatcher::GetClipboardFormats() {
    return GetPasteboardTypes();
}

std::string ClipboardWatcher::ReadClipboardText(int maxLength) {
    return ReadPasteboardText(maxLength);
}
#endif

void ClipboardWatcher::EmitClipboardEvent(const ClipboardEvent& event) {
    std::string json_str = CreateEventJson(event);
    
    // Call JavaScript callback with data
    if (tsfn_) {
        tsfn_.NonBlockingCall([json_str](Napi::Env env, Napi::Function callback) {
            callback.Call({Napi::String::New(env, json_str)});
        });
    }
}

void ClipboardWatcher::EmitHeartbeat() {
    std::string json_str = CreateHeartbeatJson();
    
    if (tsfn_) {
        tsfn_.NonBlockingCall([json_str](Napi::Env env, Napi::Function callback) {
            callback.Call({Napi::String::New(env, json_str)});
        });
    }
}

void ClipboardWatcher::EmitErrorEvent(const std::string& message) {
    std::string json_str = CreateErrorJson(message);
    
    if (tsfn_) {
        tsfn_.NonBlockingCall([json_str](Napi::Env env, Napi::Function callback) {
            callback.Call({Napi::String::New(env, json_str)});
        });
    }
}

std::string ClipboardWatcher::CreateEventJson(const ClipboardEvent& event) {
    std::ostringstream json;
    json << "{";
    json << "\"module\": \"clipboard-worker\",";
    json << "\"eventType\": \"" << EscapeJson(event.eventType) << "\",";
    
    if (event.sourceApp.empty()) {
        json << "\"sourceApp\": null,";
    } else {
        json << "\"sourceApp\": \"" << EscapeJson(event.sourceApp) << "\",";
    }
    
    if (event.pid == -1) {
        json << "\"pid\": null,";
    } else {
        json << "\"pid\": " << event.pid << ",";
    }
    
    json << "\"clipFormats\": [";
    for (size_t i = 0; i < event.clipFormats.size(); i++) {
        if (i > 0) json << ",";
        json << "\"" << EscapeJson(event.clipFormats[i]) << "\"";
    }
    json << "],";
    
    if (event.contentPreview.empty()) {
        json << "\"contentPreview\": null,";
    } else {
        json << "\"contentPreview\": \"" << EscapeJson(event.contentPreview) << "\",";
    }
    
    if (event.contentHash.empty()) {
        json << "\"contentHash\": null,";
    } else {
        json << "\"contentHash\": \"" << EscapeJson(event.contentHash) << "\",";
    }
    
    json << "\"isSensitive\": " << (event.isSensitive ? "true" : "false") << ",";
    json << "\"timestamp\": " << event.timestamp.count() << ",";
    json << "\"ts\": " << event.timestamp.count() << ",";
    json << "\"count\": " << counter_.load() << ",";
    json << "\"source\": \"native\"";
    json << "}";
    
    return json.str();
}

std::string ClipboardWatcher::CreateHeartbeatJson() {
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    );
    
    std::ostringstream json;
    json << "{";
    json << "\"module\": \"clipboard-worker\",";
    json << "\"eventType\": \"heartbeat\",";
    json << "\"timestamp\": " << now.count() << ",";
    json << "\"ts\": " << now.count() << ",";
    json << "\"count\": " << counter_.load() << ",";
    json << "\"privacyMode\": " << static_cast<int>(privacyMode_.load()) << ",";
    json << "\"source\": \"native\",";
    json << "\"status\": \"monitoring\"";
    json << "}";
    
    return json.str();
}

std::string ClipboardWatcher::CreateErrorJson(const std::string& message) {
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    );
    
    std::ostringstream json;
    json << "{";
    json << "\"module\": \"clipboard-worker\",";
    json << "\"eventType\": \"error\",";
    json << "\"message\": \"" << EscapeJson(message) << "\",";
    json << "\"timestamp\": " << now.count() << ",";
    json << "\"ts\": " << now.count();
    json << "}";
    
    return json.str();
}

std::string ClipboardWatcher::EscapeJson(const std::string& str) {
    std::string escaped;
    for (char c : str) {
        switch (c) {
            case '\"': escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            case '\b': escaped += "\\b"; break;
            case '\f': escaped += "\\f"; break;
            default: 
                if (c < 32) {
                    escaped += "\\u";
                    escaped += "0000";
                    std::ostringstream hex;
                    hex << std::hex << static_cast<int>(c);
                    std::string hexStr = hex.str();
                    escaped.replace(escaped.length() - hexStr.length(), hexStr.length(), hexStr);
                } else {
                    escaped += c;
                }
                break;
        }
    }
    return escaped;
}

bool ClipboardWatcher::IsContentSensitive(const std::string& content) {
    if (content.empty()) return false;

    // Temporarily disable regex to avoid errors - just check for obvious patterns
    try {
        // Check for common patterns that might indicate sensitive information
        for (const auto& pattern : sensitivePatterns_) {
            std::regex regex(pattern, std::regex_constants::icase);
            if (std::regex_search(content, regex)) {
                return true;
            }
        }
    } catch (const std::exception& e) {
        // If regex fails, fall back to simple string checks
        std::string lower_content = content;
        std::transform(lower_content.begin(), lower_content.end(), lower_content.begin(), ::tolower);

        // Simple checks for sensitive patterns
        if (lower_content.find("password") != std::string::npos ||
            lower_content.find("secret") != std::string::npos ||
            lower_content.find("token") != std::string::npos ||
            lower_content.find("key") != std::string::npos) {
            return true;
        }
    }

    return false;
}

std::string ClipboardWatcher::HashContent(const std::string& content) {
    // Simple hash implementation (in real implementation, use SHA-256)
    std::hash<std::string> hasher;
    std::size_t hashValue = hasher(content);
    
    std::ostringstream oss;
    oss << "sha256-" << std::hex << hashValue;
    return oss.str();
}

std::string ClipboardWatcher::CreateContentPreview(const std::string& content, int maxLength) {
    if (content.empty()) return "";
    
    std::string preview = content;
    if (preview.length() > static_cast<size_t>(maxLength)) {
        preview = preview.substr(0, maxLength) + "...";
    }
    
    // Remove newlines and tabs for preview
    std::replace(preview.begin(), preview.end(), '\n', ' ');
    std::replace(preview.begin(), preview.end(), '\r', ' ');
    std::replace(preview.begin(), preview.end(), '\t', ' ');
    
    return preview;
}

std::string ClipboardWatcher::CreateEventFingerprint(const ClipboardEvent& event) {
    std::ostringstream fingerprint;
    
    // Create fingerprint from formats and content preview/hash
    for (const auto& format : event.clipFormats) {
        fingerprint << format << ";";
    }
    
    if (!event.contentHash.empty()) {
        fingerprint << event.contentHash;
    } else if (!event.contentPreview.empty()) {
        fingerprint << event.contentPreview;
    }
    
    return fingerprint.str();
}

bool ClipboardWatcher::ShouldEmitEvent(const std::string& fingerprint) {
    auto now = std::chrono::steady_clock::now();
    
    // Check if we have seen this fingerprint recently
    auto it = fingerprintCache_.find(fingerprint);
    if (it != fingerprintCache_.end()) {
        auto timeDiff = now - it->second;
        if (timeDiff < minEventInterval_) {
            return false; // Too soon, skip this event
        }
    }
    
    // Check global rate limiting
    auto timeSinceLastEvent = now - lastEventTime_;
    if (timeSinceLastEvent < minEventInterval_) {
        return false;
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
    auto maxAge = std::chrono::seconds(30); // Keep fingerprints for 30 seconds
    
    auto it = fingerprintCache_.begin();
    while (it != fingerprintCache_.end()) {
        if (now - it->second > maxAge) {
            it = fingerprintCache_.erase(it);
        } else {
            ++it;
        }
    }
}

void ClipboardWatcher::InitializeSensitivePatterns() {
    sensitivePatterns_ = {
        // Email patterns
        R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        
        // Phone number patterns
        R"(\b\d{3}[-.]?\d{3}[-.]?\d{4}\b)",
        R"(\(\d{3}\)\s*\d{3}[-.]?\d{4})",
        
        // Credit card patterns (simplified)
        R"(\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b)",
        
        // Social Security Number patterns
        R"(\b\d{3}-\d{2}-\d{4}\b)",
        
        // Long sequences of digits (could be sensitive)
        R"(\b\d{9,}\b)",
        
        // URL patterns with tokens or keys
        R"(https?://[^\s]*(?:token|key|password|secret)[^\s]*)",
        
        // Common password/key indicators
        R"((?i)\b(?:password|passwd|pwd|secret|key|token|auth)\s*[:=]\s*\S+)",
    };
}

ClipboardEvent ClipboardWatcher::GetCurrentSnapshot() {
    ClipboardEvent snapshot;
    snapshot.eventType = "snapshot";
    snapshot.sourceApp = GetActiveWindowProcessName();
    snapshot.pid = GetActiveWindowPID();
    snapshot.clipFormats = GetClipboardFormats();
    
    PrivacyMode currentMode = privacyMode_.load();
    std::string content = ReadClipboardText(1024);
    
    if (currentMode == PrivacyMode::FULL) {
        snapshot.contentPreview = CreateContentPreview(content, 256);
        snapshot.isSensitive = IsContentSensitive(content);
    } else if (currentMode == PrivacyMode::REDACTED) {
        snapshot.contentPreview = CreateContentPreview(content, 32);
        snapshot.contentHash = HashContent(content);
        snapshot.isSensitive = IsContentSensitive(content);
    }
    
    return snapshot;
}

bool ClipboardWatcher::ClearClipboard() {
#ifdef __APPLE__
    @autoreleasepool {
        NSPasteboard* pasteboard = [NSPasteboard generalPasteboard];
        if (pasteboard) {
            // Clear all data from the pasteboard
            [pasteboard clearContents];

            // Verify the clipboard was cleared
            NSArray* types = [pasteboard types];
            if (types == nil || [types count] == 0) {
                return true;
            }
        }
        return false;
    }
#elif _WIN32
    if (OpenClipboard(NULL)) {
        EmptyClipboard();
        CloseClipboard();
        return true;
    }
    return false;
#else
    return false; // Unsupported platform
#endif
}