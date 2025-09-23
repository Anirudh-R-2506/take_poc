#include "FocusIdleWatcher.h"
#include <sstream>
#include <ctime>
#include <chrono>
#include <algorithm>

FocusIdleWatcher::FocusIdleWatcher() 
    : running_(false), counter_(0), intervalMs_(1000), isIdle_(false), 
      hasFocus_(true), isMinimized_(false), lastActivityTime_(0), 
      idleStartTime_(0), lastFocusChangeTime_(0), examWindowHandle_(nullptr)
#ifdef _WIN32
    , examHwnd_(nullptr)
#elif __APPLE__
    , hasAccessibilityPermission_(false)
#endif
{
    lastActivityTime_ = GetCurrentTimestamp();
}

FocusIdleWatcher::~FocusIdleWatcher() {
    Stop();
}

void FocusIdleWatcher::Start(Napi::Function callback, int intervalMs) {
    if (running_.load()) {
        return; // Already running
    }
    
    intervalMs_ = intervalMs;
    callback_ = Napi::Persistent(callback);
    
    // Create thread-safe function for callbacks
    tsfn_ = Napi::ThreadSafeFunction::New(
        callback.Env(),
        callback,
        "FocusIdleWatcher",
        0,
        1,
        [this](Napi::Env) {
            // Finalize callback
        }
    );
    
    running_.store(true);
    
    // Start worker thread
    worker_thread_ = std::thread([this]() {
        WatcherLoop();
    });
}

void FocusIdleWatcher::Stop() {
    if (!running_.load()) {
        return; // Not running
    }
    
    running_.store(false);
    
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
    
#ifdef _WIN32
    cleanupWindows();
#elif __APPLE__
    cleanupMacOS();
#endif
    
    if (tsfn_) {
        tsfn_.Release();
    }
    
    callback_.Reset();
}

bool FocusIdleWatcher::IsRunning() const {
    return running_.load();
}

void FocusIdleWatcher::SetConfig(const FocusIdleConfig& config) {
    config_ = config;
}

void FocusIdleWatcher::SetExamWindowHandle(void* windowHandle) {
    examWindowHandle_ = windowHandle;
#ifdef _WIN32
    examHwnd_ = static_cast<HWND>(windowHandle);
#endif
}

void FocusIdleWatcher::WatcherLoop() {
    // Platform-specific initialization
    bool initialized = false;
#ifdef _WIN32
    initialized = initializeWindows();
#elif __APPLE__
    initialized = initializeMacOS();
#endif
    
    if (!initialized) {
        printf("[FocusIdleWatcher] Failed to initialize platform-specific components\n");
    }
    
    auto lastHeartbeat = std::chrono::steady_clock::now();
    const auto heartbeatInterval = std::chrono::seconds(5);
    
    while (running_.load()) {
        try {
            // Check idle state
            if (config_.enableIdleDetection) {
                CheckIdleState();
            }
            
            // Check focus state
            if (config_.enableFocusDetection) {
                CheckFocusState();
            }
            
            // Check minimize state
            if (config_.enableMinimizeDetection) {
                CheckMinimizeState();
            }
            
            // Send periodic heartbeat
            auto now = std::chrono::steady_clock::now();
            if (now - lastHeartbeat >= heartbeatInterval) {
                EmitHeartbeat();
                lastHeartbeat = now;
            }
            
            counter_++;
            
        } catch (const std::exception& e) {
            printf("[FocusIdleWatcher] Error in watcher loop: %s\n", e.what());
        }
        
        // Sleep for specified interval
        std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs_));
    }
}

void FocusIdleWatcher::CheckIdleState() {
    bool currentlyIdle = IsSystemIdle(config_.idleThresholdSec);
    UpdateIdleState(currentlyIdle);
}

void FocusIdleWatcher::CheckFocusState() {
    bool currentlyFocused = IsExamWindowFocused();
    std::string activeApp;
    std::string windowTitle;
    
    if (!currentlyFocused) {
#ifdef _WIN32
        HWND foregroundHwnd;
        activeApp = GetForegroundWindowInfo(foregroundHwnd, windowTitle);
#elif __APPLE__
        activeApp = GetFrontmostApplication(windowTitle);
#endif
    }
    
    UpdateFocusState(currentlyFocused, activeApp, windowTitle);
}

void FocusIdleWatcher::CheckMinimizeState() {
    bool currentlyMinimized = IsExamWindowMinimized();
    UpdateMinimizeState(currentlyMinimized);
}

void FocusIdleWatcher::UpdateIdleState(bool currentlyIdle) {
    int64_t currentTime = GetCurrentTimestamp();
    
    if (currentlyIdle != isIdle_) {
        if (currentlyIdle) {
            // Transition to idle
            idleStartTime_ = currentTime;
            FocusIdleEvent event("idle-start", currentTime);
            EmitFocusIdleEvent(event);
        } else {
            // Transition from idle to active
            int idleDuration = static_cast<int>((currentTime - idleStartTime_) / 1000);
            FocusIdleEvent event("idle-end", currentTime);
            event.details.idleDuration = idleDuration;
            EmitFocusIdleEvent(event);
            
            lastActivityTime_ = currentTime;
        }
        
        isIdle_ = currentlyIdle;
    }
}

void FocusIdleWatcher::UpdateFocusState(bool currentlyFocused, const std::string& activeApp, const std::string& windowTitle) {
    int64_t currentTime = GetCurrentTimestamp();
    
    if (currentlyFocused != hasFocus_) {
        if (ShouldEmitFocusChange(activeApp, currentTime)) {
            if (!currentlyFocused) {
                // Lost focus
                FocusIdleEvent event("focus-lost", currentTime);
                event.details.activeApp = activeApp;
                event.details.windowTitle = windowTitle;
                event.details.reason = "user-switched-app";
                EmitFocusIdleEvent(event);
            } else {
                // Gained focus
                FocusIdleEvent event("focus-gained", currentTime);
                EmitFocusIdleEvent(event);
            }
            
            hasFocus_ = currentlyFocused;
            lastActiveApp_ = activeApp;
            lastFocusChangeTime_ = currentTime;
        }
    }
}

void FocusIdleWatcher::UpdateMinimizeState(bool currentlyMinimized) {
    if (currentlyMinimized != isMinimized_) {
        int64_t currentTime = GetCurrentTimestamp();
        
        FocusIdleEvent event(currentlyMinimized ? "minimized" : "restored", currentTime);
        EmitFocusIdleEvent(event);
        
        isMinimized_ = currentlyMinimized;
    }
}

bool FocusIdleWatcher::ShouldEmitFocusChange(const std::string& newActiveApp, int64_t currentTime) {
    // Debounce focus changes to avoid transient events
    if (currentTime - lastFocusChangeTime_ < config_.focusDebounceMs) {
        return false;
    }
    
    // Avoid duplicate events for the same app
    if (newActiveApp == lastActiveApp_ && !newActiveApp.empty()) {
        return false;
    }
    
    return true;
}

void FocusIdleWatcher::EmitFocusIdleEvent(const FocusIdleEvent& event) {
    std::string jsonStr = CreateEventJson(event);
    
    if (tsfn_) {
        tsfn_.NonBlockingCall([jsonStr](Napi::Env env, Napi::Function callback) {
            callback.Call({Napi::String::New(env, jsonStr)});
        });
    }
}

void FocusIdleWatcher::EmitHeartbeat() {
    std::time_t now = std::time(nullptr);
    
    std::ostringstream json;
    json << "{"
         << "\"module\": \"focus-idle-watch\","
         << "\"eventType\": \"heartbeat\","
         << "\"timestamp\": " << (now * 1000) << ","
         << "\"ts\": " << (now * 1000) << ","
         << "\"count\": " << counter_.load() << ","
         << "\"source\": \"native\""
         << "}";
    
    std::string jsonStr = json.str();
    
    if (tsfn_) {
        tsfn_.NonBlockingCall([jsonStr](Napi::Env env, Napi::Function callback) {
            callback.Call({Napi::String::New(env, jsonStr)});
        });
    }
}

std::string FocusIdleWatcher::CreateEventJson(const FocusIdleEvent& event) {
    std::ostringstream json;
    json << "{"
         << "\"module\": \"focus-idle-watch\","
         << "\"eventType\": \"" << EscapeJson(event.eventType) << "\","
         << "\"timestamp\": " << event.timestamp << ","
         << "\"details\": {";
    
    bool hasDetails = false;
    
    if (event.details.idleDuration > 0) {
        json << "\"idleDuration\": " << event.details.idleDuration;
        hasDetails = true;
    }
    
    if (!event.details.activeApp.empty()) {
        if (hasDetails) json << ",";
        json << "\"activeApp\": \"" << EscapeJson(event.details.activeApp) << "\"";
        hasDetails = true;
    }
    
    if (!event.details.windowTitle.empty()) {
        if (hasDetails) json << ",";
        json << "\"windowTitle\": \"" << EscapeJson(event.details.windowTitle) << "\"";
        hasDetails = true;
    }
    
    if (!event.details.reason.empty()) {
        if (hasDetails) json << ",";
        json << "\"reason\": \"" << EscapeJson(event.details.reason) << "\"";
        hasDetails = true;
    }
    
    json << "},"
         << "\"ts\": " << event.timestamp << ","
         << "\"count\": " << counter_.load() << ","
         << "\"source\": \"native\""
         << "}";
    
    return json.str();
}

int64_t FocusIdleWatcher::GetCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

std::string FocusIdleWatcher::GenerateEventId() {
    return "focus_idle_" + std::to_string(GetCurrentTimestamp()) + "_" + std::to_string(counter_.load());
}

std::string FocusIdleWatcher::EscapeJson(const std::string& str) {
    std::string escaped;
    for (char c : str) {
        switch (c) {
            case '"': escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default: escaped += c; break;
        }
    }
    return escaped;
}

#ifdef _WIN32
// Windows implementation
bool FocusIdleWatcher::initializeWindows() {
    printf("[FocusIdleWatcher] Windows focus/idle detection initialized\n");
    return true;
}

void FocusIdleWatcher::cleanupWindows() {
    // No cleanup needed for Windows APIs we're using
}

int64_t FocusIdleWatcher::GetWindowsIdleTime() {
    LASTINPUTINFO lii = { sizeof(LASTINPUTINFO) };
    if (!GetLastInputInfo(&lii)) {
        return 0;
    }
    
    DWORD currentTick = GetTickCount();
    return (currentTick - lii.dwTime);
}

bool FocusIdleWatcher::IsSystemIdle(int thresholdSec) {
    int64_t idleTimeMs = GetWindowsIdleTime();
    return (idleTimeMs >= (thresholdSec * 1000));
}

std::string FocusIdleWatcher::GetForegroundWindowInfo(HWND& outHwnd, std::string& outTitle) {
    outHwnd = GetForegroundWindow();
    if (!outHwnd) {
        return "";
    }
    
    outTitle = GetWindowTitleSafe(outHwnd);
    return GetProcessNameFromWindow(outHwnd);
}

bool FocusIdleWatcher::IsExamWindowFocused() {
    if (!examHwnd_) {
        return false; // Can't determine without window handle
    }
    
    HWND foregroundWindow = GetForegroundWindow();
    return (foregroundWindow == examHwnd_);
}

std::string FocusIdleWatcher::GetProcessNameFromWindow(HWND hwnd) {
    DWORD processId;
    GetWindowThreadProcessId(hwnd, &processId);
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) {
        return "Unknown";
    }
    
    char processName[MAX_PATH];
    if (GetModuleBaseName(hProcess, nullptr, processName, sizeof(processName))) {
        CloseHandle(hProcess);
        return std::string(processName);
    }
    
    CloseHandle(hProcess);
    return "Unknown";
}

std::string FocusIdleWatcher::GetWindowTitleSafe(HWND hwnd) {
    char windowTitle[512];
    if (GetWindowText(hwnd, windowTitle, sizeof(windowTitle)) > 0) {
        return std::string(windowTitle);
    }
    return "";
}

bool FocusIdleWatcher::IsExamWindowMinimized() {
    if (!examHwnd_) {
        return false; // Can't determine without window handle
    }
    
    return IsIconic(examHwnd_);
}

#elif __APPLE__
// macOS implementation
bool FocusIdleWatcher::initializeMacOS() {
    hasAccessibilityPermission_ = CheckAccessibilityPermission();
    
    if (!hasAccessibilityPermission_) {
        printf("[FocusIdleWatcher] Accessibility permission required for full focus detection\n");
        RequestAccessibilityPermission();
        EmitPermissionWarning();
        return false;  // Will have limited functionality
    }
    
    printf("[FocusIdleWatcher] macOS focus/idle detection initialized with Accessibility\n");
    return true;
}

void FocusIdleWatcher::cleanupMacOS() {
    // No cleanup needed for APIs we're using
}

bool FocusIdleWatcher::CheckAccessibilityPermission() {
    NSDictionary* options = @{(__bridge NSString*)kAXTrustedCheckOptionPrompt: @NO};
    return AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)options);
}

void FocusIdleWatcher::RequestAccessibilityPermission() {
    printf("[FocusIdleWatcher] Requesting Accessibility permission...\n");
    printf("Please enable Accessibility permission for this app in System Preferences > Security & Privacy > Privacy > Accessibility\n");
    
    NSDictionary* options = @{(__bridge NSString*)kAXTrustedCheckOptionPrompt: @YES};
    AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)options);
}

void FocusIdleWatcher::EmitPermissionWarning() {
    int64_t currentTime = GetCurrentTimestamp();
    
    std::ostringstream json;
    json << "{"
         << "\"module\": \"focus-idle-watch\","
         << "\"eventType\": \"permission-missing\","
         << "\"timestamp\": " << currentTime << ","
         << "\"details\": {"
         << "\"permission\": \"Accessibility\""
         << "},"
         << "\"ts\": " << currentTime << ","
         << "\"count\": " << counter_.load() << ","
         << "\"source\": \"native\""
         << "}";
    
    std::string jsonStr = json.str();
    
    if (tsfn_) {
        tsfn_.NonBlockingCall([jsonStr](Napi::Env env, Napi::Function callback) {
            callback.Call({Napi::String::New(env, jsonStr)});
        });
    }
}

double FocusIdleWatcher::GetMacOSIdleTime() {
    // Use Quartz to get idle time
    CFTimeInterval idleTime = CGEventSourceSecondsSinceLastEventType(
        kCGEventSourceStateCombinedSessionState, 
        kCGAnyInputEventType
    );
    return idleTime;
}

bool FocusIdleWatcher::IsSystemIdle(int thresholdSec) {
    double idleTimeSec = GetMacOSIdleTime();
    return (idleTimeSec >= thresholdSec);
}

std::string FocusIdleWatcher::GetFrontmostApplication(std::string& outTitle) {
    @autoreleasepool {
        NSWorkspace* workspace = [NSWorkspace sharedWorkspace];
        NSRunningApplication* frontApp = [workspace frontmostApplication];
        
        if (frontApp) {
            // Get the app name (prefer localizedName, fallback to bundleIdentifier)
            NSString* appName = [frontApp localizedName];
            if (!appName || [appName length] == 0) {
                appName = [frontApp bundleIdentifier];
            }
            outTitle = std::string([appName UTF8String] ?: "Unknown App");
            
            // Return bundle identifier for precise identification
            NSString* bundleId = [frontApp bundleIdentifier];
            return std::string([bundleId UTF8String] ?: "unknown.app");
        }
    }
    
    // If we can't get frontmost app info, try to provide some basic info
    return "unknown.app";
}

bool FocusIdleWatcher::IsExamWindowFocused() {
    @autoreleasepool {
        NSWorkspace* workspace = [NSWorkspace sharedWorkspace];
        NSRunningApplication* frontApp = [workspace frontmostApplication];
        NSRunningApplication* currentApp = [NSRunningApplication currentApplication];
        
        if (frontApp && currentApp) {
            bool isFocused = [[frontApp bundleIdentifier] isEqualToString:[currentApp bundleIdentifier]];
            // Additional check: ensure the frontmost app PID matches our current PID
            return isFocused && ([frontApp processIdentifier] == [currentApp processIdentifier]);
        }
    }
    
    // If we can't determine, assume not focused to be safe
    return false;
}

bool FocusIdleWatcher::IsExamWindowMinimized() {
    // Use CGWindowList to check if exam window is visible
    CFArrayRef windowList = GetWindowList();
    if (!windowList) {
        return false;
    }
    
    bool isVisible = FindExamWindowInList(windowList);
    CFRelease(windowList);
    
    // If window is not visible in the list, it might be minimized
    return !isVisible;
}

CFArrayRef FocusIdleWatcher::GetWindowList() {
    return CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly, kCGNullWindowID);
}

bool FocusIdleWatcher::FindExamWindowInList(CFArrayRef windowList) {
    if (!windowList) return false;
    
    CFIndex count = CFArrayGetCount(windowList);
    for (CFIndex i = 0; i < count; i++) {
        CFDictionaryRef windowInfo = (CFDictionaryRef)CFArrayGetValueAtIndex(windowList, i);
        
        // Check if this window belongs to our process
        CFNumberRef pidRef = (CFNumberRef)CFDictionaryGetValue(windowInfo, kCGWindowOwnerPID);
        if (pidRef) {
            int windowPid;
            CFNumberGetValue(pidRef, kCFNumberIntType, &windowPid);
            
            if (windowPid == getpid()) {
                // This is our window and it's on screen
                return true;
            }
        }
    }
    
    return false;
}
#endif

FocusIdleEvent FocusIdleWatcher::GetCurrentStatus() {
    FocusIdleEvent status;
    status.timestamp = GetCurrentTimestamp();
    
    // Get real-time focus and idle status instead of cached values
    bool currentFocus = IsExamWindowFocused();
    bool currentIdle = IsSystemIdle(config_.idleThresholdSec);
    
    if (currentIdle) {
        status.eventType = "idle-start";
        if (isIdle_) {
            status.details.idleDuration = static_cast<int>((status.timestamp - idleStartTime_) / 1000);
        }
    } else if (currentFocus) {
        // Electron app has focus - this is the normal/good state
        status.eventType = "heartbeat";
        status.details.reason = "exam-app-focused";
    } else {
        // Electron app lost focus - this is the concerning state
        status.eventType = "focus-lost";
        // Get current frontmost app info
        std::string activeApp, windowTitle;
        activeApp = GetFrontmostApplication(windowTitle);
        status.details.activeApp = activeApp;
        status.details.windowTitle = windowTitle;
        status.details.reason = "user-switched-app";
    }
    
    return status;
}