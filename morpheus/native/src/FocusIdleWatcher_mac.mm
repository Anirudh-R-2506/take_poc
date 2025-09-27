#include "FocusIdleWatcher.h"
#include <sstream>
#include <ctime>
#include <chrono>
#include <algorithm>

FocusIdleWatcher::FocusIdleWatcher()
    : running_(false), counter_(0), intervalMs_(1000), isIdle_(false),
      hasFocus_(true), isMinimized_(false), lastActivityTime_(0),
      idleStartTime_(0), lastFocusChangeTime_(0), examWindowHandle_(nullptr),
      realtimeMonitorRunning_(false), lastWindowSwitchTime_(0), hasWindowSwitchEvents_(false)
#ifdef _WIN32
    , examHwnd_(nullptr)
#elif __APPLE__
    , hasAccessibilityPermission_(false)
#endif
{
    lastActivityTime_ = GetCurrentTimestamp();
}

FocusIdleWatcher::~FocusIdleWatcher() {
    StopRealtimeWindowMonitor();
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

    StopRealtimeWindowMonitor();
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
    
    // Start real-time monitoring if enabled
    if (config_.enableRealtimeWindowSwitching) {
        StartRealtimeWindowMonitor();
    }

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
            NSString* frontBundleId = [frontApp bundleIdentifier];
            NSString* currentBundleId = [currentApp bundleIdentifier];
            pid_t frontPid = [frontApp processIdentifier];
            pid_t currentPid = [currentApp processIdentifier];

            printf("[FocusIdleWatcher] Focus check: Front=%s (PID:%d), Current=%s (PID:%d)\n",
                   [frontBundleId UTF8String] ?: "unknown",
                   frontPid,
                   [currentBundleId UTF8String] ?: "unknown",
                   currentPid);

            // Primary check: PID comparison is most reliable
            if (frontPid == currentPid) {
                printf("[FocusIdleWatcher] ✓ PID match - app is focused\n");
                return true;
            }

            // Backup check: bundle identifier comparison
            if (frontBundleId && currentBundleId) {
                // Direct match
                if ([frontBundleId isEqualToString:currentBundleId]) {
                    printf("[FocusIdleWatcher] ✓ Bundle ID match - app is focused\n");
                    return true;
                }

                // Check for Electron app patterns
                if ([frontBundleId containsString:@"electron"] ||
                    [frontBundleId isEqualToString:@"com.github.Electron"] ||
                    [currentBundleId containsString:@"electron"] ||
                    [currentBundleId isEqualToString:@"com.github.Electron"]) {
                    // If either is Electron-related, check if they're both Electron apps
                    bool frontIsElectron = [frontBundleId containsString:@"electron"] || [frontBundleId isEqualToString:@"com.github.Electron"];
                    bool currentIsElectron = [currentBundleId containsString:@"electron"] || [currentBundleId isEqualToString:@"com.github.Electron"];

                    printf("[FocusIdleWatcher] Electron check: Front=%s, Current=%s\n",
                           frontIsElectron ? "true" : "false",
                           currentIsElectron ? "true" : "false");

                    if (frontIsElectron && currentIsElectron) {
                        printf("[FocusIdleWatcher] ✓ Both are Electron apps - app is focused\n");
                        return true;
                    }
                }
            }
        }
    }

    printf("[FocusIdleWatcher] ✗ App focus check failed - not focused\n");
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

// Enhanced real-time detection methods
void FocusIdleWatcher::StartRealtimeWindowMonitor() {
    if (realtimeMonitorRunning_.load()) {
        return; // Already running
    }

    if (!config_.enableRealtimeWindowSwitching) {
        printf("[FocusIdleWatcher] Real-time window monitoring disabled by config\n");
        return;
    }

    printf("[FocusIdleWatcher] Starting real-time window monitoring with %dms interval\n", config_.realtimePollIntervalMs);

    realtimeMonitorRunning_.store(true);
    realtimeMonitorThread_ = std::thread([this]() {
        RealtimeMonitorLoop();
    });
}

void FocusIdleWatcher::StopRealtimeWindowMonitor() {
    if (!realtimeMonitorRunning_.load()) {
        return; // Not running
    }

    realtimeMonitorRunning_.store(false);

    if (realtimeMonitorThread_.joinable()) {
        realtimeMonitorThread_.join();
    }

    printf("[FocusIdleWatcher] Real-time window monitoring stopped\n");
}

void FocusIdleWatcher::RealtimeMonitorLoop() {
    printf("[FocusIdleWatcher] Real-time monitor loop started\n");

    while (realtimeMonitorRunning_.load()) {
        try {
            std::string windowTitle;
            std::string newActiveApp = GetFrontmostApplication(windowTitle);

            // Detect window switches
            if (newActiveApp != currentActiveApp_ || windowTitle != currentWindowTitle_) {
                ProcessWindowSwitch(newActiveApp, windowTitle);
            }

            // Detect partial window switches (quick app switches)
            if (DetectPartialWindowSwitch()) {
                // Emit immediate violation for rapid switching behavior
                FocusIdleEvent event("rapid-window-switching", GetCurrentTimestamp());
                event.details.activeApp = currentActiveApp_;
                event.details.windowTitle = currentWindowTitle_;
                event.details.reason = "rapid-switching-detected";
                EmitFocusIdleEvent(event);
            }

        } catch (const std::exception& e) {
            printf("[FocusIdleWatcher] Error in real-time monitor loop: %s\n", e.what());
        }

        // High-frequency polling for real-time detection
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.realtimePollIntervalMs));
    }

    printf("[FocusIdleWatcher] Real-time monitor loop ended\n");
}

void FocusIdleWatcher::ProcessWindowSwitch(const std::string& newApp, const std::string& newTitle) {
    int64_t currentTime = GetCurrentTimestamp();
    std::string previousApp = currentActiveApp_;

    // Update current state
    currentActiveApp_ = newApp;
    currentWindowTitle_ = newTitle;
    lastWindowSwitchTime_ = currentTime;
    hasWindowSwitchEvents_ = true;

    // Check if switching away from exam app
    @autoreleasepool {
        NSRunningApplication* currentApp = [NSRunningApplication currentApplication];
        NSString* currentBundleId = [currentApp bundleIdentifier];
        std::string examAppId = std::string([currentBundleId UTF8String] ?: "unknown.app");

        bool switchedAwayFromExam = (previousApp == examAppId && newApp != examAppId);
        bool switchedToExam = (previousApp != examAppId && newApp == examAppId);

        if (switchedAwayFromExam) {
            printf("[FocusIdleWatcher] ⚠️  Window switch detected: %s -> %s\n", previousApp.c_str(), newApp.c_str());

            FocusIdleEvent event("window-switch-violation", currentTime);
            event.details.activeApp = newApp;
            event.details.windowTitle = newTitle;
            event.details.reason = "switched-away-from-exam";
            EmitFocusIdleEvent(event);

            EmitWindowSwitchEvent(previousApp, newApp);
        } else if (switchedToExam) {
            printf("[FocusIdleWatcher] ✓ Returned to exam app: %s -> %s\n", previousApp.c_str(), newApp.c_str());

            FocusIdleEvent event("focus-gained", currentTime);
            event.details.reason = "returned-to-exam";
            EmitFocusIdleEvent(event);
        } else if (newApp != examAppId) {
            printf("[FocusIdleWatcher] 🔄 Window switch (non-exam): %s -> %s\n", previousApp.c_str(), newApp.c_str());

            FocusIdleEvent event("window-switch-ongoing", currentTime);
            event.details.activeApp = newApp;
            event.details.windowTitle = newTitle;
            event.details.reason = "continued-non-exam-usage";
            EmitFocusIdleEvent(event);
        }
    }
}

bool FocusIdleWatcher::DetectPartialWindowSwitch() {
    // Detect rapid window switching patterns (potential cheating behavior)
    int64_t currentTime = GetCurrentTimestamp();
    int64_t timeSinceLastSwitch = currentTime - lastWindowSwitchTime_;

    // If multiple switches happen within 2 seconds, flag as suspicious
    if (hasWindowSwitchEvents_ && timeSinceLastSwitch < 2000) {
        static int rapidSwitchCount = 0;
        rapidSwitchCount++;

        if (rapidSwitchCount >= 3) {
            printf("[FocusIdleWatcher] 🚨 Rapid window switching detected (%d switches in 2s)\n", rapidSwitchCount);
            rapidSwitchCount = 0; // Reset counter
            return true;
        }
    } else {
        // Reset counter if no recent activity
        static int rapidSwitchCount = 0;
        rapidSwitchCount = 0;
    }

    return false;
}

void FocusIdleWatcher::EmitWindowSwitchEvent(const std::string& fromApp, const std::string& toApp) {
    int64_t currentTime = GetCurrentTimestamp();

    std::ostringstream json;
    json << "{"
         << "\"module\": \"focus-idle-watch\","
         << "\"eventType\": \"window-switch-detected\","
         << "\"timestamp\": " << currentTime << ","
         << "\"details\": {"
         << "\"fromApp\": \"" << EscapeJson(fromApp) << "\","
         << "\"toApp\": \"" << EscapeJson(toApp) << "\","
         << "\"reason\": \"real-time-detection\""
         << "},"
         << "\"ts\": " << currentTime << ","
         << "\"count\": " << counter_.load() << ","
         << "\"source\": \"realtime-native\""
         << "}";

    std::string jsonStr = json.str();

    if (tsfn_) {
        tsfn_.NonBlockingCall([jsonStr](Napi::Env env, Napi::Function callback) {
            callback.Call({Napi::String::New(env, jsonStr)});
        });
    }
}

FocusIdleEvent FocusIdleWatcher::GetRealtimeFocusStatus() {
    FocusIdleEvent status;
    status.timestamp = GetCurrentTimestamp();

    // Get real-time focus status with enhanced detection
    bool currentFocus = IsExamWindowFocused();

    if (currentFocus) {
        status.eventType = "realtime-focused";
        status.details.reason = "exam-app-focused";
    } else {
        status.eventType = "realtime-focus-lost";
        status.details.activeApp = currentActiveApp_;
        status.details.windowTitle = currentWindowTitle_;
        status.details.reason = "real-time-violation";
    }

    return status;
}