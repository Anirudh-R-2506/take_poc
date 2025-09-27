#include "FocusIdleWatcher.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "psapi.lib")
#elif __APPLE__
#include <CoreGraphics/CoreGraphics.h>
#include <IOKit/IOKitLib.h>
#include <ApplicationServices/ApplicationServices.h>
#endif

FocusIdleWatcher::FocusIdleWatcher()
    : running_(false), counter_(0), intervalMs_(1000),
      isIdle_(false), hasFocus_(true), isMinimized_(false),
      lastActivityTime_(0), idleStartTime_(0), lastFocusChangeTime_(0),
      examWindowHandle_(nullptr)
{

    // Set default configuration
    config_.enableIdleDetection = true;
    config_.enableFocusDetection = true;
    config_.enableMinimizeDetection = true;
    config_.idleThresholdSec = 30;
    config_.focusDebounceMs = 1000;
    config_.examAppTitle = "";

#ifdef _WIN32
    examHwnd_ = nullptr;
    initializeWindows();
#elif __APPLE__
    hasAccessibilityPermission_ = false;
    initializeMacOS();
#endif
}

FocusIdleWatcher::~FocusIdleWatcher()
{
    Stop();
#ifdef _WIN32
    cleanupWindows();
#elif __APPLE__
    cleanupMacOS();
#endif
}

void FocusIdleWatcher::Start(Napi::Function callback, int intervalMs)
{
    if (running_)
        return;

    intervalMs_ = intervalMs;
    running_ = true;

    // Store callback using ThreadSafeFunction for proper threading
    tsfn_ = Napi::ThreadSafeFunction::New(
        callback.Env(),
        callback,
        "FocusIdleWatcher",
        0,
        1);

    // Start worker thread
    worker_thread_ = std::thread(&FocusIdleWatcher::WatcherLoop, this);

    std::cout << "[FocusIdleWatcher] Started with interval " << intervalMs << "ms" << std::endl;
}

void FocusIdleWatcher::Stop()
{
    if (!running_)
        return;

    running_ = false;

    if (worker_thread_.joinable())
    {
        worker_thread_.join();
    }

    // Release thread-safe function
    if (tsfn_)
    {
        tsfn_.Release();
    }

    std::cout << "[FocusIdleWatcher] Stopped" << std::endl;
}

bool FocusIdleWatcher::IsRunning() const
{
    return running_;
}

void FocusIdleWatcher::SetConfig(const FocusIdleConfig &config)
{
    config_ = config;
    std::cout << "[FocusIdleWatcher] Configuration updated" << std::endl;
}

void FocusIdleWatcher::SetExamWindowHandle(void *handle)
{
    examWindowHandle_ = handle;
#ifdef _WIN32
    examHwnd_ = static_cast<HWND>(handle);
#endif
    std::cout << "[FocusIdleWatcher] Exam window handle set" << std::endl;
}

FocusIdleEvent FocusIdleWatcher::GetCurrentStatus()
{
    FocusIdleEvent event;
    auto now = GetCurrentTimestamp();

    try
    {
        event.timestamp = now;

        // Check idle state
        if (config_.enableIdleDetection)
        {
            CheckIdleState();
        }

        // Check focus state
        if (config_.enableFocusDetection)
        {
            CheckFocusState();
        }

        // Check minimize state
        if (config_.enableMinimizeDetection)
        {
            CheckMinimizeState();
        }

        // Determine event type based on state changes
        if (isIdle_ && !lastIdleState_)
        {
            event.eventType = "idle-start";
            event.details.idleDuration = (now - lastActivityTime_) / 1000;
            idleStartTime_ = now;
        }
        else if (!isIdle_ && lastIdleState_)
        {
            event.eventType = "idle-end";
            event.details.idleDuration = idleStartTime_ > 0 ? (now - idleStartTime_) / 1000 : 0;
        }
        else if (!hasFocus_ && lastFocusState_)
        {
            event.eventType = "focus-lost";
            event.details.activeApp = lastActiveApp_;
            event.details.reason = "user-switched-app";
        }
        else if (hasFocus_ && !lastFocusState_)
        {
            event.eventType = "focus-gained";
            event.details.activeApp = config_.examAppTitle;
            event.details.reason = "user-returned";
        }
        else if (isMinimized_ && !lastMinimizeState_)
        {
            event.eventType = "minimized";
            event.details.reason = "window-minimized";
        }
        else if (!isMinimized_ && lastMinimizeState_)
        {
            event.eventType = "restored";
            event.details.reason = "window-restored";
        }
        else
        {
            event.eventType = "heartbeat";
        }

        // Update last states
        lastIdleState_ = isIdle_;
        lastFocusState_ = hasFocus_;
        lastMinimizeState_ = isMinimized_;
    }
    catch (const std::exception &e)
    {
        event.eventType = "error";
        event.details.reason = e.what();
        std::cerr << "[FocusIdleWatcher] Error in GetCurrentStatus: " << e.what() << std::endl;
    }

    return event;
}

void FocusIdleWatcher::WatcherLoop()
{
    auto lastHeartbeat = std::chrono::steady_clock::now();

    while (running_)
    {
        try
        {
            FocusIdleEvent event = GetCurrentStatus();
            counter_++;

            // Emit significant events immediately, heartbeat every 30 seconds
            auto now = std::chrono::steady_clock::now();
            bool shouldEmit = (event.eventType != "heartbeat") ||
                              (std::chrono::duration_cast<std::chrono::seconds>(now - lastHeartbeat).count() >= 30);

            if (shouldEmit)
            {
                EmitFocusIdleEvent(event);
                if (event.eventType != "heartbeat")
                {
                    lastHeartbeat = now;
                }
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "[FocusIdleWatcher] Error in worker loop: " << e.what() << std::endl;
        }

        // Sleep for the specified interval
        std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs_));
    }
}

void FocusIdleWatcher::CheckIdleState()
{
    int64_t currentTime = GetCurrentTimestamp();

#ifdef _WIN32
    int64_t idleTime = GetWindowsIdleTime();
#elif __APPLE__
    double idleTimeSec = GetMacOSIdleTime();
    int64_t idleTime = static_cast<int64_t>(idleTimeSec * 1000);
#else
    int64_t idleTime = 0; // Fallback
#endif

    bool currentlyIdle = idleTime >= (config_.idleThresholdSec * 1000);

    if (currentlyIdle != isIdle_)
    {
        if (!currentlyIdle)
        {
            lastActivityTime_ = currentTime;
        }
        isIdle_ = currentlyIdle;
    }
}

void FocusIdleWatcher::CheckFocusState()
{
    bool currentlyFocused = false;
    std::string activeApp;

#ifdef _WIN32
    currentlyFocused = IsExamWindowFocused();
    if (!currentlyFocused)
    {
        HWND foregroundHwnd;
        std::string windowTitle;
        activeApp = GetForegroundWindowInfo(foregroundHwnd, windowTitle);
    }
#elif __APPLE__
    if (CheckAccessibilityPermission())
    {
        std::string windowTitle;
        activeApp = GetFrontmostApplication(windowTitle);
        currentlyFocused = IsExamWindowFocused();
    }
    else
    {
        // Fallback without accessibility permission
        currentlyFocused = true; // Assume focused to avoid false alarms
    }
#endif

    int64_t currentTime = GetCurrentTimestamp();

    if (ShouldEmitFocusChange(activeApp, currentTime))
    {
        hasFocus_ = currentlyFocused;
        lastActiveApp_ = activeApp;
        lastFocusChangeTime_ = currentTime;
    }
}

void FocusIdleWatcher::CheckMinimizeState()
{
#ifdef _WIN32
    bool currentlyMinimized = IsExamWindowMinimized();
#elif __APPLE__
    bool currentlyMinimized = IsExamWindowMinimized();
#else
    bool currentlyMinimized = false;
#endif

    isMinimized_ = currentlyMinimized;
}

bool FocusIdleWatcher::ShouldEmitFocusChange(const std::string &newActiveApp, int64_t currentTime)
{
    // Apply debouncing to prevent rapid focus change events
    return (currentTime - lastFocusChangeTime_) >= config_.focusDebounceMs;
}

void FocusIdleWatcher::EmitFocusIdleEvent(const FocusIdleEvent &event)
{
    if (!tsfn_)
        return;

    std::string jsonData = CreateEventJson(event);

    // Use ThreadSafeFunction to safely call JavaScript from worker thread
    auto callback = [](Napi::Env env, Napi::Function jsCallback, std::string *data)
    {
        jsCallback.Call({Napi::String::New(env, *data)});
        delete data;
    };

    napi_status status = tsfn_.BlockingCall(new std::string(jsonData), callback);
    if (status != napi_ok)
    {
        std::cerr << "[FocusIdleWatcher] Error calling JavaScript callback" << std::endl;
    }
}

std::string FocusIdleWatcher::CreateEventJson(const FocusIdleEvent &event)
{
    std::stringstream ss;

    ss << "{";
    ss << "\"module\":\"focus-idle-watch\",";
    ss << "\"eventType\":\"" << EscapeJson(event.eventType) << "\",";
    ss << "\"timestamp\":" << event.timestamp << ",";
    ss << "\"ts\":" << event.timestamp << ",";
    ss << "\"count\":" << counter_ << ",";
    ss << "\"source\":\"native\",";

    ss << "\"details\":{";
    bool hasDetails = false;

    if (event.details.idleDuration > 0)
    {
        ss << "\"idleDuration\":" << event.details.idleDuration;
        hasDetails = true;
    }

    if (!event.details.activeApp.empty())
    {
        if (hasDetails)
            ss << ",";
        ss << "\"activeApp\":\"" << EscapeJson(event.details.activeApp) << "\"";
        hasDetails = true;
    }

    if (!event.details.windowTitle.empty())
    {
        if (hasDetails)
            ss << ",";
        ss << "\"windowTitle\":\"" << EscapeJson(event.details.windowTitle) << "\"";
        hasDetails = true;
    }

    if (!event.details.reason.empty())
    {
        if (hasDetails)
            ss << ",";
        ss << "\"reason\":\"" << EscapeJson(event.details.reason) << "\"";
        hasDetails = true;
    }

    ss << "}";
    ss << "}";

    return ss.str();
}

std::string FocusIdleWatcher::EscapeJson(const std::string &str)
{
    std::string escaped;
    for (char c : str)
    {
        switch (c)
        {
        case '"':
            escaped += "\\\"";
            break;
        case '\\':
            escaped += "\\\\";
            break;
        case '\b':
            escaped += "\\b";
            break;
        case '\f':
            escaped += "\\f";
            break;
        case '\n':
            escaped += "\\n";
            break;
        case '\r':
            escaped += "\\r";
            break;
        case '\t':
            escaped += "\\t";
            break;
        default:
            escaped += c;
            break;
        }
    }
    return escaped;
}

int64_t FocusIdleWatcher::GetCurrentTimestamp()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

#ifdef _WIN32

bool FocusIdleWatcher::initializeWindows()
{
    return true; // No special initialization needed for Windows
}

void FocusIdleWatcher::cleanupWindows()
{
    // Cleanup if needed
}

int64_t FocusIdleWatcher::GetWindowsIdleTime()
{
    LASTINPUTINFO lii;
    lii.cbSize = sizeof(LASTINPUTINFO);

    if (GetLastInputInfo(&lii))
    {
        // Use GetTickCount64 for 64-bit tick count to avoid overflow (Windows Vista+)
        ULONGLONG currentTickCount = GetTickCount64();
        ULONGLONG idleTime = currentTickCount - lii.dwTime;
        return static_cast<int64_t>(idleTime);
    }

    return 0;
}

std::string FocusIdleWatcher::GetForegroundWindowInfo(HWND &outHwnd, std::string &outTitle)
{
    outHwnd = GetForegroundWindow();
    if (!outHwnd)
        return "";

    // Get window title
    outTitle = GetWindowTitleSafe(outHwnd);

    // Get process name
    return GetProcessNameFromWindow(outHwnd);
}

bool FocusIdleWatcher::IsExamWindowFocused()
{
    HWND foregroundWindow = GetForegroundWindow();

    // If no specific exam window handle is set, check for Electron/Morpheus app
    if (!examHwnd_)
    {
        if (!foregroundWindow)
            return false;

        std::string windowTitle = GetWindowTitleSafe(foregroundWindow);
        std::string processName = GetProcessNameFromWindow(foregroundWindow);

        // Check if it's our Electron app
        bool isMorpheusApp = (processName.find("Electron") != std::string::npos ||
                              processName.find("morpheus") != std::string::npos ||
                              windowTitle.find("Morpheus") != std::string::npos ||
                              windowTitle.find("Proctoring") != std::string::npos);

        return isMorpheusApp;
    }

    // Check if the foreground window is our exam window or a child of it
    HWND currentWindow = foregroundWindow;
    while (currentWindow)
    {
        if (currentWindow == examHwnd_)
        {
            return true;
        }
        currentWindow = GetParent(currentWindow);
    }

    return false;
}

std::string FocusIdleWatcher::GetProcessNameFromWindow(HWND hwnd)
{
    DWORD processId;
    GetWindowThreadProcessId(hwnd, &processId);

    // Use minimal required permissions for security (no PROCESS_VM_READ)
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!hProcess)
    {
        // Fallback for older processes
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    }
    if (!hProcess)
        return "";

    // Use Unicode API with extended path support
    wchar_t processNameW[32768]; // Extended path support
    DWORD size = sizeof(processNameW) / sizeof(wchar_t);

    if (QueryFullProcessImageNameW(hProcess, 0, processNameW, &size))
    {
        CloseHandle(hProcess);

        // Convert Unicode to UTF-8
        std::wstring fullPathW(processNameW);
        std::string fullPath;
        if (!fullPathW.empty())
        {
            int utf8Size = WideCharToMultiByte(CP_UTF8, 0, fullPathW.c_str(), -1, nullptr, 0, nullptr, nullptr);
            if (utf8Size > 0)
            {
                fullPath.resize(utf8Size - 1);
                WideCharToMultiByte(CP_UTF8, 0, fullPathW.c_str(), -1, &fullPath[0], utf8Size, nullptr, nullptr);
            }
        }

        // Extract just the filename from full path
        size_t lastSlash = fullPath.find_last_of("\\/");
        return (lastSlash != std::string::npos) ? fullPath.substr(lastSlash + 1) : fullPath;
    }

    CloseHandle(hProcess);
    return "";
}

std::string FocusIdleWatcher::GetWindowTitleSafe(HWND hwnd)
{
    // Use Unicode API for better international support
    int titleLength = GetWindowTextLengthW(hwnd);
    if (titleLength == 0)
        return "";

    std::vector<wchar_t> titleBufferW(titleLength + 1);
    GetWindowTextW(hwnd, titleBufferW.data(), titleLength + 1);

    // Convert Unicode to UTF-8
    std::wstring titleW(titleBufferW.data());
    if (titleW.empty())
        return "";

    int utf8Size = WideCharToMultiByte(CP_UTF8, 0, titleW.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (utf8Size <= 0)
        return "";

    std::string title(utf8Size - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, titleW.c_str(), -1, &title[0], utf8Size, nullptr, nullptr);

    return title;
}

bool FocusIdleWatcher::IsExamWindowMinimized()
{
    if (!examHwnd_)
        return false;

    return IsIconic(examHwnd_) != 0;
}

#elif __APPLE__

bool FocusIdleWatcher::initializeMacOS()
{
    hasAccessibilityPermission_ = CheckAccessibilityPermission();
    if (!hasAccessibilityPermission_)
    {
        std::cout << "[FocusIdleWatcher] Warning: Accessibility permission not granted, focus detection may be limited" << std::endl;
    }
    return true;
}

void FocusIdleWatcher::cleanupMacOS()
{
    // Cleanup if needed
}

bool FocusIdleWatcher::CheckAccessibilityPermission()
{
    return AXIsProcessTrusted();
}

double FocusIdleWatcher::GetMacOSIdleTime()
{
    CFTimeInterval idleTime = CGEventSourceSecondsSinceLastEventType(
        kCGEventSourceStateHIDSystemState, kCGAnyInputEventType);
    return idleTime;
}

std::string FocusIdleWatcher::GetFrontmostApplication(std::string &outTitle)
{
    NSWorkspace *workspace = [NSWorkspace sharedWorkspace];
    NSRunningApplication *frontApp = [workspace frontmostApplication];

    if (frontApp)
    {
        NSString *appName = [frontApp localizedName];
        if (appName)
        {
            return std::string([appName UTF8String]);
        }
    }

    return "";
}

bool FocusIdleWatcher::IsExamWindowFocused()
{
    if (config_.examAppTitle.empty())
        return true; // Default to focused if no app title set

    std::string windowTitle;
    std::string frontmostApp = GetFrontmostApplication(windowTitle);

    // Check if the frontmost application matches our exam app
    return frontmostApp.find(config_.examAppTitle) != std::string::npos;
}

bool FocusIdleWatcher::IsExamWindowMinimized()
{
    // This is more complex on macOS and would require additional Accessibility API calls
    // For now, return false as a safe default
    return false;
}

void FocusIdleWatcher::StartRealtimeWindowMonitor()
{
    if (realtimeMonitorRunning_.load())
    {
        return; // Already running
    }

    if (!config_.enableRealtimeWindowSwitching)
    {
        std::cout << "[FocusIdleWatcher] Real-time window monitoring disabled by config" << std::endl;
        return;
    }

    std::cout << "[FocusIdleWatcher] Starting real-time window monitoring with " << config_.realtimePollIntervalMs << "ms interval" << std::endl;

    realtimeMonitorRunning_.store(true);
    realtimeMonitorThread_ = std::thread([this]()
                                         { RealtimeMonitorLoop(); });
}

void FocusIdleWatcher::StopRealtimeWindowMonitor()
{
    if (!realtimeMonitorRunning_.load())
    {
        return; // Not running
    }

    realtimeMonitorRunning_.store(false);

    if (realtimeMonitorThread_.joinable())
    {
        realtimeMonitorThread_.join();
    }

    std::cout << "[FocusIdleWatcher] Real-time window monitoring stopped" << std::endl;
}

void FocusIdleWatcher::RealtimeMonitorLoop()
{
    std::cout << "[FocusIdleWatcher] Real-time monitor loop started" << std::endl;

    while (realtimeMonitorRunning_.load())
    {
        try
        {
            std::string windowTitle;
            std::string newActiveApp = GetFrontmostApplication(windowTitle);

            // Detect window switches
            if (newActiveApp != currentActiveApp_ || windowTitle != currentWindowTitle_)
            {
                ProcessWindowSwitch(newActiveApp, windowTitle);
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "[FocusIdleWatcher] Error in realtime monitor: " << e.what() << std::endl;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(config_.realtimePollIntervalMs));
    }

    std::cout << "[FocusIdleWatcher] Real-time monitor loop ended" << std::endl;
}

void FocusIdleWatcher::ProcessWindowSwitch(const std::string &appName, const std::string &windowTitle)
{
    currentActiveApp_ = appName;
    currentWindowTitle_ = windowTitle;

    // Emit window switch event
    FocusIdleEvent event;
    event.eventType = "window-switch";
    event.timestamp = GetCurrentTimestamp();
    event.details.activeApp = appName;
    event.details.windowTitle = windowTitle;
    event.details.reason = "realtime-window-switch";

    EmitFocusIdleEvent(event);
}

FocusIdleEvent FocusIdleWatcher::GetRealtimeFocusStatus()
{
    FocusIdleEvent status;
    status.timestamp = GetCurrentTimestamp();

    // Get real-time focus status with enhanced detection
    bool currentFocus = IsExamWindowFocused();

    if (currentFocus)
    {
        status.eventType = "realtime-focused";
        status.details.reason = "exam-app-focused";
    }
    else
    {
        status.eventType = "realtime-focus-lost";
        status.details.activeApp = currentActiveApp_;
        status.details.windowTitle = currentWindowTitle_;
        status.details.reason = "real-time-violation";
    }

    return status;
}

#endif