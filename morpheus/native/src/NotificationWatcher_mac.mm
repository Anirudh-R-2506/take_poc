#include "NotificationWatcher.h"
#include <sstream>
#include <ctime>
#include <chrono>
#include <algorithm>
#include <random>

// Static instance for callbacks
NotificationWatcher* NotificationWatcher::instance_ = nullptr;

NotificationWatcher::NotificationWatcher() 
    : running_(false), counter_(0), intervalMs_(1000)
#ifdef _WIN32
    , eventHook_(nullptr), uiAutomation_(nullptr)
#elif __APPLE__
    , hasAccessibilityPermission_(false), runLoopObserver_(nullptr)
#endif
{
    instance_ = this;
}

NotificationWatcher::~NotificationWatcher() {
    Stop();
    instance_ = nullptr;
}

void NotificationWatcher::Start(Napi::Function callback, int intervalMs) {
    if (running_.load()) {
        return; // Already running
    }
    
    intervalMs_ = intervalMs;
    callback_ = Napi::Persistent(callback);
    
    // Create thread-safe function for callbacks
    tsfn_ = Napi::ThreadSafeFunction::New(
        callback.Env(),
        callback,
        "NotificationWatcher",
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

void NotificationWatcher::Stop() {
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

bool NotificationWatcher::IsRunning() const {
    return running_.load();
}

void NotificationWatcher::SetConfig(const NotificationConfig& config) {
    config_ = config;
}

void NotificationWatcher::WatcherLoop() {
    // Platform-specific initialization
    bool initialized = false;
#ifdef _WIN32
    initialized = initializeWindows();
#elif __APPLE__
    initialized = initializeMacOS();
#endif
    
    if (!initialized) {
        printf("[NotificationWatcher] Failed to initialize platform-specific components, using polling fallback\n");
    }
    
    auto lastHeartbeat = std::chrono::steady_clock::now();
    const auto heartbeatInterval = std::chrono::seconds(5);
    
    while (running_.load()) {
        try {
            std::vector<NotificationInfo> notifications;
            
#ifdef _WIN32
            notifications = initialized ? DetectWindowsNotifications() : PollWindowsNotifications();
#elif __APPLE__
            notifications = initialized ? DetectMacOSNotifications() : PollMacOSNotifications();
#endif
            
            // Process and emit notifications
            for (const auto& notification : notifications) {
                if (ShouldEmitEvent(notification)) {
                    EmitNotificationEvent(notification);
                }
            }
            
            // Send periodic heartbeat
            auto now = std::chrono::steady_clock::now();
            if (now - lastHeartbeat >= heartbeatInterval) {
                EmitHeartbeat();
                lastHeartbeat = now;
            }
            
            counter_++;
            
        } catch (const std::exception& e) {
            printf("[NotificationWatcher] Error in watcher loop: %s\n", e.what());
        }
        
        // Sleep for specified interval
        std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs_));
    }
}

void NotificationWatcher::EmitNotificationEvent(const NotificationInfo& notification) {
    std::string jsonStr = CreateEventJson(notification);
    
    if (tsfn_) {
        tsfn_.NonBlockingCall([jsonStr](Napi::Env env, Napi::Function callback) {
            callback.Call({Napi::String::New(env, jsonStr)});
        });
    }
}

void NotificationWatcher::EmitHeartbeat() {
    std::time_t now = std::time(nullptr);
    
    std::ostringstream json;
    json << "{"
         << "\"module\": \"notification-watch\","
         << "\"eventType\": \"heartbeat\","
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

std::string NotificationWatcher::CreateEventJson(const NotificationInfo& notification) {
    std::ostringstream json;
    json << "{"
         << "\"module\": \"notification-watch\","
         << "\"eventType\": \"" << EscapeJson(notification.eventType) << "\","
         << "\"sourceApp\": \"" << EscapeJson(notification.sourceApp) << "\","
         << "\"pid\": " << notification.pid << ","
         << "\"title\": " << (notification.title.empty() ? "null" : "\"" + EscapeJson(notification.title) + "\"") << ","
         << "\"body\": " << (notification.body.empty() ? "null" : "\"" + EscapeJson(notification.body) + "\"") << ","
         << "\"notificationId\": \"" << EscapeJson(notification.notificationId) << "\","
         << "\"timestamp\": " << notification.timestamp << ","
         << "\"confidence\": " << notification.confidence << ","
         << "\"ts\": " << notification.timestamp << ","
         << "\"count\": " << counter_.load() << ","
         << "\"source\": \"native\""
         << "}";
    
    return json.str();
}

bool NotificationWatcher::ShouldEmitEvent(const NotificationInfo& notification) {
    int64_t currentTime = GetCurrentTimestamp();
    std::string fingerprint = CreateNotificationFingerprint(notification);
    
    // Check for duplicates
    if (seenNotifications_.find(fingerprint) != seenNotifications_.end()) {
        return false;
    }
    
    // Rate limiting per source app
    auto it = lastEventTime_.find(notification.sourceApp);
    if (it != lastEventTime_.end()) {
        if (currentTime - it->second < config_.minEventInterval) {
            return false;
        }
    }
    
    // Update tracking
    seenNotifications_.insert(fingerprint);
    lastEventTime_[notification.sourceApp] = currentTime;
    
    // Clean up old entries periodically
    if (seenNotifications_.size() > 1000) {
        seenNotifications_.clear();
    }
    
    return true;
}

std::string NotificationWatcher::CreateNotificationFingerprint(const NotificationInfo& notification) {
    std::ostringstream fp;
    fp << notification.sourceApp << "|" << notification.title.substr(0, 50) << "|" 
       << notification.body.substr(0, 50);
    return fp.str();
}

std::string NotificationWatcher::GenerateNotificationId() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(100000, 999999);
    
    return "notif_" + std::to_string(GetCurrentTimestamp()) + "_" + std::to_string(dis(gen));
}

int64_t NotificationWatcher::GetCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

std::string NotificationWatcher::SanitizeText(const std::string& text) {
    std::string result = text;
    
    // Remove control characters and limit length
    result.erase(std::remove_if(result.begin(), result.end(), 
                               [](char c) { return c < 32 && c != '\t' && c != '\n'; }), 
                result.end());
    
    if (result.length() > 500) {
        result = result.substr(0, 500) + "...";
    }
    
    return result;
}

std::string NotificationWatcher::EscapeJson(const std::string& str) {
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
bool NotificationWatcher::initializeWindows() {
    // Initialize COM
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (FAILED(hr)) {
        printf("[NotificationWatcher] Failed to initialize COM: %ld\n", hr);
        return false;
    }
    
    // Initialize UI Automation
    hr = CoCreateInstance(CLSID_CUIAutomation, nullptr, CLSCTX_INPROC_SERVER,
                         IID_IUIAutomation, (void**)&uiAutomation_);
    if (FAILED(hr) || !uiAutomation_) {
        printf("[NotificationWatcher] Failed to create UI Automation instance: %ld\n", hr);
        CoUninitialize();
        return false;
    }
    
    // Set up window event hook for real-time detection
    eventHook_ = SetWinEventHook(
        EVENT_OBJECT_SHOW,          // Show events
        EVENT_OBJECT_NAMECHANGE,    // Name change events  
        nullptr,                    // All processes
        WinEventProc,              // Callback function
        0,                         // All processes
        0,                         // All threads
        WINEVENT_OUTOFCONTEXT      // Out of context
    );
    
    if (!eventHook_) {
        printf("[NotificationWatcher] Failed to set window event hook: %ld\n", GetLastError());
        uiAutomation_->Release();
        uiAutomation_ = nullptr;
        CoUninitialize();
        return false;
    }
    
    printf("[NotificationWatcher] Windows notification detection initialized\n");
    return true;
}

void NotificationWatcher::cleanupWindows() {
    if (eventHook_) {
        UnhookWinEvent(eventHook_);
        eventHook_ = nullptr;
    }
    
    if (uiAutomation_) {
        uiAutomation_->Release();
        uiAutomation_ = nullptr;
    }
    
    CoUninitialize();
}

void CALLBACK NotificationWatcher::WinEventProc(HWINEVENTHOOK hWinEventHook, DWORD event,
                                               HWND hwnd, LONG idObject, LONG idChild,
                                               DWORD dwEventThread, DWORD dwmsEventTime) {
    if (instance_ && hwnd) {
        instance_->HandleWindowEvent(hwnd, event);
    }
}

void NotificationWatcher::HandleWindowEvent(HWND hwnd, DWORD event) {
    if (!IsNotificationWindow(hwnd)) {
        return;
    }
    
    NotificationInfo notification = ExtractNotificationFromWindow(hwnd);
    if (!notification.title.empty() || !notification.body.empty()) {
        if (ShouldEmitEvent(notification)) {
            EmitNotificationEvent(notification);
        }
    }
}

std::vector<NotificationInfo> NotificationWatcher::DetectWindowsNotifications() {
    // This is called periodically - the real-time detection happens via event hooks
    return PollWindowsNotifications();
}

std::vector<NotificationInfo> NotificationWatcher::PollWindowsNotifications() {
    std::vector<NotificationInfo> notifications;
    
    // Enumerate all top-level windows
    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        NotificationWatcher* watcher = reinterpret_cast<NotificationWatcher*>(lParam);
        
        if (watcher->IsNotificationWindow(hwnd)) {
            NotificationInfo notification = watcher->ExtractNotificationFromWindow(hwnd);
            if (!notification.title.empty() || !notification.body.empty()) {
                reinterpret_cast<std::vector<NotificationInfo>*>(lParam)->push_back(notification);
            }
        }
        
        return TRUE;
    }, reinterpret_cast<LPARAM>(&notifications));
    
    return notifications;
}

bool NotificationWatcher::IsNotificationWindow(HWND hwnd) {
    if (!IsWindowVisible(hwnd)) {
        return false;
    }
    
    char className[256];
    if (GetClassName(hwnd, className, sizeof(className)) == 0) {
        return false;
    }
    
    std::string classStr(className);
    
    // Windows 10/11 Toast Notifications
    if (classStr.find("Windows.UI.Core.CoreWindow") != std::string::npos ||
        classStr.find("ToastContentHost") != std::string::npos ||
        classStr.find("NotificationArea") != std::string::npos) {
        return true;
    }
    
    // Legacy balloon notifications
    if (classStr.find("tooltips_class32") != std::string::npos) {
        return true;
    }
    
    // Check window size and position (notifications are typically small and positioned in corners)
    RECT rect;
    if (GetWindowRect(hwnd, &rect)) {
        int width = rect.right - rect.left;
        int height = rect.bottom - rect.top;
        
        // Typical notification dimensions
        if (width > 250 && width < 500 && height > 60 && height < 200) {
            // Check if positioned like a notification (top-right corner typically)
            RECT desktopRect;
            GetWindowRect(GetDesktopWindow(), &desktopRect);
            
            if (rect.left > desktopRect.right - 600) {  // Right side of screen
                return true;
            }
        }
    }
    
    return false;
}

NotificationInfo NotificationWatcher::ExtractNotificationFromWindow(HWND hwnd) {
    NotificationInfo notification;
    notification.eventType = "notification-arrived";
    notification.timestamp = GetCurrentTimestamp();
    notification.notificationId = GenerateNotificationId();
    
    // Get process info
    DWORD processId;
    GetWindowThreadProcessId(hwnd, &processId);
    notification.pid = static_cast<int>(processId);
    notification.sourceApp = GetWindowProcessName(hwnd);
    
    // Extract title and body
    notification.title = GetNotificationTitle(hwnd);
    
    if (!config_.redactBody) {
        notification.body = GetNotificationBody(hwnd);
    }
    
    if (config_.redactTitle) {
        notification.title = "[REDACTED]";
    }
    
    return notification;
}

std::string NotificationWatcher::GetWindowProcessName(HWND hwnd) {
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

std::string NotificationWatcher::GetNotificationTitle(HWND hwnd) {
    char windowText[1024];
    if (GetWindowText(hwnd, windowText, sizeof(windowText)) > 0) {
        return SanitizeText(std::string(windowText));
    }
    
    // Try UI Automation if available
    if (uiAutomation_) {
        IUIAutomationElement* element = nullptr;
        HRESULT hr = uiAutomation_->ElementFromHandle(hwnd, &element);
        if (SUCCEEDED(hr) && element) {
            BSTR name;
            hr = element->get_CurrentName(&name);
            if (SUCCEEDED(hr) && name) {
                std::wstring wstr(name);
                std::string result(wstr.begin(), wstr.end());
                SysFreeString(name);
                element->Release();
                return SanitizeText(result);
            }
            element->Release();
        }
    }
    
    return "";
}

std::string NotificationWatcher::GetNotificationBody(HWND hwnd) {
    // Try to get notification body using UI Automation
    if (!uiAutomation_) {
        return "";
    }
    
    IUIAutomationElement* element = nullptr;
    HRESULT hr = uiAutomation_->ElementFromHandle(hwnd, &element);
    if (FAILED(hr) || !element) {
        return "";
    }
    
    // Try to find text elements within the notification
    IUIAutomationCondition* textCondition = nullptr;
    VARIANT varProp;
    varProp.vt = VT_I4;
    varProp.lVal = UIA_TextControlTypeId;
    
    hr = uiAutomation_->CreatePropertyCondition(UIA_ControlTypePropertyId, varProp, &textCondition);
    if (SUCCEEDED(hr) && textCondition) {
        IUIAutomationElementArray* textElements = nullptr;
        hr = element->FindAll(TreeScope_Descendants, textCondition, &textElements);
        
        if (SUCCEEDED(hr) && textElements) {
            int count;
            textElements->get_Length(&count);
            
            if (count > 0) {
                IUIAutomationElement* textElement = nullptr;
                hr = textElements->GetElement(0, &textElement);
                
                if (SUCCEEDED(hr) && textElement) {
                    BSTR name;
                    hr = textElement->get_CurrentName(&name);
                    if (SUCCEEDED(hr) && name) {
                        std::wstring wstr(name);
                        std::string result(wstr.begin(), wstr.end());
                        SysFreeString(name);
                        textElement->Release();
                        textElements->Release();
                        textCondition->Release();
                        element->Release();
                        return SanitizeText(result);
                    }
                    textElement->Release();
                }
            }
            textElements->Release();
        }
        textCondition->Release();
    }
    
    element->Release();
    return "";
}

#elif __APPLE__
// macOS implementation
bool NotificationWatcher::initializeMacOS() {
    hasAccessibilityPermission_ = CheckAccessibilityPermission();
    
    if (!hasAccessibilityPermission_) {
        printf("[NotificationWatcher] Accessibility permission required for full notification detection\n");
        RequestAccessibilityPermission();
        return false;  // Will use polling fallback
    }
    
    printf("[NotificationWatcher] macOS notification detection initialized with Accessibility\n");
    return true;
}

void NotificationWatcher::cleanupMacOS() {
    if (runLoopObserver_) {
        CFRunLoopObserverInvalidate(runLoopObserver_);
        CFRelease(runLoopObserver_);
        runLoopObserver_ = nullptr;
    }
}

bool NotificationWatcher::CheckAccessibilityPermission() {
    // Check if we have accessibility permissions
    NSDictionary* options = @{(__bridge NSString*)kAXTrustedCheckOptionPrompt: @NO};
    return AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)options);
}

void NotificationWatcher::RequestAccessibilityPermission() {
    printf("[NotificationWatcher] Requesting Accessibility permission...\n");
    printf("Please enable Accessibility permission for this app in System Preferences > Security & Privacy > Privacy > Accessibility\n");
    
    // This will show the system prompt if needed
    NSDictionary* options = @{(__bridge NSString*)kAXTrustedCheckOptionPrompt: @YES};
    AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)options);
}

std::vector<NotificationInfo> NotificationWatcher::DetectMacOSNotifications() {
    std::vector<NotificationInfo> notifications;
    
    if (hasAccessibilityPermission_) {
        auto axNotifications = GetNotificationsFromAccessibility();
        notifications.insert(notifications.end(), axNotifications.begin(), axNotifications.end());
    }
    
    // Always check window list as well
    auto windowNotifications = GetNotificationsFromWindowList();
    notifications.insert(notifications.end(), windowNotifications.begin(), windowNotifications.end());
    
    return notifications;
}

std::vector<NotificationInfo> NotificationWatcher::GetNotificationsFromWindowList() {
    std::vector<NotificationInfo> notifications;
    
    CFArrayRef windowList = CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly, kCGNullWindowID);
    if (!windowList) {
        return notifications;
    }
    
    CFIndex count = CFArrayGetCount(windowList);
    for (CFIndex i = 0; i < count; i++) {
        CFDictionaryRef windowInfo = (CFDictionaryRef)CFArrayGetValueAtIndex(windowList, i);
        
        if (IsNotificationWindow(windowInfo)) {
            NotificationInfo notification = ExtractNotificationFromWindow(windowInfo);
            if (!notification.title.empty() || !notification.body.empty()) {
                notifications.push_back(notification);
            }
        }
    }
    
    CFRelease(windowList);
    return notifications;
}

bool NotificationWatcher::IsNotificationWindow(CFDictionaryRef windowInfo) {
    // Check window layer (notifications are usually on high layers)
    CFNumberRef layerRef = (CFNumberRef)CFDictionaryGetValue(windowInfo, kCGWindowLayer);
    if (layerRef) {
        int layer;
        CFNumberGetValue(layerRef, kCFNumberIntType, &layer);
        
        // Notification layers are typically > 1000
        if (layer < 1000) {
            return false;
        }
    }
    
    // Check window owner
    CFStringRef ownerName = (CFStringRef)CFDictionaryGetValue(windowInfo, kCGWindowOwnerName);
    if (ownerName) {
        char ownerBuffer[256];
        if (CFStringGetCString(ownerName, ownerBuffer, sizeof(ownerBuffer), kCFStringEncodingUTF8)) {
            std::string owner(ownerBuffer);
            
            // macOS Notification Center
            if (owner == "NotificationCenter" || owner == "UserNotificationCenter") {
                return true;
            }
        }
    }
    
    // Check window size (notifications have typical dimensions)
    CFDictionaryRef bounds = (CFDictionaryRef)CFDictionaryGetValue(windowInfo, kCGWindowBounds);
    if (bounds) {
        CFNumberRef widthRef = (CFNumberRef)CFDictionaryGetValue(bounds, CFSTR("Width"));
        CFNumberRef heightRef = (CFNumberRef)CFDictionaryGetValue(bounds, CFSTR("Height"));
        
        if (widthRef && heightRef) {
            double width, height;
            CFNumberGetValue(widthRef, kCFNumberDoubleType, &width);
            CFNumberGetValue(heightRef, kCFNumberDoubleType, &height);
            
            // Typical notification dimensions on macOS
            if (width > 300 && width < 500 && height > 60 && height < 200) {
                return true;
            }
        }
    }
    
    return false;
}

NotificationInfo NotificationWatcher::ExtractNotificationFromWindow(CFDictionaryRef windowInfo) {
    NotificationInfo notification;
    notification.eventType = "notification-arrived";
    notification.timestamp = GetCurrentTimestamp();
    notification.notificationId = GenerateNotificationId();
    
    // Get owner info
    notification.sourceApp = GetWindowOwnerName(windowInfo);
    
    CFNumberRef pidRef = (CFNumberRef)CFDictionaryGetValue(windowInfo, kCGWindowOwnerPID);
    if (pidRef) {
        CFNumberGetValue(pidRef, kCFNumberIntType, &notification.pid);
    }
    
    // Get title
    notification.title = GetWindowTitle(windowInfo);
    
    if (config_.redactTitle) {
        notification.title = "[REDACTED]";
    }
    
    // Body extraction is limited on macOS without deeper accessibility integration
    if (!config_.redactBody) {
        notification.body = "";  // Could be enhanced with more detailed accessibility queries
    }
    
    return notification;
}

std::string NotificationWatcher::GetWindowOwnerName(CFDictionaryRef windowInfo) {
    CFStringRef ownerName = (CFStringRef)CFDictionaryGetValue(windowInfo, kCGWindowOwnerName);
    if (ownerName) {
        char buffer[256];
        if (CFStringGetCString(ownerName, buffer, sizeof(buffer), kCFStringEncodingUTF8)) {
            return std::string(buffer);
        }
    }
    return "Unknown";
}

std::string NotificationWatcher::GetWindowTitle(CFDictionaryRef windowInfo) {
    CFStringRef windowName = (CFStringRef)CFDictionaryGetValue(windowInfo, kCGWindowName);
    if (windowName) {
        char buffer[512];
        if (CFStringGetCString(windowName, buffer, sizeof(buffer), kCFStringEncodingUTF8)) {
            return SanitizeText(std::string(buffer));
        }
    }
    return "";
}

std::vector<NotificationInfo> NotificationWatcher::GetNotificationsFromAccessibility() {
    // More advanced accessibility-based detection would go here
    // This is a placeholder for deeper AX integration
    return std::vector<NotificationInfo>();
}

std::vector<NotificationInfo> NotificationWatcher::PollMacOSNotifications() {
    return GetNotificationsFromWindowList();
}
#endif

// Platform-independent methods
std::vector<NotificationInfo> NotificationWatcher::GetCurrentNotifications() {
    std::vector<NotificationInfo> notifications;
    
#ifdef _WIN32
    notifications = PollWindowsNotifications();
#elif __APPLE__
    notifications = PollMacOSNotifications();
#endif
    
    return notifications;
}