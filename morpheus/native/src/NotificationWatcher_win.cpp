#include "NotificationWatcher.h"
#include <iostream>
#include <sstream>
#include <chrono>
#include <thread>
#include <unordered_set>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <dwmapi.h>
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "dwmapi.lib")
#endif

NotificationWatcher::NotificationWatcher() 
    : running_(false), counter_(0), intervalMs_(1000),
      minEventInterval_(std::chrono::milliseconds(500)) {
    
    // Set default configuration matching Mac implementation
    config_.redactBody = false;
    config_.redactTitle = false;
    config_.rateLimit = 10;  // Max notifications per source per minute
    config_.minEventInterval = 500;  // Minimum ms between events
    
    std::cout << "[NotificationWatcher] Windows notification watcher initialized" << std::endl;
}

NotificationWatcher::~NotificationWatcher() {
    Stop();
}

void NotificationWatcher::Start(Napi::Function callback, int intervalMs) {
    if (running_) return;
    
    intervalMs_ = intervalMs;
    running_ = true;
    
    // Store callback
    callback_ = Napi::Persistent(callback);
    
    // Start worker thread
    workerThread_ = std::thread(&NotificationWatcher::workerLoop, this);
    
    std::cout << "[NotificationWatcher] Started with interval " << intervalMs << "ms" << std::endl;
}

void NotificationWatcher::Stop() {
    if (!running_) return;
    
    running_ = false;
    
    if (workerThread_.joinable()) {
        workerThread_.join();
    }
    
    // Release callback
    callback_.Reset();
    
    std::cout << "[NotificationWatcher] Stopped" << std::endl;
}

bool NotificationWatcher::IsRunning() const {
    return running_;
}

void NotificationWatcher::SetConfig(const NotificationConfig& config) {
    config_ = config;
    std::cout << "[NotificationWatcher] Configuration updated" << std::endl;
}

std::vector<NotificationInfo> NotificationWatcher::GetCurrentNotifications() {
    std::vector<NotificationInfo> notifications;
    
    try {
#ifdef _WIN32
        // Windows 10/11 notification detection using window enumeration
        EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&notifications));
        
        // Add metadata to notifications
        for (auto& notif : notifications) {
            auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count();
            
            notif.timestamp = now;
            notif.confidence = 0.8;  // Default confidence for window-based detection
            
            // Generate notification ID
            notif.notificationId = "notif_" + std::to_string(now) + "_" + std::to_string(rand() % 1000000);
            
            // Apply privacy settings
            applyPrivacySettings(notif);
        }
#endif
    } catch (const std::exception& e) {
        std::cerr << "[NotificationWatcher] Error getting current notifications: " << e.what() << std::endl;
    }
    
    return notifications;
}

std::string NotificationWatcher::notificationToJson(const NotificationInfo& notification) {
    std::stringstream ss;
    
    ss << "{";
    ss << "\"module\":\"notification-watch\",";
    ss << "\"eventType\":\"" << escapeJson(notification.eventType) << "\",";
    ss << "\"sourceApp\":\"" << escapeJson(notification.sourceApp) << "\",";
    ss << "\"pid\":" << notification.pid << ",";
    
    if (!notification.title.empty()) {
        ss << "\"title\":\"" << escapeJson(notification.title) << "\",";
    } else {
        ss << "\"title\":null,";
    }
    
    if (!notification.body.empty()) {
        ss << "\"body\":\"" << escapeJson(notification.body) << "\",";
    } else {
        ss << "\"body\":null,";
    }
    
    ss << "\"notificationId\":\"" << escapeJson(notification.notificationId) << "\",";
    ss << "\"timestamp\":" << notification.timestamp << ",";
    ss << "\"confidence\":" << notification.confidence << ",";
    ss << "\"ts\":" << notification.timestamp << ",";
    ss << "\"count\":" << counter_ << ",";
    ss << "\"source\":\"native\"";
    ss << "}";
    
    return ss.str();
}

std::string NotificationWatcher::createHeartbeatJson() {
    std::stringstream ss;
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    ss << "{";
    ss << "\"module\":\"notification-watch\",";
    ss << "\"eventType\":\"heartbeat\",";
    ss << "\"ts\":" << timestamp << ",";
    ss << "\"count\":" << counter_ << ",";
    ss << "\"source\":\"native\"";
    ss << "}";
    
    return ss.str();
}

void NotificationWatcher::workerLoop() {
    auto lastHeartbeat = std::chrono::steady_clock::now();
    auto lastNotificationCheck = std::chrono::steady_clock::now();
    
    while (running_) {
        try {
            auto now = std::chrono::steady_clock::now();
            
            // Check for notifications periodically
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - lastNotificationCheck).count() >= intervalMs_) {
                std::vector<NotificationInfo> currentNotifications = GetCurrentNotifications();
                
                for (const auto& notif : currentNotifications) {
                    // Rate limiting and deduplication
                    std::string fingerprint = createNotificationFingerprint(notif);
                    if (shouldEmitNotification(fingerprint)) {
                        counter_++;
                        
                        if (callback_) {
                            std::string jsonData = notificationToJson(notif);
                            callback_.Call({
                                Napi::String::New(callback_.Env(), jsonData)
                            });
                        }
                    }
                }
                
                lastNotificationCheck = now;
            }
            
            // Send heartbeat every 30 seconds
            if (std::chrono::duration_cast<std::chrono::seconds>(now - lastHeartbeat).count() >= 30) {
                if (callback_) {
                    std::string heartbeatData = createHeartbeatJson();
                    callback_.Call({
                        Napi::String::New(callback_.Env(), heartbeatData)
                    });
                }
                lastHeartbeat = now;
            }
            
        } catch (const std::exception& e) {
            std::cerr << "[NotificationWatcher] Error in worker loop: " << e.what() << std::endl;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

#ifdef _WIN32
BOOL CALLBACK NotificationWatcher::EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    std::vector<NotificationInfo>* notifications = reinterpret_cast<std::vector<NotificationInfo>*>(lParam);
    
    // Get window information
    RECT rect;
    if (!GetWindowRect(hwnd, &rect)) {
        return TRUE;  // Continue enumeration
    }
    
    // Get window title
    char windowTitle[256];
    int titleLength = GetWindowTextA(hwnd, windowTitle, sizeof(windowTitle));
    if (titleLength == 0) {
        return TRUE;  // Continue enumeration
    }
    
    // Get window class
    char className[256];
    if (!GetClassNameA(hwnd, className, sizeof(className))) {
        return TRUE;  // Continue enumeration
    }
    
    // Check if this looks like a notification window
    if (isNotificationWindow(hwnd, windowTitle, className, rect)) {
        NotificationInfo notif;
        notif.eventType = "notification-arrived";
        notif.title = std::string(windowTitle);
        notif.body = "";  // Body extraction would require more complex UI Automation
        
        // Get process information
        DWORD processId;
        GetWindowThreadProcessId(hwnd, &processId);
        notif.pid = processId;
        
        // Get process name
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
        if (hProcess) {
            char processName[MAX_PATH];
            DWORD size = sizeof(processName);
            if (QueryFullProcessImageName(hProcess, 0, processName, &size)) {
                std::string fullPath(processName);
                size_t lastSlash = fullPath.find_last_of("\\");
                if (lastSlash != std::string::npos) {
                    notif.sourceApp = fullPath.substr(lastSlash + 1);
                } else {
                    notif.sourceApp = fullPath;
                }
            }
            CloseHandle(hProcess);
        }
        
        if (notif.sourceApp.empty()) {
            notif.sourceApp = "Unknown";
        }
        
        notifications->push_back(notif);
    }
    
    return TRUE;  // Continue enumeration
}

bool NotificationWatcher::isNotificationWindow(HWND hwnd, const std::string& title, 
                                             const std::string& className, const RECT& rect) {
    // Skip invisible windows
    if (!IsWindowVisible(hwnd)) {
        return false;
    }
    
    // Calculate window dimensions
    int width = rect.right - rect.left;
    int height = rect.bottom - rect.top;
    
    // Windows 10/11 notification patterns
    std::string lowerClassName = className;
    std::transform(lowerClassName.begin(), lowerClassName.end(), lowerClassName.begin(), ::tolower);
    
    // Known notification window classes
    static const std::vector<std::string> notificationClasses = {
        "windows.ui.core.corewindow",     // Windows 10/11 notifications
        "tooltips_class32",               // Tooltip notifications
        "notifyiconwnd",                 // System tray notifications
        "shell_traywnd",                 // Taskbar notifications
        "windows.ui.popups.popuproot"    // Modern app popups
    };
    
    for (const auto& notifClass : notificationClasses) {
        if (lowerClassName.find(notifClass) != std::string::npos) {
            // Check size constraints (typical notification dimensions)
            if (width >= 250 && width <= 600 && height >= 50 && height <= 300) {
                return true;
            }
        }
    }
    
    // Check window position (notifications usually appear in top-right or bottom-right)
    RECT screenRect;
    SystemParametersInfo(SPI_GETWORKAREA, 0, &screenRect, 0);
    
    bool isInNotificationArea = (
        // Top-right corner
        (rect.left > screenRect.right - 600 && rect.top < screenRect.top + 200) ||
        // Bottom-right corner  
        (rect.left > screenRect.right - 600 && rect.bottom > screenRect.bottom - 200)
    );
    
    if (isInNotificationArea && width >= 200 && width <= 500 && height >= 50 && height <= 200) {
        return true;
    }
    
    return false;
}
#endif

void NotificationWatcher::applyPrivacySettings(NotificationInfo& notification) {
    if (config_.redactTitle && !notification.title.empty()) {
        notification.title = "[REDACTED]";
    }
    
    if (config_.redactBody && !notification.body.empty()) {
        notification.body = "[REDACTED]";
    }
    
    // Sanitize content
    sanitizeText(notification.title);
    sanitizeText(notification.body);
}

void NotificationWatcher::sanitizeText(std::string& text) {
    // Remove control characters
    text.erase(std::remove_if(text.begin(), text.end(), 
        [](char c) { return c < 32 && c != '\t' && c != '\n' && c != '\r'; }), text.end());
    
    // Limit length
    if (text.length() > 500) {
        text = text.substr(0, 500);
    }
}

std::string NotificationWatcher::createNotificationFingerprint(const NotificationInfo& notification) {
    std::stringstream ss;
    ss << notification.sourceApp << "|" 
       << notification.title.substr(0, 50) << "|"
       << notification.body.substr(0, 50);
    return ss.str();
}

bool NotificationWatcher::shouldEmitNotification(const std::string& fingerprint) {
    auto now = std::chrono::steady_clock::now();
    
    // Clean up old fingerprints (older than 30 seconds)
    auto it = recentFingerprints_.begin();
    while (it != recentFingerprints_.end()) {
        if (std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count() > 30) {
            it = recentFingerprints_.erase(it);
        } else {
            ++it;
        }
    }
    
    // Check rate limiting
    auto found = recentFingerprints_.find(fingerprint);
    if (found != recentFingerprints_.end()) {
        // Check minimum interval
        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - found->second) < minEventInterval_) {
            return false;  // Too soon, don't emit
        }
    }
    
    // Update fingerprint timestamp
    recentFingerprints_[fingerprint] = now;
    return true;
}

std::string NotificationWatcher::escapeJson(const std::string& str) {
    std::string escaped;
    escaped.reserve(str.length());
    
    for (char c : str) {
        switch (c) {
            case '"': escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\b': escaped += "\\b"; break;
            case '\f': escaped += "\\f"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default: escaped += c; break;
        }
    }
    
    return escaped;
}

// N-API wrapper functions (matching Mac implementation)
Napi::Value StartNotificationWatcher(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsFunction()) {
        Napi::TypeError::New(env, "Callback function expected").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    // This would need to be managed globally like in the Mac implementation
    // For now, this is a placeholder that matches the Mac API
    return Napi::Boolean::New(env, true);
}

Napi::Value StopNotificationWatcher(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    // This would stop the global instance
    return env.Null();
}

Napi::Value GetCurrentNotifications(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    try {
        NotificationWatcher watcher;
        auto notifications = watcher.GetCurrentNotifications();
        Napi::Array result = Napi::Array::New(env, notifications.size());
        
        for (size_t i = 0; i < notifications.size(); i++) {
            Napi::Object notificationObj = Napi::Object::New(env);
            notificationObj.Set("eventType", Napi::String::New(env, notifications[i].eventType));
            notificationObj.Set("sourceApp", Napi::String::New(env, notifications[i].sourceApp));
            notificationObj.Set("pid", Napi::Number::New(env, notifications[i].pid));
            notificationObj.Set("title", Napi::String::New(env, notifications[i].title));
            notificationObj.Set("body", Napi::String::New(env, notifications[i].body));
            notificationObj.Set("notificationId", Napi::String::New(env, notifications[i].notificationId));
            notificationObj.Set("timestamp", Napi::Number::New(env, notifications[i].timestamp));
            notificationObj.Set("confidence", Napi::Number::New(env, notifications[i].confidence));
            
            result[i] = notificationObj;
        }
        
        return result;
    } catch (const std::exception& e) {
        Napi::Error::New(env, std::string("Error getting notifications: ") + e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}