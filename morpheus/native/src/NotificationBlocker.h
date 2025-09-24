#ifndef NOTIFICATION_BLOCKER_H
#define NOTIFICATION_BLOCKER_H

#include <napi.h>
#include <string>
#include <atomic>

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#pragma comment(lib, "shell32.lib")
#elif __APPLE__
// macOS will use @sindresorhus/do-not-disturb from JavaScript side
#endif

// Notification blocking state
enum class NotificationBlockState {
    DISABLED = 0,       // Notifications enabled (normal state)
    ENABLED = 1,        // Notifications blocked (during exam)
    ERROR = 2           // Error state
};

struct NotificationEvent {
    std::string eventType;      // "notification-blocked", "notification-enabled", "state-changed", "violation"
    std::string reason;         // Reason for the event
    bool isBlocked;             // Current blocking state
    bool userModified;          // Whether user manually changed settings
    int64_t timestamp;          // Event timestamp
    std::string originalState;  // Original Focus Assist state before exam

    NotificationEvent() : isBlocked(false), userModified(false), timestamp(0) {}
};

class NotificationBlocker {
public:
    NotificationBlocker();
    ~NotificationBlocker();

    // Main control methods
    bool EnableNotificationBlocking();
    bool DisableNotificationBlocking();
    bool ResetToOriginalState();
    bool IsNotificationBlocked();

    // State monitoring
    NotificationEvent GetCurrentState();
    bool DetectUserModification();

    // Configuration
    void SetExamMode(bool examActive);
    bool IsExamActive() const;

    // Error handling
    std::string GetLastError() const;

private:
#ifdef _WIN32
    // Windows-specific Focus Assist control
    bool SetFocusAssistState(int state); // 0=Off, 1=Priority, 2=Alarms
    int GetFocusAssistState();
    bool BackupOriginalState();
    bool RestoreOriginalState();

    // Registry manipulation for Focus Assist
    bool ReadFocusAssistRegistry(DWORD& value);
    bool WriteFocusAssistRegistry(DWORD value);

    // Windows notification state detection
    bool CheckNotificationState();

    // Storage for original state
    int originalFocusAssistState_;
    bool hasBackup_;

    // Registry paths
    static const std::string FOCUS_ASSIST_REGISTRY_PATH;
    static const std::string FOCUS_ASSIST_VALUE_NAME;
#elif __APPLE__
    // macOS will be handled in JavaScript using do-not-disturb package
    bool macosNotificationState_;
#endif

    // Cross-platform state
    std::atomic<bool> examActive_;
    std::atomic<bool> notificationsBlocked_;
    std::atomic<bool> userModifiedState_;
    NotificationBlockState currentState_;
    std::string lastError_;
    int64_t lastStateChangeTime_;

    // Helper methods
    int64_t GetCurrentTimestamp();
    std::string StateToString(NotificationBlockState state);
    void UpdateState(NotificationBlockState newState, const std::string& reason);
    void EmitStateChangeEvent(const std::string& eventType, const std::string& reason);
};

#endif // NOTIFICATION_BLOCKER_H