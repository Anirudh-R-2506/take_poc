#ifndef NOTIFICATION_BLOCKER_H
#define NOTIFICATION_BLOCKER_H

#include <napi.h>
#include <string>
#include <atomic>
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
#include <shellapi.h>
#include <shlobj.h>
#pragma comment(lib, "shell32.lib")
#elif __APPLE__
#endif
enum class NotificationBlockState {
    DISABLED = 0,
    ENABLED = 1,
    ERROR_STATE = 2
};

struct NotificationEvent {
    std::string eventType;
    std::string reason;
    bool isBlocked;
    bool userModified;
    int64_t timestamp;
    std::string originalState;

    NotificationEvent() : isBlocked(false), userModified(false), timestamp(0) {}
};

class NotificationBlocker {
public:
    NotificationBlocker();
    ~NotificationBlocker();

    bool EnableNotificationBlocking();
    bool DisableNotificationBlocking();
    bool ResetToOriginalState();
    bool IsNotificationBlocked();
    NotificationEvent GetCurrentState();
    bool DetectUserModification();
    void SetExamMode(bool examActive);
    bool IsExamActive() const;
    std::string GetLastError() const;

private:
#ifdef _WIN32
    bool SetFocusAssistState(int state);
    int GetFocusAssistState();
    bool BackupOriginalState();
    bool RestoreOriginalState();
    bool ReadFocusAssistRegistry(DWORD& value);
    bool WriteFocusAssistRegistry(DWORD value);
    bool CheckNotificationState();
    int originalFocusAssistState_;
    bool hasBackup_;
    static const std::wstring FOCUS_ASSIST_REGISTRY_PATH;
    static const std::wstring FOCUS_ASSIST_VALUE_NAME;
    static const std::wstring FOCUS_ASSIST_BACKUP_PATH;
    static const std::wstring FOCUS_ASSIST_BACKUP_VALUE;
#elif __APPLE__
    bool macosNotificationState_;
#endif

    std::atomic<bool> examActive_;
    std::atomic<bool> notificationsBlocked_;
    std::atomic<bool> userModifiedState_;
    NotificationBlockState currentState_;
    std::string lastError_;
    std::chrono::steady_clock::time_point lastProgrammaticChange_;
    int lastKnownState_;
    static const int GRACE_PERIOD_MS = 5000; // 5 seconds grace period after programmatic changes
    int64_t lastStateChangeTime_;

    int64_t GetCurrentTimestamp();
    std::string StateToString(NotificationBlockState state);
    void UpdateState(NotificationBlockState newState, const std::string& reason);
    void EmitStateChangeEvent(const std::string& eventType, const std::string& reason);
};

#endif // NOTIFICATION_BLOCKER_H