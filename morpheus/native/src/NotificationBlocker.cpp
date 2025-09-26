#include "NotificationBlocker.h"
#include <iostream>
#include <chrono>
#include <sstream>

#ifdef _WIN32
#include <winreg.h>
// Focus Assist registry constants - Use reliable Windows 10/11 paths
const std::wstring NotificationBlocker::FOCUS_ASSIST_REGISTRY_PATH = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings";
const std::wstring NotificationBlocker::FOCUS_ASSIST_VALUE_NAME = L"NOC_GLOBAL_SETTING_TOASTS_ENABLED";
const std::wstring NotificationBlocker::FOCUS_ASSIST_BACKUP_PATH = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings";
const std::wstring NotificationBlocker::FOCUS_ASSIST_BACKUP_VALUE = L"NOC_GLOBAL_SETTING_TOASTS_ENABLED_BACKUP";
#endif

NotificationBlocker::NotificationBlocker()
    : examActive_(false), notificationsBlocked_(false), userModifiedState_(false),
      currentState_(NotificationBlockState::DISABLED), lastStateChangeTime_(0),
      lastProgrammaticChange_(std::chrono::steady_clock::now()), lastKnownState_(-1)
#ifdef _WIN32
      ,
      originalFocusAssistState_(0), hasBackup_(false)
#elif __APPLE__
      ,
      macosNotificationState_(false)
#endif
{
    std::cout << "[NotificationBlocker] Initialized" << std::endl;
}

NotificationBlocker::~NotificationBlocker()
{
    // Ensure we restore original state on destruction
    if (examActive_.load())
    {
        DisableNotificationBlocking();
    }
}

bool NotificationBlocker::EnableNotificationBlocking()
{
    std::cout << "[NotificationBlocker] Enabling notification blocking..." << std::endl;

    try
    {
#ifdef _WIN32
        // Backup current state before changing
        if (!BackupOriginalState())
        {
            lastError_ = "Failed to backup original Focus Assist state";
            return false;
        }

        // Set Focus Assist to "Alarms only" mode (state 2)
        if (!SetFocusAssistState(2))
        {
            lastError_ = "Failed to enable Focus Assist";
            return false;
        }

        // Track our programmatic change to prevent false violation detection
        lastProgrammaticChange_ = std::chrono::steady_clock::now();
        lastKnownState_ = 2;

        notificationsBlocked_ = true;
        UpdateState(NotificationBlockState::ENABLED, "exam-started");
        std::cout << "[NotificationBlocker] Windows Focus Assist enabled successfully" << std::endl;
        return true;

#elif __APPLE__
        // macOS notification blocking will be handled in JavaScript worker
        // using @sindresorhus/do-not-disturb package
        notificationsBlocked_ = true;
        UpdateState(NotificationBlockState::ENABLED, "exam-started");
        std::cout << "[NotificationBlocker] macOS notification blocking enabled (handled by worker)" << std::endl;
        return true;
#endif
    }
    catch (const std::exception &e)
    {
        lastError_ = "Exception in EnableNotificationBlocking: " + std::string(e.what());
        std::cerr << "[NotificationBlocker] " << lastError_ << std::endl;
        return false;
    }

    return false;
}

bool NotificationBlocker::DisableNotificationBlocking()
{
    std::cout << "[NotificationBlocker] Disabling notification blocking..." << std::endl;

    try
    {
#ifdef _WIN32
        // Restore original Focus Assist state
        if (!RestoreOriginalState())
        {
            lastError_ = "Failed to restore original Focus Assist state";
            return false;
        }

        // Track our programmatic change to prevent false violation detection
        lastProgrammaticChange_ = std::chrono::steady_clock::now();
        lastKnownState_ = originalFocusAssistState_;

        notificationsBlocked_ = false;
        UpdateState(NotificationBlockState::DISABLED, "exam-ended");
        std::cout << "[NotificationBlocker] Windows Focus Assist restored successfully" << std::endl;
        return true;

#elif __APPLE__
        // macOS notification restoration will be handled in JavaScript worker
        notificationsBlocked_ = false;
        UpdateState(NotificationBlockState::DISABLED, "exam-ended");
        std::cout << "[NotificationBlocker] macOS notification blocking disabled (handled by worker)" << std::endl;
        return true;
#endif
    }
    catch (const std::exception &e)
    {
        lastError_ = "Exception in DisableNotificationBlocking: " + std::string(e.what());
        std::cerr << "[NotificationBlocker] " << lastError_ << std::endl;
        return false;
    }

    return false;
}

bool NotificationBlocker::ResetToOriginalState()
{
    std::cout << "[NotificationBlocker] Resetting to original state..." << std::endl;

    try
    {
#ifdef _WIN32
        // Force restore to backed up original state regardless of exam mode
        if (!hasBackup_)
        {
            lastError_ = "No original state backup available";
            std::cout << "[NotificationBlocker] Warning: No backup available, setting to default (disabled)" << std::endl;
            // Set to default disabled state (0)
            if (!SetFocusAssistState(0))
            {
                lastError_ = "Failed to reset Focus Assist to default state";
                return false;
            }
            // Track our programmatic change
            lastProgrammaticChange_ = std::chrono::steady_clock::now();
            lastKnownState_ = 0;
        }
        else
        {
            // Restore to original backed up state
            if (!SetFocusAssistState(originalFocusAssistState_))
            {
                lastError_ = "Failed to restore Focus Assist to original state: " + std::to_string(originalFocusAssistState_);
                return false;
            }
            // Track our programmatic change
            lastProgrammaticChange_ = std::chrono::steady_clock::now();
            lastKnownState_ = originalFocusAssistState_;
            std::cout << "[NotificationBlocker] Windows Focus Assist restored to original state: " << originalFocusAssistState_ << std::endl;
        }

        notificationsBlocked_ = false;
        examActive_ = false;
        userModifiedState_ = false;
        UpdateState(NotificationBlockState::DISABLED, "manual-reset");
        std::cout << "[NotificationBlocker] Windows Focus Assist reset completed successfully" << std::endl;
        return true;

#elif __APPLE__
        // macOS notification reset will be handled in JavaScript worker
        notificationsBlocked_ = false;
        examActive_ = false;
        userModifiedState_ = false;
        UpdateState(NotificationBlockState::DISABLED, "manual-reset");
        std::cout << "[NotificationBlocker] macOS notification blocking reset (handled by worker)" << std::endl;
        return true;
#endif
    }
    catch (const std::exception &e)
    {
        lastError_ = "Exception in ResetToOriginalState: " + std::string(e.what());
        std::cerr << "[NotificationBlocker] " << lastError_ << std::endl;
        return false;
    }

    return false;
}

bool NotificationBlocker::IsNotificationBlocked()
{
    return notificationsBlocked_.load();
}

NotificationEvent NotificationBlocker::GetCurrentState()
{
    NotificationEvent event;
    event.timestamp = GetCurrentTimestamp();
    event.isBlocked = notificationsBlocked_.load();
    event.userModified = userModifiedState_.load();

#ifdef _WIN32
    // Check if user manually changed Focus Assist state
    int currentState = GetFocusAssistState();

    // Check if this change happened within our grace period after a programmatic change
    auto now = std::chrono::steady_clock::now();
    auto timeSinceLastChange = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastProgrammaticChange_).count();
    bool withinGracePeriod = timeSinceLastChange < GRACE_PERIOD_MS;

    if (examActive_.load() && currentState != 2)
    {
        // Only report as violation if not within grace period and state actually changed from our expected state
        if (!withinGracePeriod && lastKnownState_ == 2)
        {
            // User manually disabled Focus Assist during exam
            event.eventType = "violation";
            event.reason = "user-disabled-focus-assist";
            event.userModified = true;
            userModifiedState_ = true;
            std::cout << "[NotificationBlocker] Genuine user violation detected: Focus Assist changed from 2 to " << currentState << std::endl;
        }
        else
        {
            // Within grace period or expected state change - not a violation
            event.eventType = "notification-settings-changed";
            event.reason = "focus-assist-transitioning";
            std::cout << "[NotificationBlocker] Focus Assist state change detected but within grace period or expected change" << std::endl;
        }
    }
    else if (notificationsBlocked_.load())
    {
        event.eventType = "notification-blocked";
        event.reason = "focus-assist-active";
    }
    else
    {
        event.eventType = "notification-enabled";
        event.reason = "focus-assist-disabled";
    }

    // Update our tracking if state actually changed
    if (currentState != lastKnownState_)
    {
        lastKnownState_ = currentState;
    }
#elif __APPLE__
    if (notificationsBlocked_.load())
    {
        event.eventType = "notification-blocked";
        event.reason = "do-not-disturb-active";
    }
    else
    {
        event.eventType = "notification-enabled";
        event.reason = "do-not-disturb-disabled";
    }
#endif

    return event;
}

bool NotificationBlocker::DetectUserModification()
{
#ifdef _WIN32
    if (!examActive_.load())
        return false;

    int currentState = GetFocusAssistState();

    // Check if this change happened within our grace period after a programmatic change
    auto now = std::chrono::steady_clock::now();
    auto timeSinceLastChange = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastProgrammaticChange_).count();
    bool withinGracePeriod = timeSinceLastChange < GRACE_PERIOD_MS;

    // During exam, Focus Assist should be in "Alarms only" mode (2)
    if (currentState != 2)
    {
        // Only consider it a user modification if not within grace period and we expected state 2
        if (!withinGracePeriod && lastKnownState_ == 2)
        {
            userModifiedState_ = true;
            std::cout << "[NotificationBlocker] User modification detected: Focus Assist changed from 2 to " << currentState << std::endl;
            return true;
        }
        else
        {
            std::cout << "[NotificationBlocker] Focus Assist change detected but within grace period - not user modification" << std::endl;
        }
    }

    // Update our tracking if state changed
    if (currentState != lastKnownState_)
    {
        lastKnownState_ = currentState;
    }
#endif
    return false;
}

void NotificationBlocker::SetExamMode(bool examActive)
{
    examActive_ = examActive;
    std::cout << "[NotificationBlocker] Exam mode: " << (examActive ? "ACTIVE" : "INACTIVE") << std::endl;
}

bool NotificationBlocker::IsExamActive() const
{
    return examActive_.load();
}

std::string NotificationBlocker::GetLastError() const
{
    return lastError_;
}

#ifdef _WIN32
bool NotificationBlocker::SetFocusAssistState(int state)
{
    try
    {
        DWORD regValue = static_cast<DWORD>(state);
        if (!WriteFocusAssistRegistry(regValue))
        {
            // Fallback: Try alternative registry path with Unicode
            HKEY hKey;
            LONG result = RegOpenKeyExW(HKEY_CURRENT_USER,
                                        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings",
                                        0, KEY_SET_VALUE, &hKey);

            if (result == ERROR_SUCCESS)
            {
                DWORD focusAssistValue = (state > 0) ? 0 : 1; // 0=disabled, 1=enabled (inverted logic for toasts)
                result = RegSetValueExW(hKey, L"NOC_GLOBAL_SETTING_TOASTS_ENABLED",
                                        0, REG_DWORD, (BYTE *)&focusAssistValue, sizeof(DWORD));
                RegCloseKey(hKey);

                if (result == ERROR_SUCCESS)
                {
                    std::cout << "[NotificationBlocker] Focus Assist state set via fallback registry" << std::endl;
                    return true;
                }
            }

            lastError_ = "Failed to set Focus Assist state via registry";
            return false;
        }

        std::cout << "[NotificationBlocker] Focus Assist state set to " << state << std::endl;
        return true;
    }
    catch (const std::exception &e)
    {
        lastError_ = "Exception setting Focus Assist state: " + std::string(e.what());
        return false;
    }
}

int NotificationBlocker::GetFocusAssistState()
{
    try
    {
        // Use SHQueryUserNotificationState API to get current state
        QUERY_USER_NOTIFICATION_STATE state;
        HRESULT hr = SHQueryUserNotificationState(&state);

        if (SUCCEEDED(hr))
        {
            switch (state)
            {
            case QUNS_NOT_PRESENT:
            case QUNS_ACCEPTS_NOTIFICATIONS:
                return 0; // Notifications enabled
            case QUNS_QUIET_TIME:
            case QUNS_BUSY:
                return 2; // Focus Assist enabled (alarms only)
            case QUNS_PRESENTATION_MODE:
                return 1; // Priority only mode
            default:
                return 0;
            }
        }

        // Fallback: Check registry
        DWORD value;
        if (ReadFocusAssistRegistry(value))
        {
            return static_cast<int>(value);
        }

        return 0; // Default to notifications enabled
    }
    catch (const std::exception &e)
    {
        std::cerr << "[NotificationBlocker] Exception getting Focus Assist state: " << e.what() << std::endl;
        return 0;
    }
}

bool NotificationBlocker::BackupOriginalState()
{
    if (hasBackup_)
        return true;

    originalFocusAssistState_ = GetFocusAssistState();
    hasBackup_ = true;

    std::cout << "[NotificationBlocker] Backed up original Focus Assist state: " << originalFocusAssistState_ << std::endl;
    return true;
}

bool NotificationBlocker::RestoreOriginalState()
{
    if (!hasBackup_)
    {
        std::cout << "[NotificationBlocker] No backup to restore" << std::endl;
        return true; // Not an error if there's nothing to restore
    }

    bool success = SetFocusAssistState(originalFocusAssistState_);
    if (success)
    {
        hasBackup_ = false;
        std::cout << "[NotificationBlocker] Restored original Focus Assist state: " << originalFocusAssistState_ << std::endl;
    }

    return success;
}

bool NotificationBlocker::ReadFocusAssistRegistry(DWORD &value)
{
    HKEY hKey;
    // Use Unicode API for 2025 compatibility
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER,
                                FOCUS_ASSIST_REGISTRY_PATH.c_str(),
                                0, KEY_READ, &hKey);

    if (result != ERROR_SUCCESS)
    {
        return false;
    }

    DWORD dataSize = sizeof(DWORD);
    result = RegQueryValueExW(hKey, FOCUS_ASSIST_VALUE_NAME.c_str(),
                              nullptr, nullptr, (BYTE *)&value, &dataSize);

    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}

bool NotificationBlocker::WriteFocusAssistRegistry(DWORD value)
{
    // First backup the original value
    DWORD originalValue;
    if (ReadFocusAssistRegistry(originalValue)) {
        // Store backup
        HKEY hBackupKey;
        LONG backupResult = RegOpenKeyExW(HKEY_CURRENT_USER,
                                          FOCUS_ASSIST_BACKUP_PATH.c_str(),
                                          0, KEY_SET_VALUE, &hBackupKey);
        if (backupResult == ERROR_SUCCESS) {
            RegSetValueExW(hBackupKey, FOCUS_ASSIST_BACKUP_VALUE.c_str(),
                          0, REG_DWORD, (BYTE *)&originalValue, sizeof(DWORD));
            RegCloseKey(hBackupKey);
        }
    }

    // Now set the new value using Unicode API
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER,
                                FOCUS_ASSIST_REGISTRY_PATH.c_str(),
                                0, KEY_SET_VALUE, &hKey);

    if (result != ERROR_SUCCESS)
    {
        return false;
    }

    result = RegSetValueExW(hKey, FOCUS_ASSIST_VALUE_NAME.c_str(),
                            0, REG_DWORD, (BYTE *)&value, sizeof(DWORD));

    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}

bool NotificationBlocker::CheckNotificationState()
{
    QUERY_USER_NOTIFICATION_STATE state;
    HRESULT hr = SHQueryUserNotificationState(&state);

    return SUCCEEDED(hr) && (state != QUNS_ACCEPTS_NOTIFICATIONS && state != QUNS_NOT_PRESENT);
}

#endif // _WIN32

int64_t NotificationBlocker::GetCurrentTimestamp()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string NotificationBlocker::StateToString(NotificationBlockState state)
{
    switch (state)
    {
    case NotificationBlockState::DISABLED:
        return "disabled";
    case NotificationBlockState::ENABLED:
        return "enabled";
    case NotificationBlockState::ERROR_STATE:
        return "error";
    default:
        return "unknown";
    }
}

void NotificationBlocker::UpdateState(NotificationBlockState newState, const std::string &reason)
{
    currentState_ = newState;
    lastStateChangeTime_ = GetCurrentTimestamp();
    std::cout << "[NotificationBlocker] State updated to " << StateToString(newState)
              << " (reason: " << reason << ")" << std::endl;
}

void NotificationBlocker::EmitStateChangeEvent(const std::string &eventType, const std::string &reason)
{
    // This would be used for callback-based notifications if needed
    std::cout << "[NotificationBlocker] Event: " << eventType << " - " << reason << std::endl;
}