#ifndef PERMISSION_CHECKER_H
#define PERMISSION_CHECKER_H

#include <napi.h>

#ifdef __APPLE__
#include <ApplicationServices/ApplicationServices.h>
#include <IOKit/hid/IOHIDManager.h>
#endif

/**
 * Centralized permission checking for all macOS permissions
 */
class PermissionChecker {
public:
    // Check specific permissions
    static bool CheckAccessibilityPermission();
    static bool CheckScreenRecordingPermission();
    static bool CheckInputMonitoringPermission();
    static bool CheckRegistryPermission();
    static bool CheckDeviceEnumerationPermission();
    static bool CheckProcessAccessPermission();
    static bool CheckClipboardPermission();

    // Request specific permissions
    static bool RequestAccessibilityPermission();
    static bool RequestScreenRecordingPermission();
    static bool RequestInputMonitoringPermission();
    static bool RequestRegistryPermission();
    static bool RequestDeviceEnumerationPermission();
    static bool RequestProcessAccessPermission();
    static bool RequestClipboardPermission();
    
    // Helper methods
    static void OpenSystemPreferences(const std::string& pane);
};

// N-API wrapper functions
Napi::Value CheckAccessibilityPermission(const Napi::CallbackInfo& info);
Napi::Value CheckScreenRecordingPermission(const Napi::CallbackInfo& info);
Napi::Value CheckInputMonitoringPermission(const Napi::CallbackInfo& info);
Napi::Value CheckRegistryPermission(const Napi::CallbackInfo& info);
Napi::Value CheckDeviceEnumerationPermission(const Napi::CallbackInfo& info);
Napi::Value CheckProcessAccessPermission(const Napi::CallbackInfo& info);
Napi::Value CheckClipboardPermission(const Napi::CallbackInfo& info);

Napi::Value RequestAccessibilityPermission(const Napi::CallbackInfo& info);
Napi::Value RequestScreenRecordingPermission(const Napi::CallbackInfo& info);
Napi::Value RequestInputMonitoringPermission(const Napi::CallbackInfo& info);
Napi::Value RequestRegistryPermission(const Napi::CallbackInfo& info);
Napi::Value RequestDeviceEnumerationPermission(const Napi::CallbackInfo& info);
Napi::Value RequestProcessAccessPermission(const Napi::CallbackInfo& info);
Napi::Value RequestClipboardPermission(const Napi::CallbackInfo& info);

#endif // PERMISSION_CHECKER_H