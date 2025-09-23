#include "PermissionChecker.h"
#include <iostream>
#include <string>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <winuser.h>
#include <winreg.h>
#include <lmcons.h>
#include <shellapi.h>
#include <shlobj.h>
#include <comdef.h>
#include <wbemidl.h>
#include <wbemcli.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#endif

/**
 * Check if running as Administrator on Windows
 */
static bool IsRunningAsAdministrator() {
#ifdef _WIN32
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    
    // Allocate and initialize a SID of the administrators group
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        // Check whether the token is a member of the administrators group
        if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(adminGroup);
    }
    
    return isAdmin == TRUE;
#else
    return false;
#endif
}

/**
 * Check Windows Privacy Settings via Registry
 */
static bool CheckWindowsPrivacySetting(const std::string& settingPath, const std::string& valueName) {
#ifdef _WIN32
    HKEY hKey;
    DWORD dwValue = 0;
    DWORD dwSize = sizeof(DWORD);
    
    // Convert string to wide string for registry
    std::wstring wSettingPath(settingPath.begin(), settingPath.end());
    std::wstring wValueName(valueName.begin(), valueName.end());
    
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, wSettingPath.c_str(), 0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS) {
        result = RegQueryValueExW(hKey, wValueName.c_str(), NULL, NULL, (LPBYTE)&dwValue, &dwSize);
        RegCloseKey(hKey);
        
        if (result == ERROR_SUCCESS) {
            return dwValue == 1; // 1 means allowed
        }
    }
    
    // If registry key doesn't exist, assume permission is needed
    return false;
#else
    return true;
#endif
}

/**
 * Check if camera/microphone access is enabled in Windows Privacy Settings
 */
static bool CheckCameraAccess() {
#ifdef _WIN32
    // First check if global camera access is allowed
    bool globalAccess = CheckWindowsPrivacySetting(
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam",
        "Value"
    );
    
    if (!globalAccess) {
        // If global access is denied, definitely no access
        return false;
    }
    
    // Check per-app camera access for desktop apps (NonPackaged apps)
    bool desktopAppsAccess = CheckWindowsPrivacySetting(
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam\\NonPackaged",
        "Value"
    );
    
    // If desktop apps are allowed globally, consider it granted
    // Individual app permissions would need to be checked separately if needed
    if (desktopAppsAccess) {
        return true;
    }
    
    // If we can't determine the setting, assume it needs to be granted
    // This is safer than assuming it's granted
    return false;
#else
    return true;
#endif
}

/**
 * Check if microphone access is enabled in Windows Privacy Settings
 */
static bool CheckMicrophoneAccess() {
#ifdef _WIN32
    // First check if global microphone access is allowed
    bool globalAccess = CheckWindowsPrivacySetting(
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone",
        "Value"
    );
    
    if (!globalAccess) {
        // If global access is denied, definitely no access
        return false;
    }
    
    // Check per-app microphone access for desktop apps (NonPackaged apps)
    bool desktopAppsAccess = CheckWindowsPrivacySetting(
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone\\NonPackaged",
        "Value"
    );
    
    // If desktop apps are allowed globally, consider it granted
    if (desktopAppsAccess) {
        return true;
    }
    
    // If we can't determine the setting, assume it needs to be granted
    return false;
#else
    return true;
#endif
}

/**
 * Check Windows accessibility features
 */
static bool CheckWindowsAccessibility() {
#ifdef _WIN32
    // Check if high contrast is enabled (basic accessibility check)
    HIGHCONTRAST hc = {0};
    hc.cbSize = sizeof(HIGHCONTRAST);
    
    if (SystemParametersInfo(SPI_GETHIGHCONTRAST, sizeof(HIGHCONTRAST), &hc, 0)) {
        // If accessibility features are available, return true
        // This is a basic check - more sophisticated checks could be added
        return true;
    }
    
    // Check if narrator or other accessibility tools are running
    HWND narratorWnd = FindWindow(L"Narrator", NULL);
    if (narratorWnd != NULL) {
        return true;
    }
    
    // For now, assume accessibility is available on Windows
    return true;
#else
    return true;
#endif
}

/**
 * Open Windows Settings to specific page
 */
static void OpenWindowsSettings(const std::string& settingsUri) {
#ifdef _WIN32
    std::wstring wUri(settingsUri.begin(), settingsUri.end());
    ShellExecuteW(NULL, L"open", wUri.c_str(), NULL, NULL, SW_SHOWNORMAL);
#endif
}

/**
 * Check if accessibility permission is granted
 */
bool PermissionChecker::CheckAccessibilityPermission() {
#ifdef _WIN32
    return CheckWindowsAccessibility();
#else
    return true; // Assume granted on non-Windows platforms
#endif
}

/**
 * Check if screen recording permission is granted
 */
bool PermissionChecker::CheckScreenRecordingPermission() {
#ifdef _WIN32
    // On Windows 10/11, check camera privacy settings as a proxy for screen capture
    return CheckCameraAccess();
#else
    return true; // Assume granted on non-Windows platforms
#endif
}

/**
 * Check if input monitoring permission is granted
 */
bool PermissionChecker::CheckInputMonitoringPermission() {
#ifdef _WIN32
    // On Windows, check microphone access as a proxy for input monitoring
    // Also check if we can access input devices
    return CheckMicrophoneAccess();
#else
    return true; // Assume granted on non-Windows platforms
#endif
}

/**
 * Check if UAC is enabled
 */
static bool IsUACEnabled() {
#ifdef _WIN32
    HKEY hKey;
    DWORD dwValue = 0;
    DWORD dwSize = sizeof(DWORD);
    
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 
        0, KEY_READ, &hKey);
        
    if (result == ERROR_SUCCESS) {
        result = RegQueryValueExW(hKey, L"EnableLUA", NULL, NULL, (LPBYTE)&dwValue, &dwSize);
        RegCloseKey(hKey);
        
        if (result == ERROR_SUCCESS) {
            return dwValue == 1;
        }
    }
    
    return true; // Default to enabled if can't read
#else
    return false;
#endif
}

/**
 * Request accessibility permission (will prompt user)
 */
bool PermissionChecker::RequestAccessibilityPermission() {
#ifdef _WIN32
    // Check if running as admin first
    if (!IsRunningAsAdministrator()) {
        // Suggest running as administrator
        std::wstring msg = L"Administrator privileges may be required for full accessibility features. "
                          L"Would you like to open Ease of Access settings?";
        
        int result = MessageBoxW(NULL, msg.c_str(), L"Morpheus - Accessibility Permission", 
                                MB_YESNO | MB_ICONQUESTION);
        
        if (result == IDYES) {
            OpenWindowsSettings("ms-settings:easeofaccess");
        }
        return false;
    }
    
    OpenWindowsSettings("ms-settings:easeofaccess");
    return false; // User needs to manually grant
#else
    return true;
#endif
}

/**
 * Request screen recording permission (will prompt user)
 */
bool PermissionChecker::RequestScreenRecordingPermission() {
#ifdef _WIN32
    std::wstring msg = L"Screen recording requires camera permission in Windows Privacy Settings. "
                      L"Would you like to open Camera Privacy Settings?";
    
    int result = MessageBoxW(NULL, msg.c_str(), L"Morpheus - Screen Recording Permission", 
                            MB_YESNO | MB_ICONQUESTION);
    
    if (result == IDYES) {
        OpenWindowsSettings("ms-settings:privacy-webcam");
    }
    return false; // User needs to manually grant
#else
    return true;
#endif
}

/**
 * Request input monitoring permission (will prompt user)
 */
bool PermissionChecker::RequestInputMonitoringPermission() {
#ifdef _WIN32
    std::wstring msg = L"Input monitoring requires microphone permission in Windows Privacy Settings. "
                      L"Would you like to open Microphone Privacy Settings?";
    
    int result = MessageBoxW(NULL, msg.c_str(), L"Morpheus - Input Monitoring Permission", 
                            MB_YESNO | MB_ICONQUESTION);
    
    if (result == IDYES) {
        OpenWindowsSettings("ms-settings:privacy-microphone");
    }
    return false; // User needs to manually grant
#else
    return true;
#endif
}

/**
 * Open System Preferences to specific pane
 */
void PermissionChecker::OpenSystemPreferences(const std::string& pane) {
#ifdef _WIN32
    if (pane == "Privacy_Accessibility") {
        OpenWindowsSettings("ms-settings:easeofaccess");
    } else if (pane == "Privacy_ScreenCapture") {
        OpenWindowsSettings("ms-settings:privacy-webcam");
    } else if (pane == "Privacy_ListenEvent") {
        OpenWindowsSettings("ms-settings:privacy-microphone");
    } else {
        OpenWindowsSettings("ms-settings:privacy");
    }
#endif
}

// N-API wrapper functions - Windows implementations
Napi::Value CheckAccessibilityPermission(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    try {
        bool hasPermission = PermissionChecker::CheckAccessibilityPermission();
        return Napi::Boolean::New(env, hasPermission);
    } catch (const std::exception& e) {
        Napi::Error::New(env, std::string("Error checking accessibility permission: ") + e.what())
            .ThrowAsJavaScriptException();
        return env.Null();
    }
}

Napi::Value CheckScreenRecordingPermission(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    try {
        bool hasPermission = PermissionChecker::CheckScreenRecordingPermission();
        return Napi::Boolean::New(env, hasPermission);
    } catch (const std::exception& e) {
        Napi::Error::New(env, std::string("Error checking screen recording permission: ") + e.what())
            .ThrowAsJavaScriptException();
        return env.Null();
    }
}

Napi::Value CheckInputMonitoringPermission(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    try {
        bool hasPermission = PermissionChecker::CheckInputMonitoringPermission();
        return Napi::Boolean::New(env, hasPermission);
    } catch (const std::exception& e) {
        Napi::Error::New(env, std::string("Error checking input monitoring permission: ") + e.what())
            .ThrowAsJavaScriptException();
        return env.Null();
    }
}

Napi::Value RequestAccessibilityPermission(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    try {
        bool granted = PermissionChecker::RequestAccessibilityPermission();
        return Napi::Boolean::New(env, granted);
    } catch (const std::exception& e) {
        Napi::Error::New(env, std::string("Error requesting accessibility permission: ") + e.what())
            .ThrowAsJavaScriptException();
        return env.Null();
    }
}

Napi::Value RequestScreenRecordingPermission(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    try {
        bool granted = PermissionChecker::RequestScreenRecordingPermission();
        return Napi::Boolean::New(env, granted);
    } catch (const std::exception& e) {
        Napi::Error::New(env, std::string("Error requesting screen recording permission: ") + e.what())
            .ThrowAsJavaScriptException();
        return env.Null();
    }
}

Napi::Value RequestInputMonitoringPermission(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    try {
        bool granted = PermissionChecker::RequestInputMonitoringPermission();
        return Napi::Boolean::New(env, granted);
    } catch (const std::exception& e) {
        Napi::Error::New(env, std::string("Error requesting input monitoring permission: ") + e.what())
            .ThrowAsJavaScriptException();
        return env.Null();
    }
}