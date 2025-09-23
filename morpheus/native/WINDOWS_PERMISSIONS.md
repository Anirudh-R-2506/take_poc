# Windows Permission Implementation

## Overview

The Windows permission system has been implemented to provide equivalent functionality to the macOS version, with platform-specific Windows APIs and privacy settings integration.

## Windows Permission Types

### 1. Accessibility Permission
- **Implementation**: Checks for Windows accessibility features and tools
- **Detection**: Uses `SystemParametersInfo` for high contrast mode and `FindWindow` for Narrator
- **Request Method**: Opens Windows Ease of Access settings (`ms-settings:easeofaccess`)
- **Notes**: Most accessibility features are available by default on Windows

### 2. Screen Recording Permission  
- **Implementation**: Maps to Windows Camera Privacy Settings
- **Detection**: Checks registry keys under `CapabilityAccessManager\ConsentStore\webcam`
- **Registry Paths**:
  - Global: `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam`
  - Desktop Apps: `...\webcam\NonPackaged`
- **Request Method**: Opens Camera Privacy Settings (`ms-settings:privacy-webcam`)

### 3. Input Monitoring Permission
- **Implementation**: Maps to Windows Microphone Privacy Settings  
- **Detection**: Checks registry keys under `CapabilityAccessManager\ConsentStore\microphone`
- **Registry Paths**:
  - Global: `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone` 
  - Desktop Apps: `...\microphone\NonPackaged`
- **Request Method**: Opens Microphone Privacy Settings (`ms-settings:privacy-microphone`)

### 4. Administrator Privileges
- **Implementation**: Uses Windows Token API to check for admin group membership
- **Detection**: `CheckTokenMembership` with Administrator SID
- **UAC Integration**: Checks registry for UAC status under `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`

## Windows-Specific Features

### Registry Access
- Uses `RegOpenKeyExW` and `RegQueryValueExW` for UTF-16 string compatibility
- Checks both global and per-application privacy settings
- Handles missing registry keys gracefully (assumes permission needed)

### Native Dialog Integration
- Uses `MessageBoxW` for permission request confirmations
- Provides user-friendly explanations before opening settings
- Integrates with Windows Settings app via `ms-settings:` URIs

### Settings App Integration  
- **Ease of Access**: `ms-settings:easeofaccess`
- **Camera Privacy**: `ms-settings:privacy-webcam`
- **Microphone Privacy**: `ms-settings:privacy-microphone`
- **General Privacy**: `ms-settings:privacy`

## Build Configuration

### Libraries Required
```
- setupapi.lib      // Device enumeration
- user32.lib        // UI and system functions  
- gdi32.lib         // Graphics functions
- iphlpapi.lib      // Network functions
- advapi32.lib      // Registry access
- ws2_32.lib        // Windows sockets
- oleacc.lib        // Accessibility
- ole32.lib         // COM functions
- psapi.lib         // Process API
- dwmapi.lib        // Desktop Window Manager
- shell32.lib       // Shell functions (new)
- wbemuuid.lib      // WMI functions (new)
- oleaut32.lib      // OLE automation (new)
```

### Platform-Specific Files
- **macOS**: `PermissionChecker.mm` (Objective-C++)
- **Windows**: `PermissionChecker_win.cpp` (C++ with Windows APIs)

## Windows Privacy Model

Unlike macOS which has explicit permission dialogs, Windows uses a privacy settings model:

1. **Global Settings**: Control whether the capability is available system-wide
2. **Per-App Settings**: Control which applications can access the capability
3. **Desktop Apps**: Non-packaged apps (like Electron) fall under "NonPackaged" category

## Error Handling

- Registry access failures are handled gracefully
- Missing registry keys default to "permission needed" (conservative approach)
- Native dialog failures fall back to direct settings app launching
- All Windows API calls include proper error checking

## Testing Considerations

The Windows implementation can be tested by:

1. **Changing Privacy Settings**: Modify camera/microphone settings in Windows Privacy
2. **Registry Verification**: Check registry keys match the implementation paths
3. **UAC Testing**: Test with both admin and non-admin user accounts
4. **Dialog Testing**: Verify permission request dialogs appear correctly

## Integration Notes

- The Windows implementation provides identical JavaScript API surface to macOS
- Permission status detection is more conservative (assumes denied when uncertain)
- Native dialogs provide better user experience than direct settings launching
- All Windows-specific code is properly `#ifdef _WIN32` protected