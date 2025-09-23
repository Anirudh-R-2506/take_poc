#include "PermissionChecker.h"
#include <iostream>
#include <string>

#ifdef __APPLE__
#import <Foundation/Foundation.h>
#import <ApplicationServices/ApplicationServices.h>
#import <AVFoundation/AVFoundation.h>
#import <IOKit/hid/IOHIDManager.h>
#import <CoreFoundation/CoreFoundation.h>
#import <AppKit/AppKit.h>
#endif

#ifdef _WIN32
#include <windows.h>
#include <winuser.h>
#endif

/**
 * Check if accessibility permission is granted
 */
bool PermissionChecker::CheckAccessibilityPermission() {
#ifdef __APPLE__
    // On macOS, check if we have accessibility permission
    NSDictionary* options = @{(__bridge NSString*)kAXTrustedCheckOptionPrompt: @NO};
    Boolean isTrusted = AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)options);
    return isTrusted;
#elif _WIN32
    // On Windows, accessibility is generally available
    // Could check for specific accessibility features if needed
    return true;
#else
    // On Linux, assume accessibility is available
    return true;
#endif
}

/**
 * Check if screen recording permission is granted
 */
bool PermissionChecker::CheckScreenRecordingPermission() {
#ifdef __APPLE__
    // On macOS 10.15+, we need explicit screen recording permission
    if (@available(macOS 10.15, *)) {
        CGDisplayStreamRef stream = CGDisplayStreamCreate(
            CGMainDisplayID(), 1, 1, kCVPixelFormatType_32BGRA,
            NULL, ^(CGDisplayStreamFrameStatus status, uint64_t displayTime, 
                   IOSurfaceRef frameSurface, CGDisplayStreamUpdateRef updateRef) {
                // Empty callback - we're just testing permission
            }
        );
        
        if (stream) {
            CFRelease(stream);
            return true;
        }
        return false;
    }
    // On older macOS, screen recording is generally available
    return true;
#elif _WIN32
    // On Windows, screen recording is generally available
    // Could add specific checks for Windows 10+ privacy settings
    return true;
#else
    // On Linux, assume screen recording is available
    return true;
#endif
}

/**
 * Check if input monitoring permission is granted
 */
bool PermissionChecker::CheckInputMonitoringPermission() {
#ifdef __APPLE__
    // On macOS 10.15+, we need explicit input monitoring permission
    if (@available(macOS 10.15, *)) {
        // Try to create an HID manager to test input monitoring permission
        IOHIDManagerRef hidManager = IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDOptionsTypeNone);
        if (!hidManager) {
            return false;
        }
        
        // Set matching criteria for keyboard devices
        CFMutableDictionaryRef matchingDict = CFDictionaryCreateMutable(
            kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        
        int usagePage = kHIDPage_GenericDesktop;
        int usage = kHIDUsage_GD_Keyboard;
        
        CFNumberRef usagePageRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &usagePage);
        CFNumberRef usageRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &usage);
        
        CFDictionarySetValue(matchingDict, CFSTR(kIOHIDDeviceUsagePageKey), usagePageRef);
        CFDictionarySetValue(matchingDict, CFSTR(kIOHIDDeviceUsageKey), usageRef);
        
        IOHIDManagerSetDeviceMatching(hidManager, matchingDict);
        
        // Try to open the manager
        IOReturn result = IOHIDManagerOpen(hidManager, kIOHIDOptionsTypeNone);
        
        // Clean up
        CFRelease(usagePageRef);
        CFRelease(usageRef);
        CFRelease(matchingDict);
        
        if (result == kIOReturnSuccess) {
            IOHIDManagerClose(hidManager, kIOHIDOptionsTypeNone);
            CFRelease(hidManager);
            return true;
        }
        
        CFRelease(hidManager);
        return false;
    }
    // On older macOS, input monitoring is generally available
    return true;
#elif _WIN32
    // On Windows, input monitoring is generally available
    // Could add specific checks for Windows privacy settings
    return true;
#else
    // On Linux, assume input monitoring is available
    return true;
#endif
}

/**
 * Request accessibility permission (will prompt user)
 */
bool PermissionChecker::RequestAccessibilityPermission() {
#ifdef __APPLE__
    // On macOS, prompt the user for accessibility permission
    NSDictionary* options = @{(__bridge NSString*)kAXTrustedCheckOptionPrompt: @YES};
    Boolean isTrusted = AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)options);
    return isTrusted;
#else
    // On non-macOS, assume granted
    return true;
#endif
}

/**
 * Request screen recording permission (will prompt user)
 */
bool PermissionChecker::RequestScreenRecordingPermission() {
#ifdef __APPLE__
    // On macOS 10.15+, request screen recording permission
    if (@available(macOS 10.15, *)) {
        // The act of trying to capture will prompt for permission
        CGImageRef image = CGDisplayCreateImage(CGMainDisplayID());
        if (image) {
            CFRelease(image);
            return true;
        }
        return false;
    }
    return true;
#else
    // On non-macOS, assume granted
    return true;
#endif
}

/**
 * Request input monitoring permission (will prompt user)
 */
bool PermissionChecker::RequestInputMonitoringPermission() {
#ifdef __APPLE__
    // On macOS, requesting input monitoring automatically prompts
    return CheckInputMonitoringPermission();
#else
    // On non-macOS, assume granted
    return true;
#endif
}

/**
 * Open System Preferences to specific pane
 */
void PermissionChecker::OpenSystemPreferences(const std::string& pane) {
#ifdef __APPLE__
    std::string command = "open x-apple.systempreferences:" + pane;
    system(command.c_str());
#elif _WIN32
    // On Windows, open Settings app
    if (pane == "Privacy_Accessibility") {
        system("start ms-settings:easeofaccess");
    } else if (pane == "Privacy_ScreenCapture") {
        system("start ms-settings:privacy-webcam");
    } else if (pane == "Privacy_ListenEvent") {
        system("start ms-settings:privacy-microphone");
    } else {
        system("start ms-settings:privacy");
    }
#endif
}

// N-API wrapper functions
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

