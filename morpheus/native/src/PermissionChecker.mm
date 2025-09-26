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

bool PermissionChecker::CheckAccessibilityPermission() {
#ifdef __APPLE__
    NSDictionary* options = @{(__bridge NSString*)kAXTrustedCheckOptionPrompt: @NO};
    Boolean isTrusted = AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)options);
    return isTrusted;
#elif _WIN32
    return true;
#else
    return true;
#endif
}

bool PermissionChecker::CheckScreenRecordingPermission() {
#ifdef __APPLE__
    if (@available(macOS 10.15, *)) {
        CGDisplayStreamRef stream = CGDisplayStreamCreate(
            CGMainDisplayID(), 1, 1, kCVPixelFormatType_32BGRA,
            NULL, ^(CGDisplayStreamFrameStatus status, uint64_t displayTime, 
                   IOSurfaceRef frameSurface, CGDisplayStreamUpdateRef updateRef) {
            }
        );
        
        if (stream) {
            CFRelease(stream);
            return true;
        }
        return false;
    }
    return true;
#elif _WIN32
    return true;
#else
    return true;
#endif
}

bool PermissionChecker::CheckInputMonitoringPermission() {
#ifdef __APPLE__
    if (@available(macOS 10.15, *)) {
        IOHIDManagerRef hidManager = IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDOptionsTypeNone);
        if (!hidManager) {
            return false;
        }
        
        CFMutableDictionaryRef matchingDict = CFDictionaryCreateMutable(
            kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        
        int usagePage = kHIDPage_GenericDesktop;
        int usage = kHIDUsage_GD_Keyboard;
        
        CFNumberRef usagePageRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &usagePage);
        CFNumberRef usageRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &usage);
        
        CFDictionarySetValue(matchingDict, CFSTR(kIOHIDDeviceUsagePageKey), usagePageRef);
        CFDictionarySetValue(matchingDict, CFSTR(kIOHIDDeviceUsageKey), usageRef);
        
        IOHIDManagerSetDeviceMatching(hidManager, matchingDict);
        
        IOReturn result = IOHIDManagerOpen(hidManager, kIOHIDOptionsTypeNone);
        
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
    return true;
#elif _WIN32
    return true;
#else
    return true;
#endif
}

bool PermissionChecker::RequestAccessibilityPermission() {
#ifdef __APPLE__
    NSDictionary* options = @{(__bridge NSString*)kAXTrustedCheckOptionPrompt: @YES};
    Boolean isTrusted = AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)options);
    return isTrusted;
#else
    return true;
#endif
}

bool PermissionChecker::RequestScreenRecordingPermission() {
#ifdef __APPLE__
    if (@available(macOS 10.15, *)) {
        CGImageRef image = CGDisplayCreateImage(CGMainDisplayID());
        if (image) {
            CFRelease(image);
            return true;
        }
        return false;
    }
    return true;
#else
    return true;
#endif
}

bool PermissionChecker::RequestInputMonitoringPermission() {
#ifdef __APPLE__
    return CheckInputMonitoringPermission();
#else
    return true;
#endif
}

void PermissionChecker::OpenSystemPreferences(const std::string& pane) {
#ifdef __APPLE__
    std::string command = "open x-apple.systempreferences:" + pane;
    system(command.c_str());
#elif _WIN32
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

