#include "ScreenWatcher.h"
#include <sstream>
#include <iostream>
#include <chrono>
#include <algorithm>
#include <ctime>

#ifdef _WIN32
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#elif __APPLE__
#include <libproc.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <cstring>
#include <mach/mach.h>
#include <dlfcn.h>

// Import Objective-C frameworks
#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <AVFoundation/AVFoundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <IOKit/IOKitLib.h>
#import <IOKit/hid/IOHIDLib.h>
#import <ApplicationServices/ApplicationServices.h>
#endif

ScreenWatcher::ScreenWatcher() : isRunning(false), checkIntervalMs(3000),
                                 lastRecordingState_(false), recordingConfidenceThreshold_(0.75), overlayConfidenceThreshold_(0.6),
                                 lastScreenSharingState_(false), screenSharingConfidenceThreshold_(0.75) {
    std::cout << "[ScreenWatcher] Initialized for platform: " 
              << (isPlatformSupported() ? "supported" : "unsupported") << std::endl;
    
    // Initialize recording detection blacklist
    initializeRecordingBlacklist();
}

ScreenWatcher::~ScreenWatcher() {
    stopWatching();
}

bool ScreenWatcher::isPlatformSupported() {
#if defined(_WIN32) || defined(__APPLE__)
    return true;
#else
    return false;
#endif
}

bool ScreenWatcher::startWatching(std::function<void(const std::string&)> callback, int intervalMs) {
    if (isRunning) {
        std::cout << "[ScreenWatcher] Already running" << std::endl;
        return false;
    }
    
    if (!isPlatformSupported()) {
        std::cout << "[ScreenWatcher] Platform not supported" << std::endl;
        return false;
    }
    
    eventCallback = callback;
    checkIntervalMs = intervalMs;
    isRunning = true;
    
    watcherThread = std::thread(&ScreenWatcher::watcherLoop, this);
    
    std::cout << "[ScreenWatcher] Started monitoring (interval: " << intervalMs << "ms)" << std::endl;
    return true;
}

void ScreenWatcher::stopWatching() {
    if (!isRunning) return;
    
    isRunning = false;
    
    if (watcherThread.joinable()) {
        watcherThread.join();
    }
    
    std::cout << "[ScreenWatcher] Stopped monitoring" << std::endl;
}

void ScreenWatcher::watcherLoop() {
    while (isRunning) {
        try {
            ScreenStatus status = detectScreenStatus();
            std::string jsonData = statusToJson(status);
            
            if (eventCallback) {
                eventCallback(jsonData);
            }
        } catch (const std::exception& e) {
            std::cerr << "[ScreenWatcher] Error in monitoring loop: " << e.what() << std::endl;
        }
        
        // Sleep for the specified interval
        auto sleepDuration = std::chrono::milliseconds(checkIntervalMs);
        std::this_thread::sleep_for(sleepDuration);
    }
}

ScreenStatus ScreenWatcher::getCurrentStatus() {
    return detectScreenStatus();
}

ScreenStatus ScreenWatcher::detectScreenStatus() {
    ScreenStatus status = {};
    
    try {
#ifdef _WIN32
        status.displays = getWindowsDisplays();
        status.mirroring = isWindowsMirroring();
        status.splitScreen = isWindowsSplitScreen();
        auto devices = getWindowsInputDevices();
#elif __APPLE__
        status.displays = getMacOSDisplays();
        status.mirroring = isMacOSMirroring();
        status.splitScreen = isMacOSSplitScreen();
        auto devices = getMacOSInputDevices();
#else
        // Unsupported platform - return empty status
        return status;
#endif
        
        // Separate external displays and devices
        for (const auto& display : status.displays) {
            if (display.isExternal) {
                status.externalDisplays.push_back(display);
            }
        }
        
        for (const auto& device : devices) {
            if (device.isExternal) {
                if (device.type == "keyboard") {
                    status.externalKeyboards.push_back(device);
                } else {
                    status.externalDevices.push_back(device);
                }
            }
        }
        
    } catch (const std::exception& e) {
        std::cerr << "[ScreenWatcher] Error detecting screen status: " << e.what() << std::endl;
    }
    
    return status;
}

#ifdef _WIN32

std::vector<DisplayInfo> ScreenWatcher::getWindowsDisplays() {
    std::vector<DisplayInfo> displays;
    
    DISPLAY_DEVICE displayDevice;
    displayDevice.cb = sizeof(DISPLAY_DEVICE);
    
    for (DWORD i = 0; EnumDisplayDevices(NULL, i, &displayDevice, 0); i++) {
        DisplayInfo info;
        info.name = std::string(displayDevice.DeviceString);
        info.isPrimary = (displayDevice.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE) != 0;
        info.isExternal = !info.isPrimary; // Simple heuristic for Windows
        info.isMirrored = false; // Will be set by mirroring detection
        
        // Get display dimensions
        DEVMODE devMode;
        devMode.dmSize = sizeof(DEVMODE);
        if (EnumDisplaySettings(displayDevice.DeviceName, ENUM_CURRENT_SETTINGS, &devMode)) {
            info.width = devMode.dmPelsWidth;
            info.height = devMode.dmPelsHeight;
        } else {
            info.width = 0;
            info.height = 0;
        }
        
        displays.push_back(info);
    }
    
    return displays;
}

std::vector<InputDeviceInfo> ScreenWatcher::getWindowsInputDevices() {
    std::vector<InputDeviceInfo> devices;
    
    // Enumerate keyboards
    HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_KEYBOARD, NULL, NULL, DIGCF_PRESENT);
    if (hDevInfo != INVALID_HANDLE_VALUE) {
        SP_DEVINFO_DATA deviceInfoData;
        deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
        
        for (DWORD i = 0; SetupDiEnumInputDeviceInfo(hDevInfo, i, &deviceInfoData); i++) {
            char buffer[256];
            if (SetupDiGetDeviceRegistryPropertyA(hDevInfo, &deviceInfoData, SPDRP_FRIENDLYNAME,
                                                 NULL, (PBYTE)buffer, sizeof(buffer), NULL)) {
                InputDeviceInfo device;
                device.name = sanitizeDeviceName(std::string(buffer));
                device.type = "keyboard";
                // Simple heuristic: external if not containing "HID" or "Standard"
                device.isExternal = (device.name.find("HID") == std::string::npos && 
                                   device.name.find("Standard") == std::string::npos);
                devices.push_back(device);
            }
        }
        SetupDiDestroyInputDeviceInfoList(hDevInfo);
    }
    
    // Enumerate mice
    hDevInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_MOUSE, NULL, NULL, DIGCF_PRESENT);
    if (hDevInfo != INVALID_HANDLE_VALUE) {
        SP_DEVINFO_DATA deviceInfoData;
        deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
        
        for (DWORD i = 0; SetupDiEnumInputDeviceInfo(hDevInfo, i, &deviceInfoData); i++) {
            char buffer[256];
            if (SetupDiGetDeviceRegistryPropertyA(hDevInfo, &deviceInfoData, SPDRP_FRIENDLYNAME,
                                                 NULL, (PBYTE)buffer, sizeof(buffer), NULL)) {
                InputDeviceInfo device;
                device.name = sanitizeDeviceName(std::string(buffer));
                device.type = "mouse";
                // Simple heuristic: external if not containing "HID" or "PS/2"
                device.isExternal = (device.name.find("HID") == std::string::npos && 
                                   device.name.find("PS/2") == std::string::npos);
                devices.push_back(device);
            }
        }
        SetupDiDestroyInputDeviceInfoList(hDevInfo);
    }
    
    return devices;
}

bool ScreenWatcher::isWindowsMirroring() {
    int monitorCount = GetSystemMetrics(SM_CMONITORS);
    if (monitorCount <= 1) return false;
    
    // Simple heuristic: if we have multiple monitors, check if they have the same resolution
    // This is a simplified approach - more sophisticated detection would compare actual content
    std::vector<std::pair<int, int>> resolutions;
    
    DISPLAY_DEVICE displayDevice;
    displayDevice.cb = sizeof(DISPLAY_DEVICE);
    
    for (DWORD i = 0; EnumDisplayDevices(NULL, i, &displayDevice, 0); i++) {
        DEVMODE devMode;
        devMode.dmSize = sizeof(DEVMODE);
        if (EnumDisplaySettings(displayDevice.DeviceName, ENUM_CURRENT_SETTINGS, &devMode)) {
            resolutions.push_back({devMode.dmPelsWidth, devMode.dmPelsHeight});
        }
    }
    
    // Check if all resolutions are the same (indication of mirroring)
    if (resolutions.size() > 1) {
        auto firstRes = resolutions[0];
        for (size_t i = 1; i < resolutions.size(); i++) {
            if (resolutions[i] != firstRes) {
                return false; // Different resolutions, likely extended display
            }
        }
        return true; // Same resolutions, likely mirroring
    }
    
    return false;
}

bool ScreenWatcher::isWindowsSplitScreen() {
    HWND foregroundWindow = GetForegroundWindow();
    if (!foregroundWindow) return false;
    
    RECT windowRect, screenRect;
    if (!GetWindowRect(foregroundWindow, &windowRect)) return false;
    
    // Get the monitor containing the window
    HMONITOR monitor = MonitorFromWindow(foregroundWindow, MONITOR_DEFAULTTONEAREST);
    MONITORINFO monitorInfo;
    monitorInfo.cbSize = sizeof(MONITORINFO);
    
    if (!GetMonitorInfo(monitor, &monitorInfo)) return false;
    
    screenRect = monitorInfo.rcWork;
    
    int windowWidth = windowRect.right - windowRect.left;
    int windowHeight = windowRect.bottom - windowRect.top;
    int screenWidth = screenRect.right - screenRect.left;
    int screenHeight = screenRect.bottom - screenRect.top;
    
    // Check if window is approximately half the screen width (split screen)
    bool isHalfWidth = (windowWidth > screenWidth * 0.4 && windowWidth < screenWidth * 0.6);
    bool isFullHeight = (windowHeight > screenHeight * 0.8);
    
    return isHalfWidth && isFullHeight;
}

#elif __APPLE__

std::vector<DisplayInfo> ScreenWatcher::getMacOSDisplays() {
    std::vector<DisplayInfo> displays;
    
    uint32_t displayCount;
    CGGetOnlineDisplayList(0, nullptr, &displayCount);
    
    if (displayCount > 0) {
        std::vector<CGDirectDisplayID> displayList(displayCount);
        CGGetOnlineDisplayList(displayCount, displayList.data(), &displayCount);
        
        for (uint32_t i = 0; i < displayCount; i++) {
            CGDirectDisplayID displayID = displayList[i];
            DisplayInfo info;
            
            // Get display name - simplified approach
            info.name = "Display " + std::to_string(i + 1);
            if (CGDisplayIsMain(displayID)) {
                info.name = "Built-in Display";
            }
            
            info.isPrimary = CGDisplayIsMain(displayID);
            info.isExternal = !info.isPrimary;
            info.isMirrored = CGDisplayIsInMirrorSet(displayID);
            info.width = (int)CGDisplayPixelsWide(displayID);
            info.height = (int)CGDisplayPixelsHigh(displayID);
            
            displays.push_back(info);
        }
    }
    
    return displays;
}

std::vector<InputDeviceInfo> ScreenWatcher::getMacOSInputDevices() {
    std::vector<InputDeviceInfo> devices;
    
    // Create HID manager
    IOHIDManagerRef hidManager = IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDOptionsTypeNone);
    if (!hidManager) return devices;
    
    // Set matching criteria for keyboards and mice
    CFMutableDictionaryRef keyboardDict = IOServiceMatching(kIOHIDDeviceKey);
    CFMutableDictionaryRef mouseDict = IOServiceMatching(kIOHIDDeviceKey);

    // Add usage page and usage for keyboard
    int keyboardUsagePageValue = kHIDPage_GenericDesktop;
    int keyboardUsageValue = kHIDUsage_GD_Keyboard;
    CFNumberRef keyboardUsagePage = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &keyboardUsagePageValue);
    CFNumberRef keyboardUsage = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &keyboardUsageValue);
    CFDictionarySetValue(keyboardDict, CFSTR(kIOHIDPrimaryUsagePageKey), keyboardUsagePage);
    CFDictionarySetValue(keyboardDict, CFSTR(kIOHIDPrimaryUsageKey), keyboardUsage);

    // Add usage page and usage for mouse
    int mouseUsagePageValue = kHIDPage_GenericDesktop;
    int mouseUsageValue = kHIDUsage_GD_Mouse;
    CFNumberRef mouseUsagePage = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &mouseUsagePageValue);
    CFNumberRef mouseUsage = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &mouseUsageValue);
    CFDictionarySetValue(mouseDict, CFSTR(kIOHIDPrimaryUsagePageKey), mouseUsagePage);
    CFDictionarySetValue(mouseDict, CFSTR(kIOHIDPrimaryUsageKey), mouseUsage);

    // Create array of matching dictionaries
    CFMutableArrayRef matchingArray = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    CFArrayAppendValue(matchingArray, keyboardDict);
    CFArrayAppendValue(matchingArray, mouseDict);

    IOHIDManagerSetDeviceMatchingMultiple(hidManager, matchingArray);
    IOHIDManagerOpen(hidManager, kIOHIDOptionsTypeNone);

    // Clean up
    CFRelease(keyboardUsagePage);
    CFRelease(keyboardUsage);
    CFRelease(mouseUsagePage);
    CFRelease(mouseUsage);
    CFRelease(matchingArray);
    
    CFSetRef deviceSet = IOHIDManagerCopyDevices(hidManager);
    if (deviceSet) {
        CFIndex deviceCount = CFSetGetCount(deviceSet);
        std::vector<IOHIDDeviceRef> deviceList(deviceCount);
        CFSetGetValues(deviceSet, (const void**)deviceList.data());
        
        for (CFIndex i = 0; i < deviceCount; i++) {
            IOHIDDeviceRef device = deviceList[i];
            
            // Get device name
            CFStringRef productName = (CFStringRef)IOHIDDeviceGetProperty(device, CFSTR(kIOHIDProductKey));
            if (productName) {
                char nameBuffer[256];
                if (CFStringGetCString(productName, nameBuffer, sizeof(nameBuffer), kCFStringEncodingUTF8)) {
                    InputDeviceInfo deviceInfo;
                    deviceInfo.name = sanitizeDeviceName(std::string(nameBuffer));
                    
                    // Determine device type
                    CFNumberRef usagePage = (CFNumberRef)IOHIDDeviceGetProperty(device, CFSTR(kIOHIDPrimaryUsagePageKey));
                    CFNumberRef usage = (CFNumberRef)IOHIDDeviceGetProperty(device, CFSTR(kIOHIDPrimaryUsageKey));
                    
                    int usagePageValue = 0, usageValue = 0;
                    if (usagePage) CFNumberGetValue(usagePage, kCFNumberIntType, &usagePageValue);
                    if (usage) CFNumberGetValue(usage, kCFNumberIntType, &usageValue);
                    
                    if (usagePageValue == kHIDPage_GenericDesktop) {
                        if (usageValue == kHIDUsage_GD_Keyboard) {
                            deviceInfo.type = "keyboard";
                        } else if (usageValue == kHIDUsage_GD_Mouse) {
                            deviceInfo.type = "mouse";
                        } else {
                            deviceInfo.type = "other";
                        }
                    } else {
                        deviceInfo.type = "other";
                    }
                    
                    // Determine if external (comprehensive filtering)
                    std::string lowerName = deviceInfo.name;
                    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
                    
                    bool isInternalDevice = (
                        // Standard Apple internal device patterns
                        lowerName.find("apple internal") != std::string::npos ||
                        lowerName.find("built-in") != std::string::npos ||
                        lowerName.find("internal") != std::string::npos ||
                        
                        // MacBook internal components
                        lowerName.find("headset") != std::string::npos ||
                        lowerName.find("btm") != std::string::npos ||
                        lowerName.find("keyboard backlight") != std::string::npos ||
                        lowerName.find("ambient light sensor") != std::string::npos ||
                        lowerName.find("smc") != std::string::npos ||
                        lowerName.find("touchbar") != std::string::npos ||
                        lowerName.find("touch bar") != std::string::npos ||
                        lowerName.find("force touch") != std::string::npos ||
                        lowerName.find("trackpad") != std::string::npos ||
                        lowerName.find("lid angle") != std::string::npos ||
                        lowerName.find("motion") != std::string::npos ||
                        
                        // System and virtual devices
                        lowerName.find("virtual") != std::string::npos ||
                        lowerName.find("system") != std::string::npos ||
                        lowerName.find("generic") != std::string::npos ||
                        
                        // Empty or very short device names (often system components)
                        lowerName.length() < 3
                    );
                    
                    deviceInfo.isExternal = !isInternalDevice;
                    
                    devices.push_back(deviceInfo);
                }
            }
        }
        
        CFRelease(deviceSet);
    }
    
    IOHIDManagerClose(hidManager, kIOHIDOptionsTypeNone);
    CFRelease(hidManager);
    
    return devices;
}

bool ScreenWatcher::isMacOSMirroring() {
    uint32_t displayCount;
    CGGetOnlineDisplayList(0, nullptr, &displayCount);
    
    if (displayCount <= 1) return false;
    
    std::vector<CGDirectDisplayID> displayList(displayCount);
    CGGetOnlineDisplayList(displayCount, displayList.data(), &displayCount);
    
    for (uint32_t i = 0; i < displayCount; i++) {
        if (CGDisplayIsInMirrorSet(displayList[i])) {
            return true;
        }
    }
    
    return false;
}

bool ScreenWatcher::isMacOSSplitScreen() {
    // This is a simplified approach for macOS Split View detection
    // A more sophisticated implementation would use Accessibility APIs
    
    // For now, return false as proper Split View detection requires
    // more complex Accessibility API integration
    return false;
}

#endif

std::string ScreenWatcher::sanitizeDeviceName(const std::string& name) {
    std::string sanitized = name;
    
    // Remove null characters and control characters
    sanitized.erase(std::remove_if(sanitized.begin(), sanitized.end(), 
                   [](char c) { return c < 32 || c > 126; }), sanitized.end());
    
    // Trim whitespace
    sanitized.erase(0, sanitized.find_first_not_of(" \t"));
    sanitized.erase(sanitized.find_last_not_of(" \t") + 1);
    
    return sanitized;
}

std::string ScreenWatcher::statusToJson(const ScreenStatus& status) {
    std::ostringstream json;
    
    json << "{";
    json << "\"mirroring\": " << (status.mirroring ? "true" : "false") << ",";
    json << "\"splitScreen\": " << (status.splitScreen ? "true" : "false") << ",";
    
    // All displays
    json << "\"displays\": [";
    for (size_t i = 0; i < status.displays.size(); ++i) {
        if (i > 0) json << ",";
        json << "\"" << escapeJson(status.displays[i].name) << "\"";
    }
    json << "],";
    
    // External displays
    json << "\"externalDisplays\": [";
    for (size_t i = 0; i < status.externalDisplays.size(); ++i) {
        if (i > 0) json << ",";
        json << "\"" << escapeJson(status.externalDisplays[i].name) << "\"";
    }
    json << "],";
    
    // External keyboards
    json << "\"externalKeyboards\": [";
    for (size_t i = 0; i < status.externalKeyboards.size(); ++i) {
        if (i > 0) json << ",";
        json << "\"" << escapeJson(status.externalKeyboards[i].name) << "\"";
    }
    json << "],";
    
    // External devices
    json << "\"externalDevices\": [";
    for (size_t i = 0; i < status.externalDevices.size(); ++i) {
        if (i > 0) json << ",";
        json << "\"" << escapeJson(status.externalDevices[i].name) << "\"";
    }
    json << "],";
    
    json << "\"timestamp\": " << std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() << ",";
    json << "\"module\": \"screen-watch\",";
    json << "\"source\": \"native\",";
    json << "\"count\": " << static_cast<int>(status.displays.size() + status.externalKeyboards.size() + status.externalDevices.size());
    
    json << "}";
    return json.str();
}

// Recording/Overlay Detection Implementation
void ScreenWatcher::initializeRecordingBlacklist() {
    // Common recording/streaming applications
    recordingBlacklist_.insert("obs64.exe");
    recordingBlacklist_.insert("obs32.exe");
    recordingBlacklist_.insert("OBS");
    recordingBlacklist_.insert("CamtasiaStudio.exe");
    recordingBlacklist_.insert("Camtasia");
    recordingBlacklist_.insert("Bandicam.exe");
    recordingBlacklist_.insert("Fraps.exe");
    recordingBlacklist_.insert("XSplit.Broadcaster.exe");
    recordingBlacklist_.insert("zoom.exe");
    recordingBlacklist_.insert("Zoom");
    recordingBlacklist_.insert("Teams.exe");
    recordingBlacklist_.insert("Microsoft Teams");
    recordingBlacklist_.insert("chrome.exe"); // For browser-based recording
    recordingBlacklist_.insert("firefox.exe");
    recordingBlacklist_.insert("QuickTime Player");
    recordingBlacklist_.insert("ScreenSearch");
    recordingBlacklist_.insert("Snagit");
    recordingBlacklist_.insert("CloudApp");
    recordingBlacklist_.insert("Loom");
    recordingBlacklist_.insert("Screencastify");
}

RecordingDetectionResult ScreenWatcher::detectRecordingAndOverlays() {
    RecordingDetectionResult result;
    result.isRecording = false;
    result.recordingConfidence = 0.0;
    result.overlayConfidence = 0.0;
    
    try {
        // Detect recording processes
        result.recordingSources = detectRecordingProcesses();
        
        // Get virtual cameras
        result.virtualCameras = getVirtualCameras();
        
        // Detect overlay windows
        result.overlayWindows = getOverlayWindows();
        
        // Calculate confidence scores
        result.recordingConfidence = calculateRecordingConfidence(result.recordingSources, result.virtualCameras);
        result.overlayConfidence = calculateOverlayConfidence(result.overlayWindows);
        
        // Determine if recording based on confidence
        result.isRecording = result.recordingConfidence >= recordingConfidenceThreshold_;
        
        // Set event type based on state changes
        if (result.isRecording != lastRecordingState_) {
            result.eventType = result.isRecording ? "recording-started" : "recording-stopped";
            lastRecordingState_ = result.isRecording;
        } else if (!result.overlayWindows.empty() && lastOverlayWindows_.size() != result.overlayWindows.size()) {
            result.eventType = result.overlayWindows.size() > lastOverlayWindows_.size() ? "overlay-detected" : "overlay-removed";
        } else {
            result.eventType = "heartbeat";
        }
        
        lastOverlayWindows_ = result.overlayWindows;
        
    } catch (const std::exception& e) {
        // Handle errors gracefully
        result.eventType = "error";
    }
    
    return result;
}

void ScreenWatcher::setRecordingBlacklist(const std::vector<std::string>& recordingBlacklist) {
    recordingBlacklist_.clear();
    for (const auto& item : recordingBlacklist) {
        recordingBlacklist_.insert(item);
    }
}

std::vector<std::string> ScreenWatcher::getVirtualCameras() {
    return enumerateVirtualCameras();
}

std::vector<OverlayWindow> ScreenWatcher::getOverlayWindows() {
    return enumerateWindowsForOverlays();
}

std::vector<ProcessInfo> ScreenWatcher::detectRecordingProcesses() {
    std::vector<ProcessInfo> recordingProcesses;
    auto processes = getRunningProcesses();
    
    for (auto& process : processes) {
        ProcessInfo recordingProcess = process;
        recordingProcess.evidence.clear();
        
        // Check against recording blacklist
        bool isBlacklisted = false;
        for (const auto& blacklistItem : recordingBlacklist_) {
            if (process.name.find(blacklistItem) != std::string::npos ||
                process.path.find(blacklistItem) != std::string::npos) {
                recordingProcess.evidence.push_back("blacklist");
                isBlacklisted = true;
                break;
            }
        }
        
        // Check for graphics/media modules
        try {
#ifdef _WIN32
            recordingProcess.loadedModules = getProcessModules(process.pid);
#elif __APPLE__
            recordingProcess.loadedModules = getProcessLibraries(process.pid);
#endif
            
            for (const auto& module : recordingProcess.loadedModules) {
                std::string lowerModule = module;
                std::transform(lowerModule.begin(), lowerModule.end(), lowerModule.begin(), ::tolower);
                
                if (lowerModule.find("dxgi") != std::string::npos) {
                    recordingProcess.evidence.push_back("module-dxgi");
                } else if (lowerModule.find("d3d11") != std::string::npos || lowerModule.find("d3d9") != std::string::npos) {
                    recordingProcess.evidence.push_back("module-d3d");
                } else if (lowerModule.find("mfplat") != std::string::npos) {
                    recordingProcess.evidence.push_back("module-mediafoundation");
                } else if (lowerModule.find("avfoundation") != std::string::npos) {
                    recordingProcess.evidence.push_back("module-avfoundation");
                } else if (lowerModule.find("screencapturekit") != std::string::npos) {
                    recordingProcess.evidence.push_back("module-screencapturekit");
                }
            }
        } catch (...) {
            // Module enumeration may fail for some processes - continue
        }
        
        if (isBlacklisted || !recordingProcess.evidence.empty()) {
            recordingProcesses.push_back(recordingProcess);
        }
    }
    
    return recordingProcesses;
}

std::vector<OverlayWindow> ScreenWatcher::detectOverlayWindows() {
    return enumerateWindowsForOverlays();
}

double ScreenWatcher::calculateRecordingConfidence(const std::vector<ProcessInfo>& recordingProcesses, const std::vector<std::string>& virtualCameras) {
    double confidence = 0.0;
    
    for (const auto& process : recordingProcesses) {
        for (const auto& evidence : process.evidence) {
            if (evidence == "blacklist") {
                confidence += 0.6;
            } else if (evidence == "module-dxgi" || evidence == "module-screencapturekit") {
                confidence += 0.8;
            } else if (evidence == "module-d3d" || evidence == "module-avfoundation") {
                confidence += 0.25;
            } else if (evidence == "module-mediafoundation") {
                confidence += 0.25;
            }
        }
    }
    
    // Virtual cameras add confidence
    confidence += virtualCameras.size() * 0.3;
    
    return std::min(confidence, 1.0);
}

double ScreenWatcher::calculateOverlayConfidence(const std::vector<OverlayWindow>& overlayWindows) {
    double confidence = 0.0;
    
    for (const auto& overlay : overlayWindows) {
        double windowConfidence = 0.0;
        
        // Base confidence for overlay window
        windowConfidence += 0.4;
        
        // Transparency increases confidence
        if (overlay.alpha < 1.0) {
            windowConfidence += 0.3;
        }
        
        // Check extended styles
        for (const auto& style : overlay.extendedStyles) {
            if (style == "WS_EX_TOPMOST" || style == "HIGH_WINDOW_LEVEL") {
                windowConfidence += 0.2;
            } else if (style == "WS_EX_LAYERED") {
                windowConfidence += 0.2;
            } else if (style == "WS_EX_TRANSPARENT" || style == "TRANSPARENT") {
                windowConfidence += 0.3;
            }
        }
        
        confidence += std::min(windowConfidence, 1.0);
    }
    
    return std::min(confidence, 1.0);
}

std::vector<ProcessInfo> ScreenWatcher::getRunningProcesses() {
    std::vector<ProcessInfo> processes;
    
#ifdef _WIN32
    // Windows implementation
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return processes;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            std::string processName(pe32.szExeFile);
            std::string processPath;
            
            // Get process path
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            if (hProcess != nullptr) {
                char path[MAX_PATH];
                DWORD size = sizeof(path);
                if (GetModuleFileNameEx(hProcess, nullptr, path, size)) {
                    processPath = std::string(path);
                }
                CloseHandle(hProcess);
            }
            
            processes.emplace_back(pe32.th32ProcessID, processName, processPath);
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    
#elif __APPLE__
    // macOS implementation
    int numberOfProcesses = proc_listallpids(nullptr, 0);
    if (numberOfProcesses <= 0) {
        return processes;
    }
    
    std::vector<pid_t> pids(numberOfProcesses);
    numberOfProcesses = proc_listallpids(pids.data(), numberOfProcesses * sizeof(pid_t));
    
    for (int i = 0; i < numberOfProcesses; i++) {
        pid_t pid = pids[i];
        if (pid <= 0) continue;
        
        char pathBuffer[PROC_PIDPATHINFO_MAXSIZE];
        int ret = proc_pidpath(pid, pathBuffer, sizeof(pathBuffer));
        
        if (ret > 0) {
            std::string fullPath(pathBuffer);
            std::string processName;
            
            // Extract process name
            size_t lastSlash = fullPath.find_last_of('/');
            if (lastSlash != std::string::npos) {
                processName = fullPath.substr(lastSlash + 1);
            } else {
                processName = fullPath;
            }
            
            processes.emplace_back(pid, processName, fullPath);
        }
    }
#endif
    
    return processes;
}

// Helper function to get process name for PID on macOS
std::string ScreenWatcher::getProcessNameForPID(pid_t pid) {
    @autoreleasepool {
        NSRunningApplication *app = [NSRunningApplication runningApplicationWithProcessIdentifier:pid];
        if (app) {
            // Try localized name first, then bundle identifier
            NSString *name = [app localizedName];
            if (name && [name length] > 0) {
                return std::string([name UTF8String]);
            }

            NSString *bundleId = [app bundleIdentifier];
            if (bundleId && [bundleId length] > 0) {
                return std::string([bundleId UTF8String]);
            }
        }

        // Fallback: try to get name from process path
        char pathBuffer[PROC_PIDPATHINFO_MAXSIZE];
        if (proc_pidpath(pid, pathBuffer, sizeof(pathBuffer)) > 0) {
            const char* baseName = strrchr(pathBuffer, '/');
            if (baseName) {
                return std::string(baseName + 1);
            }
            return std::string(pathBuffer);
        }

        // Last resort: use the PID
        return "Process " + std::to_string(pid);
    }
}

std::string ScreenWatcher::createRecordingOverlayEventJson(const RecordingDetectionResult& result) {
    std::time_t now = std::time(nullptr);
    std::ostringstream json;
    
    json << "{"
         << "\"module\": \"recorder-overlay-watch\","
         << "\"eventType\": \"" << escapeJson(result.eventType) << "\","
         << "\"timestamp\": " << (now * 1000) << ",";
    
    if (result.eventType == "recording-started" || result.eventType == "recording-stopped") {
        json << "\"sources\": [";
        for (size_t i = 0; i < result.recordingSources.size(); i++) {
            if (i > 0) json << ",";
            const auto& source = result.recordingSources[i];
            json << "{"
                 << "\"pid\": " << source.pid << ","
                 << "\"process\": \"" << escapeJson(source.name) << "\","
                 << "\"evidence\": [";
            for (size_t j = 0; j < source.evidence.size(); j++) {
                if (j > 0) json << ",";
                json << "\"" << escapeJson(source.evidence[j]) << "\"";
            }
            json << "]}";
        }
        json << "],";
        
        json << "\"virtualCameras\": [";
        for (size_t i = 0; i < result.virtualCameras.size(); i++) {
            if (i > 0) json << ",";
            json << "{\"name\": \"" << escapeJson(result.virtualCameras[i]) << "\"}";
        }
        json << "],";
        
        json << "\"confidence\": " << result.recordingConfidence;
    }
    
    if (result.eventType == "overlay-detected" || result.eventType == "overlay-removed") {
        json << "\"overlayWindows\": [";
        for (size_t i = 0; i < result.overlayWindows.size(); i++) {
            if (i > 0) json << ",";
            const auto& overlay = result.overlayWindows[i];
            json << "{"
                 << "\"pid\": " << overlay.pid << ","
                 << "\"process\": \"" << escapeJson(overlay.processName) << "\","
                 << "\"windowHandle\": \"" << escapeJson(overlay.windowHandle) << "\","
                 << "\"bounds\": {"
                 << "\"x\": " << overlay.bounds.x << ","
                 << "\"y\": " << overlay.bounds.y << ","
                 << "\"w\": " << overlay.bounds.w << ","
                 << "\"h\": " << overlay.bounds.h
                 << "},"
                 << "\"zOrder\": " << overlay.zOrder << ","
                 << "\"alpha\": " << overlay.alpha << ","
                 << "\"extendedStyles\": [";
            for (size_t j = 0; j < overlay.extendedStyles.size(); j++) {
                if (j > 0) json << ",";
                json << "\"" << escapeJson(overlay.extendedStyles[j]) << "\"";
            }
            json << "]}";
        }
        json << "],";
        
        json << "\"confidence\": " << result.overlayConfidence;
    }
    
    json << "}";
    
    return json.str();
}

std::string ScreenWatcher::escapeJson(const std::string& str) {
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

// Platform-specific implementations
#ifdef _WIN32
std::vector<std::string> ScreenWatcher::getProcessModules(DWORD processID) {
    std::vector<std::string> modules;
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (hProcess == nullptr) {
        return modules;
    }
    
    HMODULE hModules[1024];
    DWORD cbNeeded;
    
    if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char moduleName[MAX_PATH];
            if (GetModuleBaseName(hProcess, hModules[i], moduleName, sizeof(moduleName))) {
                modules.push_back(std::string(moduleName));
            }
        }
    }
    
    CloseHandle(hProcess);
    return modules;
}

std::vector<OverlayWindow> ScreenWatcher::enumerateWindowsForOverlays() {
    std::vector<OverlayWindow> overlays;
    
    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto* overlaysPtr = reinterpret_cast<std::vector<OverlayWindow>*>(lParam);
        
        // Check if window is visible
        if (!IsWindowVisible(hwnd)) return TRUE;
        
        // Get extended window style
        LONG_PTR exStyle = GetWindowLongPtr(hwnd, GWL_EXSTYLE);
        
        // Look for overlay characteristics
        bool isLayered = (exStyle & WS_EX_LAYERED) != 0;
        bool isTopMost = (exStyle & WS_EX_TOPMOST) != 0;
        bool isTransparent = (exStyle & WS_EX_TRANSPARENT) != 0;
        
        if (isLayered || isTopMost || isTransparent) {
            // Get process ID
            DWORD processId;
            GetWindowThreadProcessId(hwnd, &processId);
            
            // Get process name
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
            char processName[MAX_PATH] = "Unknown";
            if (hProcess) {
                DWORD size = sizeof(processName);
                GetModuleBaseName(hProcess, nullptr, processName, size);
                CloseHandle(hProcess);
            }
            
            // Create overlay window info
            char handleStr[32];
            sprintf_s(handleStr, "0x%p", hwnd);
            
            OverlayWindow overlay(handleStr, processId, processName);
            
            // Get window bounds
            RECT rect;
            if (GetWindowRect(hwnd, &rect)) {
                overlay.bounds.x = rect.left;
                overlay.bounds.y = rect.top;
                overlay.bounds.w = rect.right - rect.left;
                overlay.bounds.h = rect.bottom - rect.top;
            }
            
            // Add style information
            if (isLayered) overlay.extendedStyles.push_back("WS_EX_LAYERED");
            if (isTopMost) overlay.extendedStyles.push_back("WS_EX_TOPMOST");
            if (isTransparent) overlay.extendedStyles.push_back("WS_EX_TRANSPARENT");
            
            // Try to get alpha value for layered windows
            BYTE alpha;
            COLORREF colorKey;
            DWORD flags;
            if (isLayered && GetLayeredWindowAttributes(hwnd, &colorKey, &alpha, &flags)) {
                overlay.alpha = alpha / 255.0;
            }
            
            overlaysPtr->push_back(overlay);
        }
        
        return TRUE;
    }, reinterpret_cast<LPARAM>(&overlays));
    
    return overlays;
}

std::vector<std::string> ScreenWatcher::enumerateVirtualCameras() {
    std::vector<std::string> virtualCameras;
    
    // TODO: Implement DirectShow/Media Foundation device enumeration
    // This would enumerate video capture devices and identify virtual ones
    // by checking device names/vendor strings
    
    return virtualCameras;
}

#elif __APPLE__

std::vector<std::string> ScreenWatcher::getProcessLibraries(int pid) {
    std::vector<std::string> libraries;
    
    try {
        // Get task for process (this may require elevated privileges)
        task_t task;
        kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
        if (kr != KERN_SUCCESS) {
            // Fallback: try to get process path and infer likely libraries
            char pathBuffer[PROC_PIDPATHINFO_MAXSIZE];
            if (proc_pidpath(pid, pathBuffer, sizeof(pathBuffer)) > 0) {
                std::string processPath(pathBuffer);
                
                // Check if process is likely using graphics/media frameworks
                if (processPath.find("OBS") != std::string::npos ||
                    processPath.find("QuickTime") != std::string::npos ||
                    processPath.find("Camtasia") != std::string::npos) {
                    libraries.push_back("AVFoundation");
                    libraries.push_back("CoreMedia");
                }
                
                // Check for system capture apps
                if (processPath.find("screencapture") != std::string::npos ||
                    processPath.find("Screenshot") != std::string::npos) {
                    libraries.push_back("ScreenCaptureKit");
                    libraries.push_back("CoreGraphics");
                }
            }
            return libraries;
        }
        
        // Enumerate loaded dylibs (simplified approach)
        vm_address_t address = 0;
        vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        
        while (true) {
            mach_port_t object_name;
            kr = vm_region_64(task, &address, &size, VM_REGION_BASIC_INFO_64,
                             (vm_region_info_t)&info, &count, &object_name);
            
            if (kr != KERN_SUCCESS) break;
            
            // Check if this region contains executable code
            if (info.protection & VM_PROT_EXECUTE) {
                // Make educated guesses based on address ranges for system frameworks
                if ((address & 0xFFFF000000000000ULL) == 0x7FFF000000000000ULL) {
                    uint64_t offset = address & 0xFFFFFFFFULL;
                    if (offset < 0x10000000) {
                        libraries.push_back("AVFoundation");
                    } else if (offset < 0x20000000) {
                        libraries.push_back("CoreGraphics");
                    } else if (offset < 0x30000000) {
                        libraries.push_back("CoreMedia");
                    }
                }
            }
            
            address += size;
        }
        
        // Clean up
        mach_port_deallocate(mach_task_self(), task);
        
    } catch (...) {
        // Silently handle errors - library enumeration is best-effort
    }
    
    return libraries;
}

std::vector<OverlayWindow> ScreenWatcher::enumerateWindowsForOverlays() {
    std::vector<OverlayWindow> overlays;
    
    try {
        // Get list of all windows
        CFArrayRef windowList = CGWindowListCopyWindowInfo(
            kCGWindowListOptionOnScreenOnly | kCGWindowListExcludeDesktopElements,
            kCGNullWindowID
        );
        
        if (!windowList) return overlays;
        
        CFIndex count = CFArrayGetCount(windowList);
        
        for (CFIndex i = 0; i < count; i++) {
            CFDictionaryRef window = (CFDictionaryRef)CFArrayGetValueAtIndex(windowList, i);
            
            // Get window level
            CFNumberRef levelRef = (CFNumberRef)CFDictionaryGetValue(window, kCGWindowLayer);
            int windowLevel = 0;
            if (levelRef) {
                CFNumberGetValue(levelRef, kCFNumberIntType, &windowLevel);
            }
            
            // Get window alpha
            CFNumberRef alphaRef = (CFNumberRef)CFDictionaryGetValue(window, kCGWindowAlpha);
            double alpha = 1.0;
            if (alphaRef) {
                CFNumberGetValue(alphaRef, kCFNumberDoubleType, &alpha);
            }
            
            // Check for overlay characteristics
            bool isHighLevel = windowLevel > 0; // Normal windows are at level 0
            bool isTransparent = alpha < 1.0;
            bool isSuspiciousSize = false;
            
            // Get window bounds
            CFDictionaryRef boundsDict = (CFDictionaryRef)CFDictionaryGetValue(window, kCGWindowBounds);
            CGRect bounds = CGRectZero;
            if (boundsDict) {
                CGRectMakeWithDictionaryRepresentation(boundsDict, &bounds);
                
                // Check if window covers significant screen area
                CGRect screenBounds = CGDisplayBounds(CGMainDisplayID());
                double coverage = (bounds.size.width * bounds.size.height) / 
                                (screenBounds.size.width * screenBounds.size.height);
                isSuspiciousSize = coverage > 0.5; // Covers more than half the screen
            }
            
            // Get process info first to filter out false positives
            CFNumberRef pidRef = (CFNumberRef)CFDictionaryGetValue(window, kCGWindowOwnerPID);
            int pid = 0;
            if (pidRef) {
                CFNumberGetValue(pidRef, kCFNumberIntType, &pid);
            }
            
            // Get process name using more robust method
            std::string processName = "Unknown App";
            std::string processPath;
            if (pid > 0) {
                processName = getProcessNameForPID(pid);
                char pathBuffer[PROC_PIDPATHINFO_MAXSIZE];
                if (proc_pidpath(pid, pathBuffer, sizeof(pathBuffer)) > 0) {
                    processPath = std::string(pathBuffer);
                }
            }
            
            // Filter out known false positives
            std::string procName(processName);
            std::transform(procName.begin(), procName.end(), procName.begin(), ::tolower);
            
            bool isSystemProcess = (
                procName.find("windowserver") != std::string::npos ||
                procName.find("dock") != std::string::npos ||
                procName.find("finder") != std::string::npos ||
                procName.find("spotlight") != std::string::npos ||
                procName.find("controlcenter") != std::string::npos ||
                procName.find("menubar") != std::string::npos ||
                procName.find("notificationcenter") != std::string::npos ||
                procName.find("systemuiserver") != std::string::npos ||
                procName.find("loginwindow") != std::string::npos
            );
            
            bool isWhitelistedApp = (
                procName.find("docker") != std::string::npos ||
                procName.find("dbngin") != std::string::npos ||
                procName.find("code") != std::string::npos ||
                procName.find("vscode") != std::string::npos ||
                procName.find("terminal") != std::string::npos ||
                procName.find("iterm") != std::string::npos ||
                procName.find("chrome") != std::string::npos ||
                procName.find("firefox") != std::string::npos ||
                procName.find("safari") != std::string::npos ||
                procName.find("postman") != std::string::npos ||
                procName.find("datagrip") != std::string::npos ||
                procName.find("intellij") != std::string::npos ||
                procName.find("webstorm") != std::string::npos ||
                procName.find("pycharm") != std::string::npos ||
                procName.find("atom") != std::string::npos ||
                procName.find("sublime") != std::string::npos ||
                procName.find("slack") != std::string::npos ||
                procName.find("discord") != std::string::npos ||
                procName.find("teams") != std::string::npos ||
                procName.find("zoom") != std::string::npos ||
                processPath.find("Applications") != std::string::npos ||
                processPath.find("/usr/") != std::string::npos ||
                processPath.find("/System/") != std::string::npos
            );
            
            // Only flag windows that are truly suspicious overlays
            bool isSuspiciousOverlay = (
                (isHighLevel && windowLevel > 50) || // Very high window levels only
                (isTransparent && alpha < 0.8 && isSuspiciousSize) // Highly transparent large windows
            );
            
            // Skip if it's a system process, whitelisted app, or not truly suspicious
            if (isSystemProcess || isWhitelistedApp || !isSuspiciousOverlay) {
                continue;
            }
            
            // Get window ID
            CFNumberRef windowIdRef = (CFNumberRef)CFDictionaryGetValue(window, kCGWindowNumber);
            uint32_t windowId = 0;
            if (windowIdRef) {
                CFNumberGetValue(windowIdRef, kCFNumberIntType, &windowId);
            }
            
            // Create overlay window info
            char handleStr[32];
            snprintf(handleStr, sizeof(handleStr), "0x%x", windowId);
            
            OverlayWindow overlay(handleStr, pid, processName);
            overlay.bounds.x = (int)bounds.origin.x;
            overlay.bounds.y = (int)bounds.origin.y;
            overlay.bounds.w = (int)bounds.size.width;
            overlay.bounds.h = (int)bounds.size.height;
            overlay.zOrder = windowLevel;
            overlay.alpha = alpha;
            
            // Add style information based on characteristics
            if (isHighLevel) {
                overlay.extendedStyles.push_back("HIGH_WINDOW_LEVEL");
            }
            if (isTransparent) {
                overlay.extendedStyles.push_back("TRANSPARENT");
            }
            if (isSuspiciousSize) {
                overlay.extendedStyles.push_back("LARGE_COVERAGE");
            }
            
            overlays.push_back(overlay);
        }
        
        CFRelease(windowList);
        
    } catch (...) {
        // Handle errors silently - window enumeration is best-effort
    }
    
    return overlays;
}

std::vector<std::string> ScreenWatcher::enumerateVirtualCameras() {
    std::vector<std::string> virtualCameras;
    
    // Use a simpler approach - look for common virtual camera indicators
    // in system process list and known locations
    
    // Check for common virtual camera processes
    std::vector<std::string> vcamProcesses = {
        "OBS Virtual Camera",
        "Snap Camera", 
        "mmhmm",
        "Loom",
        "CamTwist",
        "ManyCam",
        "Reincubate Camo"
    };
    
    auto processes = getRunningProcesses();
    for (const auto& process : processes) {
        for (const auto& vcamProcess : vcamProcesses) {
            if (process.name.find(vcamProcess) != std::string::npos ||
                process.path.find(vcamProcess) != std::string::npos) {
                
                // If we find the process, assume the virtual camera exists
                virtualCameras.push_back(vcamProcess + " (detected via process)");
                break;
            }
        }
    }
    
    return virtualCameras;
}

std::vector<ScreenSharingSession> ScreenWatcher::detectMacOSScreenCaptureKit() {
    std::vector<ScreenSharingSession> sessions;

    @autoreleasepool {
        // Check if ScreenCaptureKit is available (macOS 12.3+)
        if (@available(macOS 12.3, *)) {
            // Check for active ScreenCaptureKit sessions by examining processes with screen capture capabilities
            std::vector<ProcessInfo> processes = getRunningProcesses();

            for (const auto& process : processes) {
                bool hasScreenCaptureKit = false;

                // Filter out system and legitimate processes first
                std::string lowerName = process.name;
                std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

                // Skip system processes and legitimate apps that commonly use ScreenCaptureKit
                bool isSystemOrLegitimate = (
                    lowerName.find("windowserver") != std::string::npos ||
                    lowerName.find("screensaverengine") != std::string::npos ||
                    lowerName.find("loginwindow") != std::string::npos ||
                    lowerName.find("systemuiserver") != std::string::npos ||
                    lowerName.find("controlcenter") != std::string::npos ||
                    lowerName.find("dock") != std::string::npos ||
                    lowerName.find("finder") != std::string::npos ||
                    lowerName.find("spotlight") != std::string::npos ||
                    lowerName.find("menubar") != std::string::npos ||
                    lowerName.find("notificationcenter") != std::string::npos ||
                    lowerName.find("quicktime") != std::string::npos ||
                    lowerName.find("screenshot") != std::string::npos ||
                    lowerName.find("magnifier") != std::string::npos ||
                    lowerName.find("accessibility") != std::string::npos ||
                    lowerName.find("voiceover") != std::string::npos ||
                    lowerName.find("coreaudiod") != std::string::npos ||
                    lowerName.find("kernel_task") != std::string::npos ||
                    lowerName.find("launchd") != std::string::npos ||
                    process.path.find("/System/") != std::string::npos ||
                    process.path.find("/usr/libexec/") != std::string::npos ||
                    process.path.find("/usr/sbin/") != std::string::npos
                );

                if (isSystemOrLegitimate) {
                    continue; // Skip system processes
                }

                // Check loaded libraries for ScreenCaptureKit
                std::vector<std::string> libraries = getProcessLibraries(process.pid);
                for (const auto& lib : libraries) {
                    std::string lowerLib = lib;
                    std::transform(lowerLib.begin(), lowerLib.end(), lowerLib.begin(), ::tolower);

                    if (lowerLib.find("screencapturekit") != std::string::npos ||
                        lowerLib.find("scstreamconfiguration") != std::string::npos ||
                        lowerLib.find("sccontentfilter") != std::string::npos) {
                        hasScreenCaptureKit = true;
                        break;
                    }
                }

                if (hasScreenCaptureKit) {
                    // Additional validation: Check if process is actually doing suspicious screen capture
                    bool isSuspiciousCapture = false;

                    // Look for screen sharing/recording patterns
                    if (lowerName.find("zoom") != std::string::npos ||
                        lowerName.find("teams") != std::string::npos ||
                        lowerName.find("meet") != std::string::npos ||
                        lowerName.find("webex") != std::string::npos ||
                        lowerName.find("obs") != std::string::npos ||
                        lowerName.find("screencast") != std::string::npos ||
                        lowerName.find("record") != std::string::npos ||
                        lowerName.find("capture") != std::string::npos ||
                        lowerName.find("vnc") != std::string::npos ||
                        lowerName.find("teamviewer") != std::string::npos ||
                        lowerName.find("anydesk") != std::string::npos) {
                        isSuspiciousCapture = true;
                    }

                    // Only report if it's actually suspicious
                    if (isSuspiciousCapture) {
                        ScreenSharingSession session;
                        session.method = ScreenSharingMethod::SCREENCAPTUREKIT;
                        session.processName = process.name;
                        session.pid = process.pid;
                        session.description = "ScreenCaptureKit API usage detected";
                        session.confidence = 0.9;
                        session.isActive = true;

                        // Only report sessions that meet confidence threshold
                        if (session.confidence >= screenSharingConfidenceThreshold_) {
                            sessions.push_back(session);
                        }
                    }
                }
            }

            // Additional check: Monitor CGS (Core Graphics Services) for screen capture
            // This is a lower-level API that ScreenCaptureKit often uses
            for (const auto& process : processes) {
                std::vector<std::string> libraries = getProcessLibraries(process.pid);
                bool hasCoreGraphicsCapture = false;

                for (const auto& lib : libraries) {
                    std::string lowerLib = lib;
                    std::transform(lowerLib.begin(), lowerLib.end(), lowerLib.begin(), ::tolower);

                    if (lowerLib.find("coregraphics") != std::string::npos &&
                        (lowerLib.find("capture") != std::string::npos ||
                         lowerLib.find("display") != std::string::npos)) {
                        hasCoreGraphicsCapture = true;
                        break;
                    }
                }

                if (hasCoreGraphicsCapture) {
                    // Check if this process isn't already detected via ScreenCaptureKit
                    bool alreadyDetected = false;
                    for (const auto& existing : sessions) {
                        if (existing.pid == process.pid) {
                            alreadyDetected = true;
                            break;
                        }
                    }

                    if (!alreadyDetected) {
                        ScreenSharingSession session;
                        session.method = ScreenSharingMethod::APPLICATION_SHARING;
                        session.processName = process.name;
                        session.pid = process.pid;
                        session.description = "Core Graphics screen capture detected";
                        session.confidence = 0.75;
                        session.isActive = true;

                        // Only report sessions that meet confidence threshold
                        if (session.confidence >= screenSharingConfidenceThreshold_) {
                            sessions.push_back(session);
                        }
                    }
                }
            }
        }
    }

    return sessions;
}

std::vector<ScreenSharingSession> ScreenWatcher::detectMacOSCoreGraphicsCapture() {
    std::vector<ScreenSharingSession> sessions;

    @autoreleasepool {
        // Check for processes using CGDisplayCreateImage or similar APIs
        std::vector<ProcessInfo> processes = getRunningProcesses();

        for (const auto& process : processes) {
            std::vector<std::string> libraries = getProcessLibraries(process.pid);
            bool hasCoreGraphics = false;

            for (const auto& lib : libraries) {
                std::string lowerLib = lib;
                std::transform(lowerLib.begin(), lowerLib.end(), lowerLib.begin(), ::tolower);

                if (lowerLib.find("coregraphics") != std::string::npos ||
                    lowerLib.find("cgdisplay") != std::string::npos ||
                    lowerLib.find("applicationservices") != std::string::npos) {
                    hasCoreGraphics = true;
                    break;
                }
            }

            if (hasCoreGraphics) {
                // Additional check: Look for screen sharing patterns in process name
                std::string lowerName = process.name;
                std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

                std::vector<std::string> screenSharePatterns = {
                    "zoom", "teams", "meet", "webex", "skype", "facetime",
                    "screensharing", "vnc", "teamviewer", "anydesk", "chrome",
                    "firefox", "safari", "edge", "obs", "quicktime"
                };

                bool isLikelyScreenSharing = false;
                for (const auto& pattern : screenSharePatterns) {
                    if (lowerName.find(pattern) != std::string::npos) {
                        isLikelyScreenSharing = true;
                        break;
                    }
                }

                if (isLikelyScreenSharing) {
                    ScreenSharingSession session;
                    session.method = ScreenSharingMethod::APPLICATION_SHARING;
                    session.processName = process.name;
                    session.pid = process.pid;
                    session.description = "Core Graphics screen capture in suspicious process";
                    session.confidence = 0.8;
                    session.isActive = true;

                    // Only report sessions that meet confidence threshold
                    if (session.confidence >= screenSharingConfidenceThreshold_) {
                        sessions.push_back(session);
                    }
                }
            }
        }
    }

    return sessions;
}

bool ScreenWatcher::isScreenCaptureKitActive() {
    auto sessions = detectMacOSScreenCaptureKit();
    return !sessions.empty();
}

std::vector<ScreenSharingSession> ScreenWatcher::scanMacOSBrowserScreenSharing() {
    std::vector<ScreenSharingSession> sessions;
    std::vector<ProcessInfo> processes = getRunningProcesses();

    // Browser processes to check
    std::vector<std::string> browserPatterns = {
        "chrome", "firefox", "safari", "edge", "opera", "brave", "vivaldi"
    };

    for (const auto& process : processes) {
        std::string lowerName = process.name;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

        bool isBrowser = false;
        for (const auto& pattern : browserPatterns) {
            if (lowerName.find(pattern) != std::string::npos) {
                isBrowser = true;
                break;
            }
        }

        if (isBrowser) {
            // Check for WebRTC and screen sharing indicators in loaded libraries
            std::vector<std::string> libraries = getProcessLibraries(process.pid);
            bool hasWebRTC = false;

            for (const auto& lib : libraries) {
                std::string lowerLib = lib;
                std::transform(lowerLib.begin(), lowerLib.end(), lowerLib.begin(), ::tolower);

                if (lowerLib.find("webrtc") != std::string::npos ||
                    lowerLib.find("screenshare") != std::string::npos ||
                    lowerLib.find("getdisplaymedia") != std::string::npos ||
                    lowerLib.find("mediacapture") != std::string::npos) {
                    hasWebRTC = true;
                    break;
                }
            }

            if (hasWebRTC) {
                ScreenSharingSession session;
                session.method = ScreenSharingMethod::BROWSER_WEBRTC;
                session.processName = process.name;
                session.pid = process.pid;
                session.description = "Browser WebRTC screen sharing detected";
                session.confidence = 0.85;
                session.isActive = true;

                // Only report sessions that meet confidence threshold
                if (session.confidence >= screenSharingConfidenceThreshold_) {
                    sessions.push_back(session);
                }
            }
        }
    }

    return sessions;
}

std::vector<ScreenSharingSession> ScreenWatcher::detectScreenSharingSessions() {
    std::vector<ScreenSharingSession> allSessions;

    // Combine all detection methods
    auto sckSessions = detectMacOSScreenCaptureKit();
    auto cgSessions = detectMacOSCoreGraphicsCapture();
    auto browserSessions = scanMacOSBrowserScreenSharing();

    allSessions.insert(allSessions.end(), sckSessions.begin(), sckSessions.end());
    allSessions.insert(allSessions.end(), cgSessions.begin(), cgSessions.end());
    allSessions.insert(allSessions.end(), browserSessions.begin(), browserSessions.end());

    return allSessions;
}

bool ScreenWatcher::isScreenBeingCaptured() {
    auto sessions = detectScreenSharingSessions();
    return !sessions.empty();
}

double ScreenWatcher::calculateScreenSharingThreatLevel() {
    auto sessions = detectScreenSharingSessions();

    if (sessions.empty()) {
        return 0.0;
    }

    double maxThreat = 0.0;
    for (const auto& session : sessions) {
        switch (session.method) {
            case ScreenSharingMethod::SCREENCAPTUREKIT:
                maxThreat = std::max(maxThreat, 0.95);
                break;
            case ScreenSharingMethod::BROWSER_WEBRTC:
                maxThreat = std::max(maxThreat, 0.9);
                break;
            case ScreenSharingMethod::APPLICATION_SHARING:
                maxThreat = std::max(maxThreat, 0.8);
                break;
            case ScreenSharingMethod::REMOTE_DESKTOP:
                maxThreat = std::max(maxThreat, 1.0);
                break;
            default:
                maxThreat = std::max(maxThreat, 0.7);
                break;
        }
    }

    return maxThreat;
}

#endif