#include "ScreenWatcher.h"
#include <sstream>
#include <iostream>
#include <chrono>
#include <algorithm>
#include <ctime>

#ifdef _WIN32
#include <tlhelp32.h>
#include <psapi.h>
#include <setupapi.h>
#include <devguid.h>
#include <cfgmgr32.h>
#include <dwmapi.h>
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "dwmapi.lib")
#endif

ScreenWatcher::ScreenWatcher() : isRunning(false), checkIntervalMs(3000), 
                                 lastRecordingState_(false), recordingConfidenceThreshold_(0.75), overlayConfidenceThreshold_(0.6), checkCount_(0) {
    std::cout << "[ScreenWatcher] Initialized Windows ScreenWatcher" << std::endl;
    initializeRecordingBlacklist();
}

ScreenWatcher::~ScreenWatcher() {
    if (isRunning) {
        stopWatching();
    }
}

bool ScreenWatcher::startWatching(std::function<void(const std::string&)> callback, int intervalMs) {
    if (isRunning) {
        std::cout << "[ScreenWatcher] Already running" << std::endl;
        return false;
    }
    
    eventCallback = callback;
    checkIntervalMs = intervalMs;
    isRunning = true;
    
    watcherThread = std::thread(&ScreenWatcher::watcherLoop, this);
    
    std::cout << "[ScreenWatcher] Windows ScreenWatcher started" << std::endl;
    return true;
}

void ScreenWatcher::stopWatching() {
    if (!isRunning) return;
    
    isRunning = false;
    
    if (watcherThread.joinable()) {
        watcherThread.join();
    }
    
    std::cout << "[ScreenWatcher] Windows ScreenWatcher stopped" << std::endl;
}

ScreenStatus ScreenWatcher::getCurrentStatus() {
    return detectScreenStatus();
}

bool ScreenWatcher::isPlatformSupported() {
#ifdef _WIN32
    return true;
#else
    return false;
#endif
}

// Windows-specific implementations
#ifdef _WIN32
std::vector<DisplayInfo> ScreenWatcher::getWindowsDisplays() {
    std::vector<DisplayInfo> displays;
    
    DISPLAY_DEVICE dd;
    dd.cb = sizeof(dd);
    
    for (int deviceNum = 0; EnumDisplayDevices(NULL, deviceNum, &dd, 0); deviceNum++) {
        if (!(dd.StateFlags & DISPLAY_DEVICE_ACTIVE)) continue;
        
        DisplayInfo display;
        display.name = std::string(dd.DeviceName);
        display.isPrimary = (dd.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE) != 0;
        display.isExternal = (dd.StateFlags & DISPLAY_DEVICE_REMOVABLE) != 0;
        display.isMirrored = false; // TODO: Implement mirroring detection
        
        DEVMODE dm;
        dm.dmSize = sizeof(dm);
        if (EnumDisplaySettings(dd.DeviceName, ENUM_CURRENT_SETTINGS, &dm)) {
            display.width = dm.dmPelsWidth;
            display.height = dm.dmPelsHeight;
        } else {
            display.width = 0;
            display.height = 0;
        }
        
        displays.push_back(display);
    }
    
    return displays;
}

std::vector<InputDeviceInfo> ScreenWatcher::getWindowsInputDevices() {
    std::vector<InputDeviceInfo> devices;
    
    PRAWINPUTDEVICELIST pRawInputDeviceList;
    UINT uiNumDevices = 0;
    
    // Get number of devices
    if (GetRawInputDeviceList(NULL, &uiNumDevices, sizeof(RAWINPUTDEVICELIST)) != 0) {
        return devices;
    }
    
    // Allocate memory for device list
    pRawInputDeviceList = (PRAWINPUTDEVICELIST)malloc(sizeof(RAWINPUTDEVICELIST) * uiNumDevices);
    if (!pRawInputDeviceList) {
        return devices;
    }
    
    // Get device list
    if (GetRawInputDeviceList(pRawInputDeviceList, &uiNumDevices, sizeof(RAWINPUTDEVICELIST)) != uiNumDevices) {
        free(pRawInputDeviceList);
        return devices;
    }
    
    // Process each device
    for (UINT i = 0; i < uiNumDevices; i++) {
        RID_DEVICE_INFO deviceInfo;
        UINT cbSize = sizeof(deviceInfo);
        deviceInfo.cbSize = cbSize;
        
        if (GetRawInputDeviceInfo(pRawInputDeviceList[i].hDevice, RIDI_DEVICEINFO, &deviceInfo, &cbSize) != cbSize) {
            continue;
        }
        
        // Get device name
        UINT nameSize = 0;
        GetRawInputDeviceInfo(pRawInputDeviceList[i].hDevice, RIDI_DEVICENAME, NULL, &nameSize);
        
        if (nameSize > 0) {
            WCHAR* deviceName = (WCHAR*)malloc(nameSize * sizeof(WCHAR));
            if (deviceName && GetRawInputDeviceInfo(pRawInputDeviceList[i].hDevice, RIDI_DEVICENAME, deviceName, &nameSize) != (UINT)-1) {
                
                InputDeviceInfo device;
                
                // Convert wide string to string
                std::wstring wName(deviceName);
                device.name = std::string(wName.begin(), wName.end());
                
                // Determine device type and external status
                if (deviceInfo.dwType == RIM_TYPEKEYBOARD) {
                    device.type = "keyboard";
                    device.isExternal = isExternalInputDevice(device.name, "keyboard");
                } else if (deviceInfo.dwType == RIM_TYPEMOUSE) {
                    device.type = "mouse";
                    device.isExternal = isExternalInputDevice(device.name, "mouse");
                } else if (deviceInfo.dwType == RIM_TYPEHID) {
                    device.type = "hid";
                    device.isExternal = isExternalInputDevice(device.name, "hid");
                }
                
                // Only include external devices or filter appropriately
                if (device.isExternal || device.type == "keyboard") {
                    devices.push_back(device);
                }
            }
            
            if (deviceName) {
                free(deviceName);
            }
        }
    }
    
    free(pRawInputDeviceList);
    return devices;
}

bool ScreenWatcher::isWindowsMirroring() {
    // TODO: Implement Windows mirroring detection
    return false;
}

bool ScreenWatcher::isWindowsSplitScreen() {
    // TODO: Implement Windows split screen detection
    return false;
}
#endif

ScreenStatus ScreenWatcher::detectScreenStatus() {
    ScreenStatus status;
    
#ifdef _WIN32
    status.displays = getWindowsDisplays();
    status.externalKeyboards = getWindowsInputDevices();
    status.mirroring = isWindowsMirroring();
    status.splitScreen = isWindowsSplitScreen();
    
    // Filter external displays
    for (const auto& display : status.displays) {
        if (display.isExternal) {
            status.externalDisplays.push_back(display);
        }
    }
    
    // Filter external devices (keyboards, mice, etc.)
    for (const auto& device : status.externalKeyboards) {
        if (device.isExternal) {
            status.externalDevices.push_back(device);
        }
    }
    
    status.recordingResult = detectRecordingAndOverlays();
#endif
    
    return status;
}

void ScreenWatcher::watcherLoop() {
    while (isRunning) {
        try {
            ScreenStatus status = getCurrentStatus();
            std::string json = statusToJson(status);
            
            if (eventCallback) {
                eventCallback(json);
            }
        } catch (const std::exception& e) {
            std::cerr << "[ScreenWatcher] Error in watcher loop: " << e.what() << std::endl;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(checkIntervalMs));
    }
}

std::string ScreenWatcher::statusToJson(const ScreenStatus& status) {
    std::stringstream ss;
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    ss << "{";
    ss << "\"mirroring\":" << (status.mirroring ? "true" : "false") << ",";
    ss << "\"splitScreen\":" << (status.splitScreen ? "true" : "false") << ",";
    
    // Display arrays (matching Mac format)
    ss << "\"displays\":[";
    for (size_t i = 0; i < status.displays.size(); i++) {
        if (i > 0) ss << ",";
        ss << "\"" << escapeJson(status.displays[i].name) << "\"";
    }
    ss << "],";
    
    ss << "\"externalDisplays\":[";
    for (size_t i = 0; i < status.externalDisplays.size(); i++) {
        if (i > 0) ss << ",";
        ss << "\"" << escapeJson(status.externalDisplays[i].name) << "\"";
    }
    ss << "],";
    
    ss << "\"externalKeyboards\":[";
    for (size_t i = 0; i < status.externalKeyboards.size(); i++) {
        if (i > 0) ss << ",";
        ss << "\"" << escapeJson(status.externalKeyboards[i].name) << "\"";
    }
    ss << "],";
    
    ss << "\"externalDevices\":[";
    for (size_t i = 0; i < status.externalDevices.size(); i++) {
        if (i > 0) ss << ",";
        ss << "\"" << escapeJson(status.externalDevices[i].name) << "\"";
    }
    ss << "],";
    
    // Module, source, timestamp, count (matching Mac format)
    ss << "\"timestamp\":" << timestamp << ",";
    ss << "\"module\":\"screen-watch\",";
    ss << "\"source\":\"native\",";
    ss << "\"count\":" << (++checkCount_);
    ss << "}";
    
    return ss.str();
}

std::string ScreenWatcher::escapeJson(const std::string& str) {
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

// Recording/Overlay detection methods
RecordingDetectionResult ScreenWatcher::detectRecordingAndOverlays() {
    RecordingDetectionResult result;
    result.isRecording = false;
    result.recordingConfidence = 0.0;
    result.overlayConfidence = 0.0;
    result.eventType = "heartbeat";
    
#ifdef _WIN32
    // TODO: Implement Windows recording detection
    result.recordingSources = detectRecordingProcesses();
    result.virtualCameras = getVirtualCameras();
    result.overlayWindows = getOverlayWindows();
    
    result.recordingConfidence = calculateRecordingConfidence(result.recordingSources, result.virtualCameras);
    result.overlayConfidence = calculateOverlayConfidence(result.overlayWindows);
    
    result.isRecording = (result.recordingConfidence > recordingConfidenceThreshold_) || 
                        (!result.recordingSources.empty() || !result.virtualCameras.empty());
    
    // Determine event type based on state changes
    bool hasOverlays = !result.overlayWindows.empty() && (result.overlayConfidence > overlayConfidenceThreshold_);
    
    if (result.isRecording && !lastRecordingState_) {
        result.eventType = "recording-detected";
    } else if (!result.isRecording && lastRecordingState_) {
        result.eventType = "recording-stopped";  
    } else if (hasOverlays && lastOverlayWindows_.size() < result.overlayWindows.size()) {
        result.eventType = "overlay-detected";
    } else if (!hasOverlays && lastOverlayWindows_.size() > result.overlayWindows.size()) {
        result.eventType = "overlay-cleared";
    }
    
    lastRecordingState_ = result.isRecording;
    lastOverlayWindows_ = result.overlayWindows;
#endif
    
    return result;
}

void ScreenWatcher::setRecordingBlacklist(const std::vector<std::string>& recordingBlacklist) {
    recordingBlacklist_.clear();
    for (const auto& item : recordingBlacklist) {
        recordingBlacklist_.insert(item);
    }
}

std::vector<std::string> ScreenWatcher::getVirtualCameras() {
    std::vector<std::string> cameras;
#ifdef _WIN32
    // TODO: Implement Windows virtual camera detection
#endif
    return cameras;
}

std::vector<OverlayWindow> ScreenWatcher::getOverlayWindows() {
    std::vector<OverlayWindow> overlays;
#ifdef _WIN32
    // TODO: Implement Windows overlay detection
#endif
    return overlays;
}

std::vector<ProcessInfo> ScreenWatcher::detectRecordingProcesses() {
    std::vector<ProcessInfo> recordingProcesses;
#ifdef _WIN32
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return recordingProcesses;
    }
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    
    if (Process32First(hSnapshot, &pe)) {
        do {
            std::string processName(pe.szExeFile);
            std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);
            
            // Check if process is in recording blacklist
            if (recordingBlacklist_.find(processName) != recordingBlacklist_.end() ||
                recordingBlacklist_.find(pe.szExeFile) != recordingBlacklist_.end()) {
                
                ProcessInfo procInfo(pe.th32ProcessID, pe.szExeFile);
                
                // Get process path
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                if (hProcess) {
                    WCHAR processPath[MAX_PATH];
                    DWORD pathSize = MAX_PATH;
                    if (QueryFullProcessImageNameW(hProcess, 0, processPath, &pathSize)) {
                        std::wstring wPath(processPath);
                        procInfo.path = std::string(wPath.begin(), wPath.end());
                    }
                    CloseHandle(hProcess);
                }
                
                // Add evidence
                procInfo.evidence.push_back("blacklist");
                
                recordingProcesses.push_back(procInfo);
            }
            
        } while (Process32Next(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
#endif
    return recordingProcesses;
}

std::vector<OverlayWindow> ScreenWatcher::detectOverlayWindows() {
    return getOverlayWindows();
}

double ScreenWatcher::calculateRecordingConfidence(const std::vector<ProcessInfo>& recordingProcesses, const std::vector<std::string>& virtualCameras) {
    if (recordingProcesses.empty() && virtualCameras.empty()) return 0.0;
    
    double confidence = 0.0;
    confidence += recordingProcesses.size() * 0.4;
    confidence += virtualCameras.size() * 0.3;
    
    return std::min(confidence, 1.0);
}

double ScreenWatcher::calculateOverlayConfidence(const std::vector<OverlayWindow>& overlayWindows) {
    if (overlayWindows.empty()) return 0.0;
    
    double confidence = overlayWindows.size() * 0.3;
    return std::min(confidence, 1.0);
}

void ScreenWatcher::initializeRecordingBlacklist() {
    // Common recording software on Windows
    recordingBlacklist_.insert("obs64.exe");
    recordingBlacklist_.insert("obs32.exe"); 
    recordingBlacklist_.insert("XSplit.Core.exe");
    recordingBlacklist_.insert("Streamlabs OBS.exe");
    recordingBlacklist_.insert("Bandicam.exe");
    recordingBlacklist_.insert("Camtasia.exe");
    recordingBlacklist_.insert("CamtasiaStudio.exe");
    recordingBlacklist_.insert("fraps.exe");
    recordingBlacklist_.insert("Action.exe");
    recordingBlacklist_.insert("nvidia-share.exe");
    recordingBlacklist_.insert("RadeonSoftware.exe");
}

std::string ScreenWatcher::createRecordingOverlayEventJson(const RecordingDetectionResult& result) {
    std::stringstream ss;
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    ss << "{";
    ss << "\"module\":\"recorder-overlay-watch\",";
    ss << "\"eventType\":\"" << escapeJson(result.eventType) << "\",";
    ss << "\"timestamp\":" << timestamp << ",";
    
    // Recording sources
    ss << "\"sources\":[";
    for (size_t i = 0; i < result.recordingSources.size(); i++) {
        if (i > 0) ss << ",";
        ss << "{";
        ss << "\"pid\":" << result.recordingSources[i].pid << ",";
        ss << "\"process\":\"" << escapeJson(result.recordingSources[i].name) << "\",";
        ss << "\"evidence\":[";
        for (size_t j = 0; j < result.recordingSources[i].evidence.size(); j++) {
            if (j > 0) ss << ",";
            ss << "\"" << escapeJson(result.recordingSources[i].evidence[j]) << "\"";
        }
        ss << "]";
        ss << "}";
    }
    ss << "],";
    
    // Virtual cameras
    ss << "\"virtualCameras\":[";
    for (size_t i = 0; i < result.virtualCameras.size(); i++) {
        if (i > 0) ss << ",";
        ss << "{\"name\":\"" << escapeJson(result.virtualCameras[i]) << "\"}";
    }
    ss << "],";
    
    ss << "\"confidence\":" << result.recordingConfidence << ",";
    
    // Overlay windows
    ss << "\"overlayWindows\":[";
    for (size_t i = 0; i < result.overlayWindows.size(); i++) {
        if (i > 0) ss << ",";
        const auto& overlay = result.overlayWindows[i];
        ss << "{";
        ss << "\"pid\":" << overlay.pid << ",";
        ss << "\"process\":\"" << escapeJson(overlay.processName) << "\",";
        ss << "\"windowHandle\":\"" << overlay.windowHandle << "\",";
        ss << "\"bounds\":{";
        ss << "\"x\":" << overlay.bounds.x << ",";
        ss << "\"y\":" << overlay.bounds.y << ",";
        ss << "\"w\":" << overlay.bounds.w << ",";
        ss << "\"h\":" << overlay.bounds.h;
        ss << "},";
        ss << "\"zOrder\":" << overlay.zOrder << ",";
        ss << "\"alpha\":" << overlay.alpha << ",";
        ss << "\"extendedStyles\":[";
        for (size_t j = 0; j < overlay.extendedStyles.size(); j++) {
            if (j > 0) ss << ",";
            ss << "\"" << escapeJson(overlay.extendedStyles[j]) << "\"";
        }
        ss << "]";
        ss << "}";
    }
    ss << "]";
    ss << "}";
    
    return ss.str();
}

#ifdef _WIN32
bool ScreenWatcher::isExternalInputDevice(const std::string& deviceName, const std::string& deviceType) {
    std::string lowerName = deviceName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
    
    // Windows-specific internal device patterns
    static const std::vector<std::string> internalPatterns = {
        "hid-compliant", "system", "terminal server", "rdp", "virtual", 
        "ps/2", "standard", "generic", "microsoft", "windows",
        "built-in", "internal", "laptop", "touchpad", "trackpad"
    };
    
    for (const auto& pattern : internalPatterns) {
        if (lowerName.find(pattern) != std::string::npos) {
            return false;  // Internal device
        }
    }
    
    // Device names shorter than 5 characters are usually system devices
    if (deviceName.length() < 5) {
        return false;
    }
    
    return true;  // Likely external
}
#endif