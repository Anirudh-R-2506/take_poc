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
#include <dshow.h>
#include <comdef.h>
#include <map>
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "strmiids.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#endif

ScreenWatcher::ScreenWatcher() : isRunning(false), checkIntervalMs(3000),
                                 lastRecordingState_(false), recordingConfidenceThreshold_(0.75), overlayConfidenceThreshold_(0.6), checkCount_(0) {
    initializeRecordingBlacklist();
}

ScreenWatcher::~ScreenWatcher() {
    if (isRunning) {
        stopWatching();
    }
}

bool ScreenWatcher::startWatching(std::function<void(const std::string&)> callback, int intervalMs) {
    if (isRunning) {
        return false;
    }

    eventCallback = callback;
    checkIntervalMs = intervalMs;
    isRunning = true;

    watcherThread = std::thread(&ScreenWatcher::watcherLoop, this);

    return true;
}

void ScreenWatcher::stopWatching() {
    if (!isRunning) return;

    isRunning = false;

    if (watcherThread.joinable()) {
        watcherThread.join();
    }
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
        display.isMirrored = false;

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

    if (GetRawInputDeviceList(NULL, &uiNumDevices, sizeof(RAWINPUTDEVICELIST)) != 0) {
        return devices;
    }

    pRawInputDeviceList = (PRAWINPUTDEVICELIST)malloc(sizeof(RAWINPUTDEVICELIST) * uiNumDevices);
    if (!pRawInputDeviceList) {
        return devices;
    }

    if (GetRawInputDeviceList(pRawInputDeviceList, &uiNumDevices, sizeof(RAWINPUTDEVICELIST)) != uiNumDevices) {
        free(pRawInputDeviceList);
        return devices;
    }

    for (UINT i = 0; i < uiNumDevices; i++) {
        RID_DEVICE_INFO deviceInfo;
        UINT cbSize = sizeof(deviceInfo);
        deviceInfo.cbSize = cbSize;

        if (GetRawInputDeviceInfo(pRawInputDeviceList[i].hDevice, RIDI_DEVICEINFO, &deviceInfo, &cbSize) != cbSize) {
            continue;
        }

        UINT nameSize = 0;
        GetRawInputDeviceInfo(pRawInputDeviceList[i].hDevice, RIDI_DEVICENAME, NULL, &nameSize);

        if (nameSize > 0) {
            WCHAR* deviceName = (WCHAR*)malloc(nameSize * sizeof(WCHAR));
            if (deviceName && GetRawInputDeviceInfo(pRawInputDeviceList[i].hDevice, RIDI_DEVICENAME, deviceName, &nameSize) != (UINT)-1) {

                InputDeviceInfo device;

                std::wstring wName(deviceName);
                device.name = std::string(wName.begin(), wName.end());

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
    UINT32 pathCount = 16;
    UINT32 modeCount = 32;

    LONG result = GetDisplayConfigBufferSizes(QDC_ONLY_ACTIVE_PATHS, &pathCount, &modeCount);
    if (result != ERROR_SUCCESS || pathCount == 0) {
        return false;
    }

    std::vector<DISPLAYCONFIG_PATH_INFO> paths(pathCount);
    std::vector<DISPLAYCONFIG_MODE_INFO> modes(modeCount);

    result = QueryDisplayConfig(QDC_ONLY_ACTIVE_PATHS, &pathCount, paths.data(),
                               &modeCount, modes.data(), nullptr);
    if (result != ERROR_SUCCESS) {
        return false;
    }

    std::map<UINT32, int> sourceModeCount;
    for (UINT32 i = 0; i < pathCount; i++) {
        if (paths[i].flags & DISPLAYCONFIG_PATH_ACTIVE) {
            sourceModeCount[paths[i].sourceInfo.modeInfoIdx]++;
        }
    }

    for (const auto& pair : sourceModeCount) {
        if (pair.second > 1) {
            return true;
        }
    }

    return false;
}

bool ScreenWatcher::isWindowsSplitScreen() {
    struct WindowInfo {
        HWND hwnd;
        RECT rect;
        bool isMaximized;
    };

    std::vector<WindowInfo> windows;

    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto* windowsPtr = reinterpret_cast<std::vector<WindowInfo>*>(lParam);

        if (!IsWindowVisible(hwnd) || IsIconic(hwnd)) {
            return TRUE;
        }

        WINDOWPLACEMENT wp;
        wp.length = sizeof(WINDOWPLACEMENT);
        if (!GetWindowPlacement(hwnd, &wp)) {
            return TRUE;
        }

        if (wp.showCmd == SW_SHOWMAXIMIZED || wp.showCmd == SW_SHOWNORMAL) {
            RECT rect;
            if (GetWindowRect(hwnd, &rect)) {
                WindowInfo info;
                info.hwnd = hwnd;
                info.rect = rect;
                info.isMaximized = (wp.showCmd == SW_SHOWMAXIMIZED);

                HMONITOR hMon = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
                MONITORINFO monInfo;
                monInfo.cbSize = sizeof(MONITORINFO);

                if (GetMonitorInfo(hMon, &monInfo)) {
                    RECT workArea = monInfo.rcWork;

                    int windowWidth = rect.right - rect.left;
                    int windowHeight = rect.bottom - rect.top;
                    int workWidth = workArea.right - workArea.left;
                    int workHeight = workArea.bottom - workArea.top;

                    if (abs(windowWidth * 2 - workWidth) < 10 && abs(windowHeight - workHeight) < 10) {
                        windowsPtr->push_back(info);
                    }
                }
            }
        }

        return TRUE;
    }, reinterpret_cast<LPARAM>(&windows));

    return windows.size() >= 2;
}
#endif

ScreenStatus ScreenWatcher::detectScreenStatus() {
    ScreenStatus status;

#ifdef _WIN32
    status.displays = getWindowsDisplays();
    status.externalKeyboards = getWindowsInputDevices();
    status.mirroring = isWindowsMirroring();
    status.splitScreen = isWindowsSplitScreen();

    for (const auto& display : status.displays) {
        if (display.isExternal) {
            status.externalDisplays.push_back(display);
        }
    }

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
        } catch (const std::exception&) {
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

RecordingDetectionResult ScreenWatcher::detectRecordingAndOverlays() {
    RecordingDetectionResult result;
    result.isRecording = false;
    result.recordingConfidence = 0.0;
    result.overlayConfidence = 0.0;
    result.eventType = "heartbeat";

#ifdef _WIN32
    result.recordingSources = detectRecordingProcesses();
    result.virtualCameras = getVirtualCameras();
    result.overlayWindows = getOverlayWindows();

    result.recordingConfidence = calculateRecordingConfidence(result.recordingSources, result.virtualCameras);
    result.overlayConfidence = calculateOverlayConfidence(result.overlayWindows);

    result.isRecording = (result.recordingConfidence > recordingConfidenceThreshold_) ||
                        (!result.recordingSources.empty() || !result.virtualCameras.empty());

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
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        return cameras;
    }

    ICreateDevEnum* pDevEnum = nullptr;
    IEnumMoniker* pEnum = nullptr;

    do {
        hr = CoCreateInstance(CLSID_SystemDeviceEnum, nullptr, CLSCTX_INPROC_SERVER,
                             IID_PPV_ARGS(&pDevEnum));
        if (FAILED(hr)) break;

        hr = pDevEnum->CreateClassEnumerator(CLSID_VideoInputDeviceCategory, &pEnum, 0);
        if (FAILED(hr) || hr == S_FALSE) break;

        IMoniker* pMoniker = nullptr;
        while (pEnum->Next(1, &pMoniker, nullptr) == S_OK) {
            IPropertyBag* pPropBag;
            hr = pMoniker->BindToStorage(0, 0, IID_PPV_ARGS(&pPropBag));
            if (SUCCEEDED(hr)) {
                VARIANT var;
                VariantInit(&var);

                hr = pPropBag->Read(L"FriendlyName", &var, 0);
                if (SUCCEEDED(hr)) {
                    std::wstring deviceNameW(var.bstrVal);
                    std::string deviceName = sanitizeDeviceName(std::string(deviceNameW.begin(), deviceNameW.end()));

                    std::string lowerName = deviceName;
                    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

                    if (lowerName.find("obs") != std::string::npos ||
                        lowerName.find("virtual") != std::string::npos ||
                        lowerName.find("streamlabs") != std::string::npos ||
                        lowerName.find("xsplit") != std::string::npos ||
                        lowerName.find("manycam") != std::string::npos ||
                        lowerName.find("droidcam") != std::string::npos) {
                        cameras.push_back(deviceName);
                    }
                }
                VariantClear(&var);
                pPropBag->Release();
            }
            pMoniker->Release();
        }
    } while (false);

    if (pEnum) pEnum->Release();
    if (pDevEnum) pDevEnum->Release();
    CoUninitialize();
#endif
    return cameras;
}

std::vector<OverlayWindow> ScreenWatcher::getOverlayWindows() {
    std::vector<OverlayWindow> overlays;
#ifdef _WIN32
    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto* overlaysPtr = reinterpret_cast<std::vector<OverlayWindow>*>(lParam);

        if (!IsWindowVisible(hwnd)) {
            return TRUE;
        }

        DWORD style = GetWindowLong(hwnd, GWL_STYLE);
        DWORD exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);

        bool isLayered = (exStyle & WS_EX_LAYERED) != 0;
        bool isTopmost = (exStyle & WS_EX_TOPMOST) != 0;
        bool isToolWindow = (exStyle & WS_EX_TOOLWINDOW) != 0;

        if (isLayered || isTopmost || isToolWindow) {
            OverlayWindow overlay;

            DWORD processId;
            GetWindowThreadProcessId(hwnd, &processId);
            overlay.pid = processId;

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
            if (hProcess) {
                wchar_t processPath[MAX_PATH];
                DWORD size = MAX_PATH;
                if (QueryFullProcessImageNameW(hProcess, 0, processPath, &size)) {
                    std::wstring pathW(processPath);
                    std::string path(pathW.begin(), pathW.end());

                    size_t lastSlash = path.find_last_of("\\");
                    overlay.processName = (lastSlash != std::string::npos) ?
                                         path.substr(lastSlash + 1) : path;
                }
                CloseHandle(hProcess);
            }

            RECT rect;
            if (GetWindowRect(hwnd, &rect)) {
                overlay.bounds.x = rect.left;
                overlay.bounds.y = rect.top;
                overlay.bounds.w = rect.right - rect.left;
                overlay.bounds.h = rect.bottom - rect.top;
            }

            std::ostringstream oss;
            oss << "0x" << std::hex << reinterpret_cast<uintptr_t>(hwnd);
            overlay.windowHandle = oss.str();

            // Calculate confidence based on multiple suspicious characteristics
            overlay.confidence = 0.0;

            // Base scoring for window properties
            if (isLayered) overlay.confidence += 0.25;      // Layered windows can be transparent overlays
            if (isTopmost) overlay.confidence += 0.30;      // Always-on-top is highly suspicious
            if (isToolWindow) overlay.confidence += 0.15;   // Tool windows are often overlays

            // Enhanced transparency analysis
            if (isLayered) {
                COLORREF colorKey;
                BYTE alpha;
                DWORD flags;
                if (GetLayeredWindowAttributes(hwnd, &colorKey, &alpha, &flags)) {
                    overlay.alpha = alpha / 255.0;
                    if (alpha < 255 && alpha > 0) {
                        // Semi-transparent windows are very suspicious
                        float transparencyScore = (255.0f - alpha) / 255.0f;
                        overlay.confidence += transparencyScore * 0.35;
                    }
                    if (flags & LWA_COLORKEY) {
                        // Color key transparency (chroma key) is suspicious
                        overlay.confidence += 0.20;
                    }
                }
            }

            // Window size analysis - small overlays are more suspicious
            int windowArea = overlay.bounds.w * overlay.bounds.h;
            if (windowArea > 0 && windowArea < 10000) {  // Very small windows (< 100x100)
                overlay.confidence += 0.15;
            }

            // Position analysis - windows at screen edges or corners are suspicious
            int screenWidth = GetSystemMetrics(SM_CXSCREEN);
            int screenHeight = GetSystemMetrics(SM_CYSCREEN);
            bool atEdge = (overlay.bounds.x <= 5 || overlay.bounds.y <= 5 ||
                          overlay.bounds.x + overlay.bounds.w >= screenWidth - 5 ||
                          overlay.bounds.y + overlay.bounds.h >= screenHeight - 5);
            if (atEdge && windowArea < 50000) {  // Small windows at screen edges
                overlay.confidence += 0.10;
            }

            // Process name analysis for known suspicious patterns
            std::string lowerProcessName = overlay.processName;
            std::transform(lowerProcessName.begin(), lowerProcessName.end(),
                          lowerProcessName.begin(), ::tolower);

            // Check for suspicious process name patterns
            std::vector<std::string> suspiciousPatterns = {
                "cheat", "hack", "overlay", "inject", "hook", "bot",
                "trainer", "mod", "exploit", "bypass", "assist"
            };

            for (const auto& pattern : suspiciousPatterns) {
                if (lowerProcessName.find(pattern) != std::string::npos) {
                    overlay.confidence += 0.40;  // Very high confidence for known patterns
                    break;
                }
            }

            // Additional window style analysis
            LONG_PTR exStyle = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
            if (exStyle & WS_EX_TRANSPARENT) {
                overlay.confidence += 0.25;  // Click-through windows are suspicious
            }
            if (exStyle & WS_EX_NOACTIVATE) {
                overlay.confidence += 0.15;  // Non-activating windows are suspicious
            }

            // Cap confidence at 1.0
            overlay.confidence = std::min(overlay.confidence, 1.0);

            // Only include overlays with sufficient confidence (adjustable threshold)
            double confidenceThreshold = 0.3;  // Lower threshold to catch more potential overlays
            if (overlay.confidence >= confidenceThreshold) {
                overlaysPtr->push_back(overlay);
            }
        }

        return TRUE;
    }, reinterpret_cast<LPARAM>(&overlays));
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

            if (recordingBlacklist_.find(processName) != recordingBlacklist_.end() ||
                recordingBlacklist_.find(pe.szExeFile) != recordingBlacklist_.end()) {

                ProcessInfo procInfo(pe.th32ProcessID, pe.szExeFile);

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

    double totalConfidence = 0.0;
    double highestConfidence = 0.0;
    int highConfidenceCount = 0;

    // Analyze individual overlay confidences
    for (const auto& overlay : overlayWindows) {
        totalConfidence += overlay.confidence;
        highestConfidence = std::max(highestConfidence, overlay.confidence);

        if (overlay.confidence >= 0.7) {
            highConfidenceCount++;
        }
    }

    // Calculate overall confidence based on multiple factors
    double averageConfidence = totalConfidence / overlayWindows.size();

    // Base confidence from average individual scores
    double overallConfidence = averageConfidence * 0.6;

    // Boost confidence for multiple overlays (potential coordinated attack)
    if (overlayWindows.size() > 1) {
        overallConfidence += (overlayWindows.size() - 1) * 0.15;
    }

    // Significant boost for high-confidence overlays
    if (highestConfidence >= 0.8) {
        overallConfidence += 0.25;
    }

    // Additional boost for multiple high-confidence overlays
    if (highConfidenceCount > 1) {
        overallConfidence += highConfidenceCount * 0.1;
    }

    return std::min(overallConfidence, 1.0);
}

void ScreenWatcher::initializeRecordingBlacklist() {
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

    ss << "\"virtualCameras\":[";
    for (size_t i = 0; i < result.virtualCameras.size(); i++) {
        if (i > 0) ss << ",";
        ss << "{\"name\":\"" << escapeJson(result.virtualCameras[i]) << "\"}";
    }
    ss << "],";

    ss << "\"confidence\":" << result.recordingConfidence << ",";

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

    static const std::vector<std::string> internalPatterns = {
        "hid-compliant", "system", "terminal server", "rdp", "virtual",
        "ps/2", "standard", "generic", "microsoft", "windows",
        "built-in", "internal", "laptop", "touchpad", "trackpad"
    };

    for (const auto& pattern : internalPatterns) {
        if (lowerName.find(pattern) != std::string::npos) {
            return false;
        }
    }

    if (deviceName.length() < 5) {
        return false;
    }

    return true;
}
#endif