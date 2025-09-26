#include "ProcessWatcher.h"
#include <sstream>
#include <ctime>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <dshow.h>
#include <comdef.h>
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "strmiids.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

static std::string WideStringToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string result(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], size, nullptr, nullptr);
    return result;
}
#elif __APPLE__
#include <libproc.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <cstring>
#include <mach/mach.h>
#include <CoreGraphics/CoreGraphics.h>
#include <dlfcn.h>
#endif

ProcessWatcher::ProcessWatcher() : running_(false), counter_(0), lastDetectionState_(false),
                                   lastRecordingState_(false), recordingConfidenceThreshold_(0.75), overlayConfidenceThreshold_(0.6) {
    blacklist_.insert("chrome");
    blacklist_.insert("chrome.exe");
    blacklist_.insert("Google Chrome");
    blacklist_.insert("Google Chrome Helper");
    blacklist_.insert("Google Chrome Helper (Renderer)");
    blacklist_.insert("Chromium");
    blacklist_.insert("chromium");

    InitializeRecordingBlacklist();
}

ProcessWatcher::~ProcessWatcher() {
    Stop();
}

void ProcessWatcher::Start(Napi::Function callback, int intervalMs) {
    if (running_.load()) {
        return;
    }

    running_.store(true);
    intervalMs_ = intervalMs;
    callback_ = Napi::Persistent(callback);

    tsfn_ = Napi::ThreadSafeFunction::New(
        callback.Env(),
        callback,
        "ProcessWatcher",
        0,
        1,
        [this](Napi::Env) {
        }
    );

    worker_thread_ = std::thread([this]() {
        WatcherLoop();
    });
}

void ProcessWatcher::Stop() {
    if (!running_.load()) {
        return;
    }

    running_.store(false);

    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }

    if (tsfn_) {
        tsfn_.Release();
    }

    callback_.Reset();
}

void ProcessWatcher::SetBlacklist(const std::vector<std::string>& blacklist) {
    blacklist_.clear();
    for (const auto& item : blacklist) {
        blacklist_.insert(item);
    }
}

void ProcessWatcher::SetRecordingBlacklist(const std::vector<std::string>& recordingBlacklist) {
    recordingBlacklist_.clear();
    for (const auto& item : recordingBlacklist) {
        recordingBlacklist_.insert(item);
    }
}

bool ProcessWatcher::IsRunning() const {
    return running_.load();
}

std::vector<ProcessInfo> ProcessWatcher::GetProcessSnapshot() {
    return GetRunningProcesses();
}

void ProcessWatcher::WatcherLoop() {
    while (running_.load()) {
        try {
            auto processes = GetRunningProcesses();
            auto blacklisted = FilterBlacklistedProcesses(processes);

            bool currentState = !blacklisted.empty();

            if (currentState != lastDetectionState_ ||
                blacklisted.size() != lastBlacklistedProcesses_.size()) {

                EmitDetectionEvent(currentState, blacklisted);
                lastDetectionState_ = currentState;
                lastBlacklistedProcesses_ = blacklisted;
            }

            counter_++;
        } catch (const std::exception& e) {
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs_));
    }
}

std::vector<ProcessInfo> ProcessWatcher::GetRunningProcesses() {
    std::vector<ProcessInfo> processes;

#ifdef _WIN32
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return processes;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            std::wstring wProcessName(pe32.szExeFile);
            std::string processName = WideStringToUtf8(wProcessName);
            std::string processPath = GetProcessPath(pe32.th32ProcessID);

            processes.emplace_back(pe32.th32ProcessID, processName, processPath);
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);

#elif __APPLE__
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
            std::string processName = ExtractProcessName(fullPath);

            processes.emplace_back(pid, processName, fullPath);
        }
    }
#endif

    return processes;
}

std::vector<ProcessInfo> ProcessWatcher::FilterBlacklistedProcesses(const std::vector<ProcessInfo>& processes) {
    std::vector<ProcessInfo> blacklisted;

    for (const auto& proc : processes) {
        for (const auto& blacklistItem : blacklist_) {
            if (proc.name.find(blacklistItem) != std::string::npos ||
                proc.path.find(blacklistItem) != std::string::npos) {
                blacklisted.push_back(proc);
                break;
            }
        }
    }

    return blacklisted;
}

void ProcessWatcher::EmitDetectionEvent(bool detected, const std::vector<ProcessInfo>& blacklistedProcesses) {
    std::time_t now = std::time(nullptr);

    std::ostringstream json;
    json << "{"
         << "\"module\": \"process-watch\","
         << "\"blacklisted_found\": " << (detected ? "true" : "false") << ","
         << "\"matches\": [";

    for (size_t i = 0; i < blacklistedProcesses.size(); i++) {
        if (i > 0) json << ",";
        json << "{"
             << "\"pid\": " << blacklistedProcesses[i].pid << ","
             << "\"name\": \"" << EscapeJson(blacklistedProcesses[i].name) << "\","
             << "\"path\": \"" << EscapeJson(blacklistedProcesses[i].path) << "\""
             << "}";
    }

    json << "],"
         << "\"ts\": " << (now * 1000) << ","
         << "\"count\": " << counter_.load() << ","
         << "\"source\": \"native\""
         << "}";

    std::string json_str = json.str();

    if (tsfn_) {
        tsfn_.NonBlockingCall([json_str](Napi::Env env, Napi::Function callback) {
            callback.Call({Napi::String::New(env, json_str)});
        });
    }
}

#ifdef _WIN32
std::string ProcessWatcher::GetProcessPath(DWORD processID) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processID);
    if (hProcess == nullptr) {
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processID);
        if (hProcess == nullptr) {
            return "";
        }
    }

    wchar_t path[32768];
    DWORD size = sizeof(path) / sizeof(wchar_t);

    if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
        CloseHandle(hProcess);
        return WideStringToUtf8(std::wstring(path));
    }

    size = sizeof(path) / sizeof(wchar_t);
    if (GetModuleFileNameExW(hProcess, nullptr, path, size)) {
        CloseHandle(hProcess);
        return WideStringToUtf8(std::wstring(path));
    }

    CloseHandle(hProcess);
    return "";
}
#endif

#ifdef __APPLE__
std::string ProcessWatcher::ExtractProcessName(const std::string& fullPath) {
    size_t lastSlash = fullPath.find_last_of('/');
    if (lastSlash != std::string::npos) {
        return fullPath.substr(lastSlash + 1);
    }
    return fullPath;
}
#endif

std::string ProcessWatcher::EscapeJson(const std::string& str) {
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

void ProcessWatcher::InitializeRecordingBlacklist() {
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
    recordingBlacklist_.insert("chrome.exe");
    recordingBlacklist_.insert("firefox.exe");
    recordingBlacklist_.insert("QuickTime Player");
    recordingBlacklist_.insert("ScreenSearch");
    recordingBlacklist_.insert("Snagit");
    recordingBlacklist_.insert("CloudApp");
    recordingBlacklist_.insert("Loom");
    recordingBlacklist_.insert("Screencastify");
}

RecordingDetectionResult ProcessWatcher::DetectRecordingAndOverlays() {
    RecordingDetectionResult result;
    result.isRecording = false;
    result.recordingConfidence = 0.0;
    result.overlayConfidence = 0.0;

    try {
        auto processes = GetRunningProcesses();

        result.recordingSources = DetectRecordingProcesses(processes);

        result.virtualCameras = GetVirtualCameras();

        result.overlayWindows = DetectOverlayWindows();

        result.recordingConfidence = CalculateRecordingConfidence(result.recordingSources, result.virtualCameras);
        result.overlayConfidence = CalculateOverlayConfidence(result.overlayWindows);

        result.isRecording = result.recordingConfidence >= recordingConfidenceThreshold_;

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
        result.eventType = "error";
    }

    return result;
}

std::vector<ProcessInfo> ProcessWatcher::DetectRecordingProcesses(const std::vector<ProcessInfo>& processes) {
    std::vector<ProcessInfo> recordingProcesses;

    for (auto& process : processes) {
        ProcessInfo recordingProcess = process;
        recordingProcess.evidence.clear();

        bool isBlacklisted = false;
        for (const auto& blacklistItem : recordingBlacklist_) {
            if (process.name.find(blacklistItem) != std::string::npos ||
                process.path.find(blacklistItem) != std::string::npos) {
                recordingProcess.evidence.push_back("blacklist");
                isBlacklisted = true;
                break;
            }
        }

        try {
#ifdef _WIN32
            recordingProcess.loadedModules = GetProcessModules(process.pid);
#elif __APPLE__
            recordingProcess.loadedModules = GetProcessLibraries(process.pid);
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
        }

        if (isBlacklisted || !recordingProcess.evidence.empty()) {
            recordingProcesses.push_back(recordingProcess);
        }
    }

    return recordingProcesses;
}

double ProcessWatcher::CalculateRecordingConfidence(const std::vector<ProcessInfo>& recordingProcesses, const std::vector<std::string>& virtualCameras) {
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

    confidence += virtualCameras.size() * 0.3;

    return std::min(confidence, 1.0);
}

double ProcessWatcher::CalculateOverlayConfidence(const std::vector<OverlayWindow>& overlayWindows) {
    double confidence = 0.0;

    for (const auto& overlay : overlayWindows) {
        double windowConfidence = 0.0;

        windowConfidence += 0.4;

        if (overlay.alpha < 1.0) {
            windowConfidence += 0.3;
        }

        for (const auto& style : overlay.extendedStyles) {
            if (style == "WS_EX_TOPMOST") {
                windowConfidence += 0.2;
            } else if (style == "WS_EX_LAYERED") {
                windowConfidence += 0.2;
            } else if (style == "WS_EX_TRANSPARENT") {
                windowConfidence += 0.3;
            }
        }

        confidence += std::min(windowConfidence, 1.0);
    }

    return std::min(confidence, 1.0);
}

#ifdef _WIN32
std::vector<std::string> ProcessWatcher::GetProcessModules(DWORD processID) {
    std::vector<std::string> modules;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (hProcess == nullptr) {
        return modules;
    }

    DWORD cbNeeded = 0;

    if (!EnumProcessModules(hProcess, nullptr, 0, &cbNeeded) || cbNeeded == 0) {
        CloseHandle(hProcess);
        return modules;
    }

    std::vector<HMODULE> hModules(cbNeeded / sizeof(HMODULE));

    if (EnumProcessModules(hProcess, hModules.data(), cbNeeded, &cbNeeded)) {
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            wchar_t moduleNameW[MAX_PATH];
            if (GetModuleBaseNameW(hProcess, hModules[i], moduleNameW, MAX_PATH)) {
                std::string moduleName = WideStringToUtf8(std::wstring(moduleNameW));
                modules.push_back(moduleName);
            }
        }
    }

    CloseHandle(hProcess);
    return modules;
}

std::vector<OverlayWindow> ProcessWatcher::EnumerateWindowsForOverlays() {
    std::vector<OverlayWindow> overlays;

    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto* overlaysPtr = reinterpret_cast<std::vector<OverlayWindow>*>(lParam);

        if (!IsWindowVisible(hwnd)) return TRUE;

        LONG_PTR exStyle = GetWindowLongPtr(hwnd, GWL_EXSTYLE);

        bool isLayered = (exStyle & WS_EX_LAYERED) != 0;
        bool isTopMost = (exStyle & WS_EX_TOPMOST) != 0;
        bool isTransparent = (exStyle & WS_EX_TRANSPARENT) != 0;

        if (isLayered || isTopMost || isTransparent) {
            DWORD processId;
            GetWindowThreadProcessId(hwnd, &processId);

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
            char processName[MAX_PATH] = "Unknown";
            if (hProcess) {
                DWORD size = sizeof(processName);
                GetModuleBaseName(hProcess, nullptr, processName, size);
                CloseHandle(hProcess);
            }

            char handleStr[32];
            sprintf_s(handleStr, "0x%p", hwnd);

            OverlayWindow overlay(handleStr, processId, processName);

            RECT rect;
            if (GetWindowRect(hwnd, &rect)) {
                overlay.bounds.x = rect.left;
                overlay.bounds.y = rect.top;
                overlay.bounds.w = rect.right - rect.left;
                overlay.bounds.h = rect.bottom - rect.top;
            }

            if (isLayered) overlay.extendedStyles.push_back("WS_EX_LAYERED");
            if (isTopMost) overlay.extendedStyles.push_back("WS_EX_TOPMOST");
            if (isTransparent) overlay.extendedStyles.push_back("WS_EX_TRANSPARENT");

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

std::vector<std::string> ProcessWatcher::EnumerateVirtualCameras() {
    std::vector<std::string> virtualCameras;

    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        return virtualCameras;
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
                    std::string deviceName = WideStringToUtf8(deviceNameW);

                    std::string lowerName = deviceName;
                    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

                    if (lowerName.find("obs") != std::string::npos ||
                        lowerName.find("virtual") != std::string::npos ||
                        lowerName.find("streamlabs") != std::string::npos ||
                        lowerName.find("xsplit") != std::string::npos ||
                        lowerName.find("snap") != std::string::npos ||
                        lowerName.find("manycam") != std::string::npos ||
                        lowerName.find("cyberlink") != std::string::npos ||
                        lowerName.find("splitcam") != std::string::npos ||
                        lowerName.find("droidcam") != std::string::npos ||
                        lowerName.find("iriun") != std::string::npos ||
                        lowerName.find("epoccam") != std::string::npos) {
                        virtualCameras.push_back(deviceName);
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

    return virtualCameras;
}

#elif __APPLE__

std::vector<std::string> ProcessWatcher::GetProcessLibraries(int pid) {
    std::vector<std::string> libraries;

    try {
        task_t task;
        kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
        if (kr != KERN_SUCCESS) {
            char pathBuffer[PROC_PIDPATHINFO_MAXSIZE];
            if (proc_pidpath(pid, pathBuffer, sizeof(pathBuffer)) > 0) {
                std::string processPath(pathBuffer);

                if (processPath.find("OBS") != std::string::npos ||
                    processPath.find("QuickTime") != std::string::npos ||
                    processPath.find("Camtasia") != std::string::npos) {
                    libraries.push_back("CoreMedia");
                }

                if (processPath.find("screencapture") != std::string::npos ||
                    processPath.find("Screenshot") != std::string::npos) {
                    libraries.push_back("ScreenCaptureKit");
                    libraries.push_back("CoreGraphics");
                }
            }
            return libraries;
        }

        vm_address_t address = 0;
        vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;

        while (true) {
            mach_port_t object_name;
            kr = vm_region_64(task, &address, &size, VM_REGION_BASIC_INFO_64,
                             (vm_region_info_t)&info, &count, &object_name);

            if (kr != KERN_SUCCESS) break;

            if (info.protection & VM_PROT_EXECUTE) {
                char regionInfo[256];
                if (address > 0x100000000ULL) {
                    if ((address & 0xFFFF000000000000ULL) == 0x7FFF000000000000ULL) {
                        uint64_t offset = address & 0xFFFFFFFFULL;
                        if (offset < 0x20000000) {
                            libraries.push_back("CoreGraphics");
                        } else if (offset < 0x30000000) {
                            libraries.push_back("CoreMedia");
                        }
                    }
                }
            }

            address += size;
        }

        mach_port_deallocate(mach_task_self(), task);

    } catch (...) {
    }

    return libraries;
}

std::vector<OverlayWindow> ProcessWatcher::EnumerateWindowsForOverlays() {
    std::vector<OverlayWindow> overlays;

    try {
        CFArrayRef windowList = CGWindowListCopyWindowInfo(
            kCGWindowListOptionOnScreenOnly | kCGWindowListExcludeDesktopElements,
            kCGNullWindowID
        );

        if (!windowList) return overlays;

        CFIndex count = CFArrayGetCount(windowList);

        for (CFIndex i = 0; i < count; i++) {
            CFDictionaryRef window = (CFDictionaryRef)CFArrayGetValueAtIndex(windowList, i);

            CFNumberRef levelRef = (CFNumberRef)CFDictionaryGetValue(window, kCGWindowLayer);
            int windowLevel = 0;
            if (levelRef) {
                CFNumberGetValue(levelRef, kCFNumberIntType, &windowLevel);
            }

            CFNumberRef alphaRef = (CFNumberRef)CFDictionaryGetValue(window, kCGWindowAlpha);
            double alpha = 1.0;
            if (alphaRef) {
                CFNumberGetValue(alphaRef, kCFNumberDoubleType, &alpha);
            }

            bool isHighLevel = windowLevel > 0;
            bool isTransparent = alpha < 1.0;
            bool isSuspiciousSize = false;

            CFDictionaryRef boundsDict = (CFDictionaryRef)CFDictionaryGetValue(window, kCGWindowBounds);
            CGRect bounds = CGRectZero;
            if (boundsDict) {
                CGRectMakeWithDictionaryRepresentation(boundsDict, &bounds);

                CGRect screenBounds = CGDisplayBounds(CGMainDisplayID());
                double coverage = (bounds.size.width * bounds.size.height) /
                                (screenBounds.size.width * screenBounds.size.height);
                isSuspiciousSize = coverage > 0.5;
            }

            if (isHighLevel || (isTransparent && isSuspiciousSize)) {
                CFNumberRef pidRef = (CFNumberRef)CFDictionaryGetValue(window, kCGWindowOwnerPID);
                int pid = 0;
                if (pidRef) {
                    CFNumberGetValue(pidRef, kCFNumberIntType, &pid);
                }

                char processName[256] = "Unknown";
                if (pid > 0) {
                    char pathBuffer[PROC_PIDPATHINFO_MAXSIZE];
                    if (proc_pidpath(pid, pathBuffer, sizeof(pathBuffer)) > 0) {
                        const char* baseName = strrchr(pathBuffer, '/');
                        if (baseName) {
                            strncpy(processName, baseName + 1, sizeof(processName) - 1);
                            processName[sizeof(processName) - 1] = '\0';
                        }
                    }
                }

                CFNumberRef windowIdRef = (CFNumberRef)CFDictionaryGetValue(window, kCGWindowNumber);
                uint32_t windowId = 0;
                if (windowIdRef) {
                    CFNumberGetValue(windowIdRef, kCFNumberIntType, &windowId);
                }

                char handleStr[32];
                snprintf(handleStr, sizeof(handleStr), "0x%x", windowId);

                OverlayWindow overlay(handleStr, pid, processName);
                overlay.bounds.x = (int)bounds.origin.x;
                overlay.bounds.y = (int)bounds.origin.y;
                overlay.bounds.w = (int)bounds.size.width;
                overlay.bounds.h = (int)bounds.size.height;
                overlay.zOrder = windowLevel;
                overlay.alpha = alpha;

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
        }

        CFRelease(windowList);

    } catch (...) {
    }

    return overlays;
}

std::vector<std::string> ProcessWatcher::EnumerateVirtualCameras() {
    std::vector<std::string> virtualCameras;

    std::vector<std::string> vcamProcesses = {
        "OBS Virtual Camera",
        "Snap Camera",
        "mmhmm",
        "Loom",
        "CamTwist",
        "ManyCam",
        "Reincubate Camo"
    };

    auto processes = GetRunningProcesses();
    for (const auto& process : processes) {
        for (const auto& vcamProcess : vcamProcesses) {
            if (process.name.find(vcamProcess) != std::string::npos ||
                process.path.find(vcamProcess) != std::string::npos) {

                virtualCameras.push_back(vcamProcess + " (detected via process)");
                break;
            }
        }
    }

    return virtualCameras;
}

#endif

std::vector<std::string> ProcessWatcher::GetVirtualCameras() {
    return EnumerateVirtualCameras();
}

std::vector<OverlayWindow> ProcessWatcher::GetOverlayWindows() {
    return EnumerateWindowsForOverlays();
}

std::string ProcessWatcher::CreateRecordingOverlayEventJson(const RecordingDetectionResult& result) {
    std::time_t now = std::time(nullptr);
    std::ostringstream json;

    json << "{"
         << "\"module\": \"recorder-overlay-watch\","
         << "\"eventType\": \"" << EscapeJson(result.eventType) << "\","
         << "\"timestamp\": " << (now * 1000) << ",";

    if (result.eventType == "recording-started" || result.eventType == "recording-stopped") {
        json << "\"sources\": [";
        for (size_t i = 0; i < result.recordingSources.size(); i++) {
            if (i > 0) json << ",";
            const auto& source = result.recordingSources[i];
            json << "{"
                 << "\"pid\": " << source.pid << ","
                 << "\"process\": \"" << EscapeJson(source.name) << "\","
                 << "\"evidence\": [";
            for (size_t j = 0; j < source.evidence.size(); j++) {
                if (j > 0) json << ",";
                json << "\"" << EscapeJson(source.evidence[j]) << "\"";
            }
            json << "]}";
        }
        json << "],";

        json << "\"virtualCameras\": [";
        for (size_t i = 0; i < result.virtualCameras.size(); i++) {
            if (i > 0) json << ",";
            json << "{\"name\": \"" << EscapeJson(result.virtualCameras[i]) << "\"}";
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
                 << "\"process\": \"" << EscapeJson(overlay.processName) << "\","
                 << "\"windowHandle\": \"" << EscapeJson(overlay.windowHandle) << "\","
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
                json << "\"" << EscapeJson(overlay.extendedStyles[j]) << "\"";
            }
            json << "]}";
        }
        json << "],";

        json << "\"confidence\": " << result.overlayConfidence;
    }

    json << "}";

    return json.str();
}