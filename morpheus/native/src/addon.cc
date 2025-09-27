#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// Prevent winsock.h from being included by Windows headers
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif
#endif

#include <napi.h>
#include "ProcessWatcher.h"
#include "ScreenWatcher.h"
#include "VMDetector.h"
#include "NotificationBlocker.h"
#include "FocusIdleWatcher.h"
#include "ClipboardWatcher.h"
#include "SystemDetector.h"
#include "SmartDeviceDetector.h"
#include "PermissionChecker.h"

static ProcessWatcher* process_watcher_instance = nullptr;
static ScreenWatcher* screen_watcher_instance = nullptr;
static VMDetector* vm_detector_instance = nullptr;
static NotificationBlocker* notification_blocker_instance = nullptr;
static FocusIdleWatcher* focus_idle_watcher_instance = nullptr;
static ClipboardWatcher* clipboard_watcher_instance = nullptr;
static SystemDetector* system_detector_instance = nullptr;
static SmartDeviceDetector* smart_device_detector_instance = nullptr;

// JavaScript interface functions
Napi::Value StartProcessWatcher(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsFunction()) {
        Napi::TypeError::New(env, "Callback function expected").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    if (process_watcher_instance && process_watcher_instance->IsRunning()) {
        return Napi::Boolean::New(env, false); // Already running
    }
    
    if (!process_watcher_instance) {
        process_watcher_instance = new ProcessWatcher();
    }
    
    // Parse options if provided
    int intervalMs = 1500;
    if (info.Length() >= 2 && info[1].IsObject()) {
        Napi::Object options = info[1].As<Napi::Object>();
        
        if (options.Has("intervalMs")) {
            intervalMs = options.Get("intervalMs").As<Napi::Number>().Int32Value();
        }
        
        if (options.Has("blacklist") && options.Get("blacklist").IsArray()) {
            Napi::Array blacklistArray = options.Get("blacklist").As<Napi::Array>();
            std::vector<std::string> blacklist;
            
            for (uint32_t i = 0; i < blacklistArray.Length(); i++) {
                if (blacklistArray.Get(i).IsString()) {
                    blacklist.push_back(blacklistArray.Get(i).As<Napi::String>().Utf8Value());
                }
            }
            
            process_watcher_instance->SetBlacklist(blacklist);
        }
    }
    
    process_watcher_instance->Start(info[0].As<Napi::Function>(), intervalMs);
    return Napi::Boolean::New(env, true);
}

Napi::Value StopProcessWatcher(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (process_watcher_instance) {
        process_watcher_instance->Stop();
        delete process_watcher_instance;
        process_watcher_instance = nullptr;
    }
    
    return env.Null();
}


// 2025 ProcessWatcher functions
Napi::Value GetProcessSnapshot(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!process_watcher_instance) {
        process_watcher_instance = new ProcessWatcher();
    }

    try {
        std::vector<ProcessInfo> processes = process_watcher_instance->GetProcessSnapshot();

        Napi::Array result = Napi::Array::New(env, processes.size());

        for (size_t i = 0; i < processes.size(); i++) {
            Napi::Object processObj = Napi::Object::New(env);

            // Basic process info
            processObj.Set("pid", Napi::Number::New(env, processes[i].pid));
            processObj.Set("name", Napi::String::New(env, processes[i].name));
            processObj.Set("path", Napi::String::New(env, processes[i].path));

            // Classification info
            processObj.Set("threatLevel", Napi::Number::New(env, processes[i].threatLevel));
            processObj.Set("category", Napi::Number::New(env, processes[i].category));
            processObj.Set("confidence", Napi::Number::New(env, processes[i].confidence));
            processObj.Set("riskReason", Napi::String::New(env, processes[i].riskReason));
            processObj.Set("flagged", Napi::Boolean::New(env, processes[i].flagged));
            processObj.Set("suspicious", Napi::Boolean::New(env, processes[i].suspicious));
            processObj.Set("blacklisted", Napi::Boolean::New(env, processes[i].blacklisted));

            // Evidence array
            Napi::Array evidenceArray = Napi::Array::New(env, processes[i].evidence.size());
            for (size_t j = 0; j < processes[i].evidence.size(); j++) {
                evidenceArray[j] = Napi::String::New(env, processes[i].evidence[j]);
            }
            processObj.Set("evidence", evidenceArray);

            // Loaded modules
            Napi::Array modulesArray = Napi::Array::New(env, processes[i].loadedModules.size());
            for (size_t j = 0; j < processes[i].loadedModules.size(); j++) {
                modulesArray[j] = Napi::String::New(env, processes[i].loadedModules[j]);
            }
            processObj.Set("loadedModules", modulesArray);

            result[i] = processObj;
        }

        return result;
    } catch (const std::exception& e) {
        Napi::Error::New(env, std::string("Error getting enhanced process snapshot: ") + e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

Napi::Value DetectSuspiciousBehavior(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!process_watcher_instance) {
        process_watcher_instance = new ProcessWatcher();
    }

    try {
        std::vector<ProcessInfo> suspiciousProcesses = process_watcher_instance->DetectSuspiciousBehavior();

        Napi::Array result = Napi::Array::New(env, suspiciousProcesses.size());

        for (size_t i = 0; i < suspiciousProcesses.size(); i++) {
            Napi::Object processObj = Napi::Object::New(env);

            processObj.Set("pid", Napi::Number::New(env, suspiciousProcesses[i].pid));
            processObj.Set("name", Napi::String::New(env, suspiciousProcesses[i].name));
            processObj.Set("path", Napi::String::New(env, suspiciousProcesses[i].path));
            processObj.Set("threatLevel", Napi::Number::New(env, suspiciousProcesses[i].threatLevel));
            processObj.Set("category", Napi::Number::New(env, suspiciousProcesses[i].category));
            processObj.Set("confidence", Napi::Number::New(env, suspiciousProcesses[i].confidence));
            processObj.Set("riskReason", Napi::String::New(env, suspiciousProcesses[i].riskReason));

            result[i] = processObj;
        }

        return result;
    } catch (const std::exception& e) {
        Napi::Error::New(env, std::string("Error detecting suspicious behavior: ") + e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}


// Screen Watcher functions
Napi::Value StartScreenWatcher(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsFunction()) {
        Napi::TypeError::New(env, "Callback function expected").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    if (screen_watcher_instance) {
        screen_watcher_instance->stopWatching();
        delete screen_watcher_instance;
    }
    
    screen_watcher_instance = new ScreenWatcher();
    
    // Parse options if provided
    int intervalMs = 3000;
    if (info.Length() >= 2 && info[1].IsObject()) {
        Napi::Object options = info[1].As<Napi::Object>();
        
        if (options.Has("intervalMs")) {
            intervalMs = options.Get("intervalMs").As<Napi::Number>().Int32Value();
        }
    }
    
    // Create persistent reference to callback
    Napi::Function callback = info[0].As<Napi::Function>();
    
    // Start watching with callback
    auto jsCallback = [env, callback](const std::string& jsonData) {
        // Call JavaScript callback from the main thread
        callback.Call({Napi::String::New(env, jsonData)});
    };
    
    bool success = screen_watcher_instance->startWatching(jsCallback, intervalMs);
    return Napi::Boolean::New(env, success);
}

Napi::Value StopScreenWatcher(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (screen_watcher_instance) {
        screen_watcher_instance->stopWatching();
        delete screen_watcher_instance;
        screen_watcher_instance = nullptr;
    }
    
    return env.Null();
}

Napi::Value GetCurrentScreenStatus(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!screen_watcher_instance) {
        screen_watcher_instance = new ScreenWatcher();
    }

    try {
        ScreenStatus status = screen_watcher_instance->getCurrentStatus();

        Napi::Object result = Napi::Object::New(env);
        result.Set("mirroring", Napi::Boolean::New(env, status.mirroring));
        result.Set("splitScreen", Napi::Boolean::New(env, status.splitScreen));
        result.Set("screenSharing", Napi::Boolean::New(env, status.screenSharing));
        result.Set("hasActiveCaptureSession", Napi::Boolean::New(env, status.hasActiveCaptureSession));
        result.Set("overallThreatLevel", Napi::Number::New(env, status.overallThreatLevel));

        // All displays
        Napi::Array displayArray = Napi::Array::New(env);
        for (size_t i = 0; i < status.displays.size(); i++) {
            Napi::Object displayObj = Napi::Object::New(env);
            displayObj.Set("name", Napi::String::New(env, status.displays[i].name));
            displayObj.Set("deviceId", Napi::String::New(env, status.displays[i].deviceId));
            displayObj.Set("isPrimary", Napi::Boolean::New(env, status.displays[i].isPrimary));
            displayObj.Set("isExternal", Napi::Boolean::New(env, status.displays[i].isExternal));
            displayObj.Set("isMirrored", Napi::Boolean::New(env, status.displays[i].isMirrored));
            displayObj.Set("isBeingCaptured", Napi::Boolean::New(env, status.displays[i].isBeingCaptured));
            displayObj.Set("hasActiveSessions", Napi::Boolean::New(env, status.displays[i].hasActiveSessions));
            displayArray[i] = displayObj;
        }
        result.Set("displays", displayArray);

        // External displays
        Napi::Array externalDisplayArray = Napi::Array::New(env);
        for (size_t i = 0; i < status.externalDisplays.size(); i++) {
            externalDisplayArray[i] = Napi::String::New(env, status.externalDisplays[i].name);
        }
        result.Set("externalDisplays", externalDisplayArray);

        // External keyboards
        Napi::Array keyboardArray = Napi::Array::New(env);
        for (size_t i = 0; i < status.externalKeyboards.size(); i++) {
            keyboardArray[i] = Napi::String::New(env, status.externalKeyboards[i].name);
        }
        result.Set("externalKeyboards", keyboardArray);

        // External devices
        Napi::Array deviceArray = Napi::Array::New(env);
        for (size_t i = 0; i < status.externalDevices.size(); i++) {
            deviceArray[i] = Napi::String::New(env, status.externalDevices[i].name);
        }
        result.Set("externalDevices", deviceArray);

        // Active sharing sessions
        Napi::Array sessionsArray = Napi::Array::New(env, status.activeSharingSessions.size());
        for (size_t i = 0; i < status.activeSharingSessions.size(); i++) {
            Napi::Object sessionObj = Napi::Object::New(env);
            sessionObj.Set("method", Napi::Number::New(env, static_cast<int>(status.activeSharingSessions[i].method)));
            sessionObj.Set("processName", Napi::String::New(env, status.activeSharingSessions[i].processName));
            sessionObj.Set("pid", Napi::Number::New(env, status.activeSharingSessions[i].pid));
            sessionObj.Set("description", Napi::String::New(env, status.activeSharingSessions[i].description));
            sessionObj.Set("confidence", Napi::Number::New(env, status.activeSharingSessions[i].confidence));
            sessionObj.Set("isActive", Napi::Boolean::New(env, status.activeSharingSessions[i].isActive));
            sessionsArray[i] = sessionObj;
        }
        result.Set("activeSharingSessions", sessionsArray);

        return result;
    } catch (const std::exception& e) {
        Napi::Error::New(env, std::string("Error getting screen status: ") + e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

// 2025 ScreenWatcher functions
Napi::Value DetectScreenSharingSessions(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!screen_watcher_instance) {
        screen_watcher_instance = new ScreenWatcher();
    }

    try {
        std::vector<ScreenSharingSession> sessions = screen_watcher_instance->detectScreenSharingSessions();

        Napi::Array result = Napi::Array::New(env, sessions.size());

        for (size_t i = 0; i < sessions.size(); i++) {
            Napi::Object sessionObj = Napi::Object::New(env);
            sessionObj.Set("method", Napi::Number::New(env, static_cast<int>(sessions[i].method)));
            sessionObj.Set("processName", Napi::String::New(env, sessions[i].processName));
            sessionObj.Set("pid", Napi::Number::New(env, sessions[i].pid));
            sessionObj.Set("targetUrl", Napi::String::New(env, sessions[i].targetUrl));
            sessionObj.Set("description", Napi::String::New(env, sessions[i].description));
            sessionObj.Set("confidence", Napi::Number::New(env, sessions[i].confidence));
            sessionObj.Set("isActive", Napi::Boolean::New(env, sessions[i].isActive));

            result[i] = sessionObj;
        }

        return result;
    } catch (const std::exception& e) {
        Napi::Error::New(env, std::string("Error detecting screen sharing sessions: ") + e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

Napi::Value IsScreenBeingCaptured(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!screen_watcher_instance) {
        screen_watcher_instance = new ScreenWatcher();
    }

    try {
        bool isBeingCaptured = screen_watcher_instance->isScreenBeingCaptured();
        return Napi::Boolean::New(env, isBeingCaptured);
    } catch (const std::exception& e) {
        Napi::Error::New(env, std::string("Error checking screen capture: ") + e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

Napi::Value CalculateScreenSharingThreatLevel(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!screen_watcher_instance) {
        screen_watcher_instance = new ScreenWatcher();
    }

    try {
        double threatLevel = screen_watcher_instance->calculateScreenSharingThreatLevel();
        return Napi::Number::New(env, threatLevel);
    } catch (const std::exception& e) {
        Napi::Error::New(env, std::string("Error calculating threat level: ") + e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

// VM Detector functions
Napi::Value StartVMDetector(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsFunction()) {
        Napi::TypeError::New(env, "Callback function expected").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    if (vm_detector_instance && vm_detector_instance->IsRunning()) {
        return Napi::Boolean::New(env, false); // Already running
    }
    
    if (!vm_detector_instance) {
        vm_detector_instance = new VMDetector();
    }
    
    // Parse options if provided
    int intervalMs = 10000; // 10 seconds default for VM detection
    if (info.Length() >= 2 && info[1].IsObject()) {
        Napi::Object options = info[1].As<Napi::Object>();
        
        if (options.Has("intervalMs")) {
            intervalMs = options.Get("intervalMs").As<Napi::Number>().Int32Value();
        }
    }
    
    vm_detector_instance->Start(info[0].As<Napi::Function>(), intervalMs);
    return Napi::Boolean::New(env, true);
}

Napi::Value StopVMDetector(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (vm_detector_instance) {
        vm_detector_instance->Stop();
        delete vm_detector_instance;
        vm_detector_instance = nullptr;
    }
    
    return env.Null();
}

Napi::Value DetectVirtualMachine(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (!vm_detector_instance) {
        vm_detector_instance = new VMDetector();
    }
    
    try {
        VMDetectionResult result = vm_detector_instance->detectVirtualMachine();
        
        Napi::Object jsResult = Napi::Object::New(env);
        jsResult.Set("isInsideVM", Napi::Boolean::New(env, result.isInsideVM));
        jsResult.Set("detectedVM", Napi::String::New(env, result.detectedVM));
        jsResult.Set("detectionMethod", Napi::String::New(env, result.detectionMethod));
        
        // Running VM processes
        Napi::Array processArray = Napi::Array::New(env);
        for (size_t i = 0; i < result.runningVMProcesses.size(); i++) {
            processArray[i] = Napi::String::New(env, result.runningVMProcesses[i]);
        }
        jsResult.Set("runningVMProcesses", processArray);
        
        // VM indicators
        Napi::Array indicatorArray = Napi::Array::New(env);
        for (size_t i = 0; i < result.vmIndicators.size(); i++) {
            indicatorArray[i] = Napi::String::New(env, result.vmIndicators[i]);
        }
        jsResult.Set("vmIndicators", indicatorArray);
        
        return jsResult;
    } catch (const std::exception& e) {
        Napi::Error::New(env, std::string("Error detecting VM: ") + e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}


// Focus Idle Watcher functions
Napi::Value StartFocusIdleWatcher(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsFunction()) {
        Napi::TypeError::New(env, "Callback function expected").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    if (focus_idle_watcher_instance && focus_idle_watcher_instance->IsRunning()) {
        return Napi::Boolean::New(env, false); // Already running
    }
    
    if (!focus_idle_watcher_instance) {
        focus_idle_watcher_instance = new FocusIdleWatcher();
    }
    
    // Parse options if provided
    int intervalMs = 1000; // 1 second default for focus/idle detection
    FocusIdleConfig config;
    
    if (info.Length() >= 2 && info[1].IsObject()) {
        Napi::Object options = info[1].As<Napi::Object>();
        
        if (options.Has("intervalMs")) {
            intervalMs = options.Get("intervalMs").As<Napi::Number>().Int32Value();
        }
        
        if (options.Has("idleThresholdSec")) {
            config.idleThresholdSec = options.Get("idleThresholdSec").As<Napi::Number>().Int32Value();
        }
        
        if (options.Has("focusDebounceMs")) {
            config.focusDebounceMs = options.Get("focusDebounceMs").As<Napi::Number>().Int32Value();
        }
        
        if (options.Has("examAppTitle")) {
            config.examAppTitle = options.Get("examAppTitle").As<Napi::String>().Utf8Value();
        }
        
        if (options.Has("enableIdleDetection")) {
            config.enableIdleDetection = options.Get("enableIdleDetection").As<Napi::Boolean>().Value();
        }
        
        if (options.Has("enableFocusDetection")) {
            config.enableFocusDetection = options.Get("enableFocusDetection").As<Napi::Boolean>().Value();
        }
        
        if (options.Has("enableMinimizeDetection")) {
            config.enableMinimizeDetection = options.Get("enableMinimizeDetection").As<Napi::Boolean>().Value();
        }
        
        if (options.Has("windowHandle")) {
            // Extract window handle if provided (platform-specific)
            // This would be passed from Electron main process
            Napi::Value handleValue = options.Get("windowHandle");
            if (handleValue.IsNumber()) {
                void* handle = reinterpret_cast<void*>(handleValue.As<Napi::Number>().Int64Value());
                focus_idle_watcher_instance->SetExamWindowHandle(handle);
            }
        }
    }
    
    focus_idle_watcher_instance->SetConfig(config);
    focus_idle_watcher_instance->Start(info[0].As<Napi::Function>(), intervalMs);
    return Napi::Boolean::New(env, true);
}

Napi::Value StopFocusIdleWatcher(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (focus_idle_watcher_instance) {
        focus_idle_watcher_instance->Stop();
        delete focus_idle_watcher_instance;
        focus_idle_watcher_instance = nullptr;
    }
    
    return env.Null();
}

Napi::Value GetCurrentFocusIdleStatus(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (!focus_idle_watcher_instance) {
        focus_idle_watcher_instance = new FocusIdleWatcher();
    }
    
    try {
        FocusIdleEvent status = focus_idle_watcher_instance->GetCurrentStatus();
        
        Napi::Object result = Napi::Object::New(env);
        result.Set("module", Napi::String::New(env, "focus-idle-watch"));
        result.Set("eventType", Napi::String::New(env, status.eventType));
        result.Set("timestamp", Napi::Number::New(env, status.timestamp));
        result.Set("ts", Napi::Number::New(env, status.timestamp));
        result.Set("count", Napi::Number::New(env, 1));
        result.Set("source", Napi::String::New(env, "native"));
        
        Napi::Object details = Napi::Object::New(env);
        if (status.details.idleDuration > 0) {
            details.Set("idleDuration", Napi::Number::New(env, status.details.idleDuration));
        }
        if (!status.details.activeApp.empty()) {
            details.Set("activeApp", Napi::String::New(env, status.details.activeApp));
        }
        if (!status.details.windowTitle.empty()) {
            details.Set("windowTitle", Napi::String::New(env, status.details.windowTitle));
        }
        if (!status.details.reason.empty()) {
            details.Set("reason", Napi::String::New(env, status.details.reason));
        }
        
        result.Set("details", details);
        
        return result;
    } catch (const std::exception& e) {
        Napi::Error::New(env, std::string("Error getting focus/idle status: ") + e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

Napi::Value StartRealtimeWindowMonitor(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!focus_idle_watcher_instance) {
        focus_idle_watcher_instance = new FocusIdleWatcher();
    }

    try {
        focus_idle_watcher_instance->StartRealtimeWindowMonitor();
        return Napi::Boolean::New(env, true);
    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }
}

Napi::Value StopRealtimeWindowMonitor(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!focus_idle_watcher_instance) {
        return Napi::Boolean::New(env, true);
    }

    try {
        focus_idle_watcher_instance->StopRealtimeWindowMonitor();
        return Napi::Boolean::New(env, true);
    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }
}

Napi::Value GetRealtimeFocusStatus(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!focus_idle_watcher_instance) {
        focus_idle_watcher_instance = new FocusIdleWatcher();
    }

    try {
        FocusIdleEvent status = focus_idle_watcher_instance->GetRealtimeFocusStatus();

        Napi::Object result = Napi::Object::New(env);
        result.Set("module", Napi::String::New(env, "focus-idle-watch"));
        result.Set("eventType", Napi::String::New(env, status.eventType));
        result.Set("timestamp", Napi::Number::New(env, status.timestamp));
        result.Set("ts", Napi::Number::New(env, status.timestamp));
        result.Set("count", Napi::Number::New(env, 1));
        result.Set("source", Napi::String::New(env, "realtime-native"));

        Napi::Object details = Napi::Object::New(env);
        if (status.details.idleDuration > 0) {
            details.Set("idleDuration", Napi::Number::New(env, status.details.idleDuration));
        }
        if (!status.details.activeApp.empty()) {
            details.Set("activeApp", Napi::String::New(env, status.details.activeApp));
        }
        if (!status.details.windowTitle.empty()) {
            details.Set("windowTitle", Napi::String::New(env, status.details.windowTitle));
        }
        if (!status.details.reason.empty()) {
            details.Set("reason", Napi::String::New(env, status.details.reason));
        }

        result.Set("details", details);

        return result;
    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

// Clipboard Watcher functions
Napi::Value StartClipboardWatcher(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsFunction()) {
        Napi::TypeError::New(env, "Callback function expected").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    if (clipboard_watcher_instance && clipboard_watcher_instance->IsRunning()) {
        return Napi::Boolean::New(env, false); // Already running
    }
    
    if (!clipboard_watcher_instance) {
        clipboard_watcher_instance = new ClipboardWatcher();
    }
    
    // Parse options if provided
    int heartbeatIntervalMs = 5000;
    if (info.Length() >= 2 && info[1].IsObject()) {
        Napi::Object options = info[1].As<Napi::Object>();
        
        if (options.Has("heartbeatIntervalMs")) {
            heartbeatIntervalMs = options.Get("heartbeatIntervalMs").As<Napi::Number>().Int32Value();
        }
        
        if (options.Has("privacyMode")) {
            int privacyMode = options.Get("privacyMode").As<Napi::Number>().Int32Value();
            clipboard_watcher_instance->SetPrivacyMode(static_cast<PrivacyMode>(privacyMode));
        }
    }
    
    clipboard_watcher_instance->Start(info[0].As<Napi::Function>(), heartbeatIntervalMs);
    return Napi::Boolean::New(env, true);
}

Napi::Value StopClipboardWatcher(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (clipboard_watcher_instance) {
        clipboard_watcher_instance->Stop();
        delete clipboard_watcher_instance;
        clipboard_watcher_instance = nullptr;
    }
    
    return env.Null();
}

Napi::Value SetClipboardPrivacyMode(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsNumber()) {
        Napi::TypeError::New(env, "Privacy mode number expected").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    if (!clipboard_watcher_instance) {
        clipboard_watcher_instance = new ClipboardWatcher();
    }
    
    int mode = info[0].As<Napi::Number>().Int32Value();
    clipboard_watcher_instance->SetPrivacyMode(static_cast<PrivacyMode>(mode));
    
    return Napi::Boolean::New(env, true);
}

Napi::Value GetClipboardSnapshot(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (!clipboard_watcher_instance) {
        clipboard_watcher_instance = new ClipboardWatcher();
    }
    
    try {
        ClipboardEvent snapshot = clipboard_watcher_instance->GetCurrentSnapshot();
        
        Napi::Object result = Napi::Object::New(env);
        result.Set("eventType", Napi::String::New(env, snapshot.eventType));
        
        if (snapshot.sourceApp.empty()) {
            result.Set("sourceApp", env.Null());
        } else {
            result.Set("sourceApp", Napi::String::New(env, snapshot.sourceApp));
        }
        
        if (snapshot.pid == -1) {
            result.Set("pid", env.Null());
        } else {
            result.Set("pid", Napi::Number::New(env, snapshot.pid));
        }
        
        Napi::Array formatsArray = Napi::Array::New(env, snapshot.clipFormats.size());
        for (size_t i = 0; i < snapshot.clipFormats.size(); i++) {
            formatsArray[i] = Napi::String::New(env, snapshot.clipFormats[i]);
        }
        result.Set("clipFormats", formatsArray);
        
        if (snapshot.contentPreview.empty()) {
            result.Set("contentPreview", env.Null());
        } else {
            result.Set("contentPreview", Napi::String::New(env, snapshot.contentPreview));
        }
        
        if (snapshot.contentHash.empty()) {
            result.Set("contentHash", env.Null());
        } else {
            result.Set("contentHash", Napi::String::New(env, snapshot.contentHash));
        }
        
        result.Set("isSensitive", Napi::Boolean::New(env, snapshot.isSensitive));
        result.Set("timestamp", Napi::Number::New(env, snapshot.timestamp.count()));
        
        return result;
    } catch (const std::exception& e) {
        Napi::Error::New(env, std::string("Error getting clipboard snapshot: ") + e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

Napi::Value ClearClipboard(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!clipboard_watcher_instance) {
        clipboard_watcher_instance = new ClipboardWatcher();
    }

    try {
        bool success = clipboard_watcher_instance->ClearClipboard();
        return Napi::Boolean::New(env, success);
    } catch (const std::exception& e) {
        Napi::Error::New(env, std::string("Error clearing clipboard: ") + e.what()).ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }
}

// Recording/Overlay Detection functions (extending ScreenWatcher)
Napi::Value DetectRecordingAndOverlays(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (!screen_watcher_instance) {
        screen_watcher_instance = new ScreenWatcher();
    }
    
    try {
        RecordingDetectionResult result = screen_watcher_instance->detectRecordingAndOverlays();
        
        Napi::Object jsResult = Napi::Object::New(env);
        jsResult.Set("isRecording", Napi::Boolean::New(env, result.isRecording));
        jsResult.Set("eventType", Napi::String::New(env, result.eventType));
        jsResult.Set("recordingConfidence", Napi::Number::New(env, result.recordingConfidence));
        jsResult.Set("overlayConfidence", Napi::Number::New(env, result.overlayConfidence));
        
        // Recording sources
        Napi::Array sourcesArray = Napi::Array::New(env, result.recordingSources.size());
        for (size_t i = 0; i < result.recordingSources.size(); i++) {
            Napi::Object sourceObj = Napi::Object::New(env);
            sourceObj.Set("pid", Napi::Number::New(env, result.recordingSources[i].pid));
            sourceObj.Set("process", Napi::String::New(env, result.recordingSources[i].name));
            
            Napi::Array evidenceArray = Napi::Array::New(env, result.recordingSources[i].evidence.size());
            for (size_t j = 0; j < result.recordingSources[i].evidence.size(); j++) {
                evidenceArray[j] = Napi::String::New(env, result.recordingSources[i].evidence[j]);
            }
            sourceObj.Set("evidence", evidenceArray);
            sourcesArray[i] = sourceObj;
        }
        jsResult.Set("sources", sourcesArray);
        
        // Virtual cameras
        Napi::Array camerasArray = Napi::Array::New(env, result.virtualCameras.size());
        for (size_t i = 0; i < result.virtualCameras.size(); i++) {
            Napi::Object cameraObj = Napi::Object::New(env);
            cameraObj.Set("name", Napi::String::New(env, result.virtualCameras[i]));
            camerasArray[i] = cameraObj;
        }
        jsResult.Set("virtualCameras", camerasArray);
        
        // Overlay windows
        Napi::Array overlaysArray = Napi::Array::New(env, result.overlayWindows.size());
        for (size_t i = 0; i < result.overlayWindows.size(); i++) {
            const auto& overlay = result.overlayWindows[i];
            Napi::Object overlayObj = Napi::Object::New(env);
            overlayObj.Set("pid", Napi::Number::New(env, overlay.pid));
            overlayObj.Set("process", Napi::String::New(env, overlay.processName));
            overlayObj.Set("windowHandle", Napi::String::New(env, overlay.windowHandle));
            overlayObj.Set("zOrder", Napi::Number::New(env, overlay.zOrder));
            overlayObj.Set("alpha", Napi::Number::New(env, overlay.alpha));
            
            // Bounds
            Napi::Object boundsObj = Napi::Object::New(env);
            boundsObj.Set("x", Napi::Number::New(env, overlay.bounds.x));
            boundsObj.Set("y", Napi::Number::New(env, overlay.bounds.y));
            boundsObj.Set("w", Napi::Number::New(env, overlay.bounds.w));
            boundsObj.Set("h", Napi::Number::New(env, overlay.bounds.h));
            overlayObj.Set("bounds", boundsObj);
            
            // Extended styles
            Napi::Array stylesArray = Napi::Array::New(env, overlay.extendedStyles.size());
            for (size_t j = 0; j < overlay.extendedStyles.size(); j++) {
                stylesArray[j] = Napi::String::New(env, overlay.extendedStyles[j]);
            }
            overlayObj.Set("extendedStyles", stylesArray);
            
            overlaysArray[i] = overlayObj;
        }
        jsResult.Set("overlayWindows", overlaysArray);
        
        return jsResult;
    } catch (const std::exception& e) {
        Napi::Error::New(env, std::string("Error detecting recording/overlays: ") + e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

Napi::Value SetRecordingBlacklist(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsArray()) {
        Napi::TypeError::New(env, "Array expected").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    if (!screen_watcher_instance) {
        screen_watcher_instance = new ScreenWatcher();
    }
    
    Napi::Array blacklistArray = info[0].As<Napi::Array>();
    std::vector<std::string> blacklist;
    
    for (uint32_t i = 0; i < blacklistArray.Length(); i++) {
        if (blacklistArray.Get(i).IsString()) {
            blacklist.push_back(blacklistArray.Get(i).As<Napi::String>().Utf8Value());
        }
    }
    
    screen_watcher_instance->setRecordingBlacklist(blacklist);
    return Napi::Boolean::New(env, true);
}

// Legacy compatibility functions
Napi::Value Start(const Napi::CallbackInfo& info) {
    return StartProcessWatcher(info);
}

Napi::Value Stop(const Napi::CallbackInfo& info) {
    return StopProcessWatcher(info);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    // Process Watcher functions
    exports.Set(Napi::String::New(env, "startProcessWatcher"), Napi::Function::New(env, StartProcessWatcher));
    exports.Set(Napi::String::New(env, "stopProcessWatcher"), Napi::Function::New(env, StopProcessWatcher));
    exports.Set(Napi::String::New(env, "getProcessSnapshot"), Napi::Function::New(env, GetProcessSnapshot));
    exports.Set(Napi::String::New(env, "detectSuspiciousBehavior"), Napi::Function::New(env, DetectSuspiciousBehavior));

    
    // Screen Watcher functions
    exports.Set(Napi::String::New(env, "startScreenWatcher"), Napi::Function::New(env, StartScreenWatcher));
    exports.Set(Napi::String::New(env, "stopScreenWatcher"), Napi::Function::New(env, StopScreenWatcher));
    exports.Set(Napi::String::New(env, "getCurrentScreenStatus"), Napi::Function::New(env, GetCurrentScreenStatus));

    exports.Set(Napi::String::New(env, "detectScreenSharingSessions"), Napi::Function::New(env, DetectScreenSharingSessions));
    exports.Set(Napi::String::New(env, "isScreenBeingCaptured"), Napi::Function::New(env, IsScreenBeingCaptured));
    exports.Set(Napi::String::New(env, "calculateScreenSharingThreatLevel"), Napi::Function::New(env, CalculateScreenSharingThreatLevel));

    // Recording/Overlay Detection functions (extending ScreenWatcher)
    exports.Set(Napi::String::New(env, "detectRecordingAndOverlays"), Napi::Function::New(env, DetectRecordingAndOverlays));
    exports.Set(Napi::String::New(env, "setRecordingBlacklist"), Napi::Function::New(env, SetRecordingBlacklist));
    
    // VM Detector functions
    exports.Set(Napi::String::New(env, "startVMDetector"), Napi::Function::New(env, StartVMDetector));
    exports.Set(Napi::String::New(env, "stopVMDetector"), Napi::Function::New(env, StopVMDetector));
    exports.Set(Napi::String::New(env, "detectVirtualMachine"), Napi::Function::New(env, DetectVirtualMachine));
    
    // Notification Watcher functions
    
    // Focus Idle Watcher functions
    exports.Set(Napi::String::New(env, "startFocusIdleWatcher"), Napi::Function::New(env, StartFocusIdleWatcher));
    exports.Set(Napi::String::New(env, "stopFocusIdleWatcher"), Napi::Function::New(env, StopFocusIdleWatcher));
    exports.Set(Napi::String::New(env, "getCurrentFocusIdleStatus"), Napi::Function::New(env, GetCurrentFocusIdleStatus));
    exports.Set(Napi::String::New(env, "startRealtimeWindowMonitor"), Napi::Function::New(env, StartRealtimeWindowMonitor));
    exports.Set(Napi::String::New(env, "stopRealtimeWindowMonitor"), Napi::Function::New(env, StopRealtimeWindowMonitor));
    exports.Set(Napi::String::New(env, "getRealtimeFocusStatus"), Napi::Function::New(env, GetRealtimeFocusStatus));
    
    // Clipboard Watcher functions
    exports.Set(Napi::String::New(env, "startClipboardWatcher"), Napi::Function::New(env, StartClipboardWatcher));
    exports.Set(Napi::String::New(env, "stopClipboardWatcher"), Napi::Function::New(env, StopClipboardWatcher));
    exports.Set(Napi::String::New(env, "setClipboardPrivacyMode"), Napi::Function::New(env, SetClipboardPrivacyMode));
    exports.Set(Napi::String::New(env, "getClipboardSnapshot"), Napi::Function::New(env, GetClipboardSnapshot));
    exports.Set(Napi::String::New(env, "clearClipboard"), Napi::Function::New(env, ClearClipboard));
    
    
    // Permission Checker functions - define inline
    exports.Set(Napi::String::New(env, "checkAccessibilityPermission"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            bool hasPermission = PermissionChecker::CheckAccessibilityPermission();
            return Napi::Boolean::New(env, hasPermission);
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error checking accessibility permission: ") + e.what()).ThrowAsJavaScriptException();
            return env.Null();
        }
    }));
    exports.Set(Napi::String::New(env, "checkScreenRecordingPermission"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            bool hasPermission = PermissionChecker::CheckScreenRecordingPermission();
            return Napi::Boolean::New(env, hasPermission);
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error checking screen recording permission: ") + e.what()).ThrowAsJavaScriptException();
            return env.Null();
        }
    }));
    exports.Set(Napi::String::New(env, "checkInputMonitoringPermission"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            bool hasPermission = PermissionChecker::CheckInputMonitoringPermission();
            return Napi::Boolean::New(env, hasPermission);
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error checking input monitoring permission: ") + e.what()).ThrowAsJavaScriptException();
            return env.Null();
        }
    }));
    exports.Set(Napi::String::New(env, "requestAccessibilityPermission"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            bool granted = PermissionChecker::RequestAccessibilityPermission();
            return Napi::Boolean::New(env, granted);
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error requesting accessibility permission: ") + e.what()).ThrowAsJavaScriptException();
            return env.Null();
        }
    }));
    exports.Set(Napi::String::New(env, "requestScreenRecordingPermission"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            bool granted = PermissionChecker::RequestScreenRecordingPermission();
            return Napi::Boolean::New(env, granted);
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error requesting screen recording permission: ") + e.what()).ThrowAsJavaScriptException();
            return env.Null();
        }
    }));
    exports.Set(Napi::String::New(env, "requestInputMonitoringPermission"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            bool granted = PermissionChecker::RequestInputMonitoringPermission();
            return Napi::Boolean::New(env, granted);
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error requesting input monitoring permission: ") + e.what()).ThrowAsJavaScriptException();
            return env.Null();
        }
    }));

    // Windows-specific permission functions
    exports.Set(Napi::String::New(env, "checkRegistryPermission"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            bool hasPermission = PermissionChecker::CheckRegistryPermission();
            return Napi::Boolean::New(env, hasPermission);
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error checking registry permission: ") + e.what()).ThrowAsJavaScriptException();
            return env.Null();
        }
    }));

    exports.Set(Napi::String::New(env, "checkDeviceEnumerationPermission"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            bool hasPermission = PermissionChecker::CheckDeviceEnumerationPermission();
            return Napi::Boolean::New(env, hasPermission);
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error checking device enumeration permission: ") + e.what()).ThrowAsJavaScriptException();
            return env.Null();
        }
    }));

    exports.Set(Napi::String::New(env, "checkProcessAccessPermission"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            bool hasPermission = PermissionChecker::CheckProcessAccessPermission();
            return Napi::Boolean::New(env, hasPermission);
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error checking process access permission: ") + e.what()).ThrowAsJavaScriptException();
            return env.Null();
        }
    }));

    exports.Set(Napi::String::New(env, "checkClipboardPermission"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            bool hasPermission = PermissionChecker::CheckClipboardPermission();
            return Napi::Boolean::New(env, hasPermission);
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error checking clipboard permission: ") + e.what()).ThrowAsJavaScriptException();
            return env.Null();
        }
    }));

    exports.Set(Napi::String::New(env, "requestRegistryPermission"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            bool granted = PermissionChecker::RequestRegistryPermission();
            return Napi::Boolean::New(env, granted);
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error requesting registry permission: ") + e.what()).ThrowAsJavaScriptException();
            return env.Null();
        }
    }));

    exports.Set(Napi::String::New(env, "requestDeviceEnumerationPermission"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            bool granted = PermissionChecker::RequestDeviceEnumerationPermission();
            return Napi::Boolean::New(env, granted);
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error requesting device enumeration permission: ") + e.what()).ThrowAsJavaScriptException();
            return env.Null();
        }
    }));

    exports.Set(Napi::String::New(env, "requestProcessAccessPermission"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            bool granted = PermissionChecker::RequestProcessAccessPermission();
            return Napi::Boolean::New(env, granted);
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error requesting process access permission: ") + e.what()).ThrowAsJavaScriptException();
            return env.Null();
        }
    }));

    exports.Set(Napi::String::New(env, "requestClipboardPermission"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            bool granted = PermissionChecker::RequestClipboardPermission();
            return Napi::Boolean::New(env, granted);
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error requesting clipboard permission: ") + e.what()).ThrowAsJavaScriptException();
            return env.Null();
        }
    }));

    // NotificationBlocker functions
    exports.Set(Napi::String::New(env, "enableNotificationBlocking"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            if (!notification_blocker_instance) {
                notification_blocker_instance = new NotificationBlocker();
            }

            notification_blocker_instance->SetExamMode(true);
            bool success = notification_blocker_instance->EnableNotificationBlocking();
            return Napi::Boolean::New(env, success);
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error enabling notification blocking: ") + e.what()).ThrowAsJavaScriptException();
            return env.Null();
        }
    }));

    exports.Set(Napi::String::New(env, "disableNotificationBlocking"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            if (!notification_blocker_instance) {
                return Napi::Boolean::New(env, true); // Nothing to disable
            }

            bool success = notification_blocker_instance->DisableNotificationBlocking();
            notification_blocker_instance->SetExamMode(false);
            return Napi::Boolean::New(env, success);
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error disabling notification blocking: ") + e.what()).ThrowAsJavaScriptException();
            return env.Null();
        }
    }));

    exports.Set(Napi::String::New(env, "getNotificationBlockerStatus"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            if (!notification_blocker_instance) {
                notification_blocker_instance = new NotificationBlocker();
            }

            NotificationEvent status = notification_blocker_instance->GetCurrentState();

            Napi::Object result = Napi::Object::New(env);
            result.Set("module", Napi::String::New(env, "notification-blocker"));
            result.Set("eventType", Napi::String::New(env, status.eventType));
            result.Set("reason", Napi::String::New(env, status.reason));
            result.Set("isBlocked", Napi::Boolean::New(env, status.isBlocked));
            result.Set("userModified", Napi::Boolean::New(env, status.userModified));
            result.Set("timestamp", Napi::Number::New(env, status.timestamp));
            result.Set("source", Napi::String::New(env, "native"));
            result.Set("examActive", Napi::Boolean::New(env, notification_blocker_instance->IsExamActive()));

            return result;
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error getting notification blocker status: ") + e.what()).ThrowAsJavaScriptException();
            return env.Null();
        }
    }));

    exports.Set(Napi::String::New(env, "resetNotificationBlocking"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            if (!notification_blocker_instance) {
                notification_blocker_instance = new NotificationBlocker();
            }

            bool success = notification_blocker_instance->ResetToOriginalState();
            return Napi::Boolean::New(env, success);
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error resetting notification blocking: ") + e.what()).ThrowAsJavaScriptException();
            return env.Null();
        }
    }));

    exports.Set(Napi::String::New(env, "detectNotificationViolation"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            if (!notification_blocker_instance) {
                return Napi::Boolean::New(env, false);
            }

            bool violation = notification_blocker_instance->DetectUserModification();
            return Napi::Boolean::New(env, violation);
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error detecting notification violation: ") + e.what()).ThrowAsJavaScriptException();
            return env.Null();
        }
    }));

    // SmartDeviceDetector functions
    exports.Set(Napi::String::New(env, "startSmartDeviceDetector"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            if (smart_device_detector_instance && smart_device_detector_instance->IsRunning()) {
                return Napi::Boolean::New(env, false);
            }

            if (!smart_device_detector_instance) {
                smart_device_detector_instance = new SmartDeviceDetector();
            }

            int intervalMs = 1000;
            if (info.Length() > 1 && info[1].IsNumber()) {
                intervalMs = info[1].As<Napi::Number>().Int32Value();
            }

            smart_device_detector_instance->Start(info[0].As<Napi::Function>(), intervalMs);
            return Napi::Boolean::New(env, true);
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error starting smart device detector: ") + e.what()).ThrowAsJavaScriptException();
            return Napi::Boolean::New(env, false);
        }
    }));

    exports.Set(Napi::String::New(env, "stopSmartDeviceDetector"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            if (smart_device_detector_instance) {
                smart_device_detector_instance->Stop();
                delete smart_device_detector_instance;
                smart_device_detector_instance = nullptr;
            }
            return Napi::Boolean::New(env, true);
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error stopping smart device detector: ") + e.what()).ThrowAsJavaScriptException();
            return Napi::Boolean::New(env, false);
        }
    }));

    exports.Set(Napi::String::New(env, "getDeviceViolations"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            if (!smart_device_detector_instance) {
                smart_device_detector_instance = new SmartDeviceDetector();
            }

            std::vector<DeviceViolation> violations = smart_device_detector_instance->GetActiveViolations();
            Napi::Array result = Napi::Array::New(env, violations.size());

            for (size_t i = 0; i < violations.size(); i++) {
                Napi::Object violation = Napi::Object::New(env);
                violation.Set("deviceId", Napi::String::New(env, violations[i].deviceId));
                violation.Set("deviceName", Napi::String::New(env, violations[i].deviceName));
                violation.Set("violationType", Napi::String::New(env, violations[i].violationType));
                violation.Set("severity", Napi::Number::New(env, violations[i].severity));
                violation.Set("reason", Napi::String::New(env, violations[i].reason));
                violation.Set("evidence", Napi::String::New(env, violations[i].evidence));
                violation.Set("timestamp", Napi::Number::New(env, violations[i].timestamp.count()));
                violation.Set("persistent", Napi::Boolean::New(env, violations[i].persistent));

                result[i] = violation;
            }

            return result;
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error getting device violations: ") + e.what()).ThrowAsJavaScriptException();
            return env.Null();
        }
    }));

    exports.Set(Napi::String::New(env, "getSecurityProfile"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            if (!smart_device_detector_instance) {
                smart_device_detector_instance = new SmartDeviceDetector();
            }

            SystemSecurityProfile profile = smart_device_detector_instance->GetSecurityProfile();

            Napi::Object result = Napi::Object::New(env);
            result.Set("systemType", Napi::Number::New(env, static_cast<int>(profile.systemType)));
            result.Set("allowedMice", Napi::Number::New(env, profile.allowedMice));
            result.Set("allowedKeyboards", Napi::Number::New(env, profile.allowedKeyboards));
            result.Set("allowedDisplays", Napi::Number::New(env, profile.allowedDisplays));
            result.Set("allowBluetooth", Napi::Boolean::New(env, profile.allowBluetooth));
            result.Set("allowWireless", Napi::Boolean::New(env, profile.allowWireless));
            result.Set("allowVirtualDevices", Napi::Boolean::New(env, profile.allowVirtualDevices));
            result.Set("allowExternalStorage", Napi::Boolean::New(env, profile.allowExternalStorage));
            result.Set("allowExternalWebcams", Napi::Boolean::New(env, profile.allowExternalWebcams));
            result.Set("strictMode", Napi::Boolean::New(env, profile.strictMode));

            return result;
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error getting security profile: ") + e.what()).ThrowAsJavaScriptException();
            return env.Null();
        }
    }));

    // SystemDetector functions
    exports.Set(Napi::String::New(env, "detectSystemType"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            if (!system_detector_instance) {
                system_detector_instance = new SystemDetector();
            }

            SystemInfo systemInfo = system_detector_instance->DetectSystemType();

            Napi::Object result = Napi::Object::New(env);
            result.Set("type", Napi::Number::New(env, static_cast<int>(systemInfo.type)));
            result.Set("manufacturer", Napi::String::New(env, systemInfo.manufacturer));
            result.Set("model", Napi::String::New(env, systemInfo.model));
            result.Set("hasBattery", Napi::Boolean::New(env, systemInfo.hasBattery));
            result.Set("hasLid", Napi::Boolean::New(env, systemInfo.hasLid));
            result.Set("isPortable", Napi::Boolean::New(env, systemInfo.isPortable));
            result.Set("chassisType", Napi::String::New(env, systemInfo.chassisType));
            result.Set("isLaptop", Napi::Boolean::New(env, systemInfo.type == SystemType::LAPTOP));
            result.Set("isDesktop", Napi::Boolean::New(env, systemInfo.type == SystemType::DESKTOP));

            return result;
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error detecting system type: ") + e.what()).ThrowAsJavaScriptException();
            return env.Null();
        }
    }));

    exports.Set(Napi::String::New(env, "isLaptop"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            if (!system_detector_instance) {
                system_detector_instance = new SystemDetector();
            }

            bool isLaptop = system_detector_instance->IsLaptop();
            return Napi::Boolean::New(env, isLaptop);
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error checking if laptop: ") + e.what()).ThrowAsJavaScriptException();
            return Napi::Boolean::New(env, false);
        }
    }));

    exports.Set(Napi::String::New(env, "isDesktop"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            if (!system_detector_instance) {
                system_detector_instance = new SystemDetector();
            }

            bool isDesktop = system_detector_instance->IsDesktop();
            return Napi::Boolean::New(env, isDesktop);
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error checking if desktop: ") + e.what()).ThrowAsJavaScriptException();
            return Napi::Boolean::New(env, false);
        }
    }));

    // SmartDeviceDetector scan functions
    exports.Set(Napi::String::New(env, "scanAllInputDevices"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            if (!smart_device_detector_instance) {
                smart_device_detector_instance = new SmartDeviceDetector();
            }

            std::vector<InputDeviceInfo> devices = smart_device_detector_instance->ScanAllInputDevices();
            Napi::Array result = Napi::Array::New(env, devices.size());

            for (size_t i = 0; i < devices.size(); i++) {
                Napi::Object deviceObj = Napi::Object::New(env);
                deviceObj.Set("name", Napi::String::New(env, devices[i].name));
                deviceObj.Set("type", Napi::String::New(env, devices[i].type));
                deviceObj.Set("deviceId", Napi::String::New(env, devices[i].deviceId));
                deviceObj.Set("manufacturer", Napi::String::New(env, devices[i].manufacturer));
                deviceObj.Set("vendorId", Napi::String::New(env, devices[i].vendorId));
                deviceObj.Set("productId", Napi::String::New(env, devices[i].productId));
                deviceObj.Set("isExternal", Napi::Boolean::New(env, devices[i].isExternal));
                deviceObj.Set("isVirtual", Napi::Boolean::New(env, devices[i].isVirtual));
                deviceObj.Set("isSpoofed", Napi::Boolean::New(env, devices[i].isSpoofed));
                deviceObj.Set("isBluetooth", Napi::Boolean::New(env, devices[i].isBluetooth));
                deviceObj.Set("isWireless", Napi::Boolean::New(env, devices[i].isWireless));
                deviceObj.Set("threatLevel", Napi::Number::New(env, devices[i].threatLevel));
                deviceObj.Set("threatReason", Napi::String::New(env, devices[i].threatReason));
                deviceObj.Set("isAllowed", Napi::Boolean::New(env, devices[i].isAllowed));

                result[i] = deviceObj;
            }

            return result;
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error scanning input devices: ") + e.what()).ThrowAsJavaScriptException();
            return env.Null();
        }
    }));

    exports.Set(Napi::String::New(env, "scanAllStorageDevices"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            if (!smart_device_detector_instance) {
                smart_device_detector_instance = new SmartDeviceDetector();
            }

            std::vector<StorageDeviceInfo> devices = smart_device_detector_instance->ScanAllStorageDevices();
            Napi::Array result = Napi::Array::New(env, devices.size());

            for (size_t i = 0; i < devices.size(); i++) {
                Napi::Object deviceObj = Napi::Object::New(env);
                deviceObj.Set("id", Napi::String::New(env, devices[i].id));
                deviceObj.Set("type", Napi::String::New(env, devices[i].type));
                deviceObj.Set("name", Napi::String::New(env, devices[i].name));
                deviceObj.Set("path", Napi::String::New(env, devices[i].path));
                deviceObj.Set("isExternal", Napi::Boolean::New(env, devices[i].isExternal));

                result[i] = deviceObj;
            }

            return result;
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error scanning storage devices: ") + e.what()).ThrowAsJavaScriptException();
            return env.Null();
        }
    }));

    exports.Set(Napi::String::New(env, "scanVideoDevices"), Napi::Function::New(env, [](const Napi::CallbackInfo& info) -> Napi::Value {
        Napi::Env env = info.Env();
        try {
            if (!smart_device_detector_instance) {
                smart_device_detector_instance = new SmartDeviceDetector();
            }

            std::vector<InputDeviceInfo> devices = smart_device_detector_instance->ScanVideoDevices();
            Napi::Array result = Napi::Array::New(env, devices.size());

            for (size_t i = 0; i < devices.size(); i++) {
                Napi::Object deviceObj = Napi::Object::New(env);
                deviceObj.Set("name", Napi::String::New(env, devices[i].name));
                deviceObj.Set("type", Napi::String::New(env, devices[i].type));
                deviceObj.Set("deviceId", Napi::String::New(env, devices[i].deviceId));
                deviceObj.Set("manufacturer", Napi::String::New(env, devices[i].manufacturer));
                deviceObj.Set("vendorId", Napi::String::New(env, devices[i].vendorId));
                deviceObj.Set("productId", Napi::String::New(env, devices[i].productId));
                deviceObj.Set("isExternal", Napi::Boolean::New(env, devices[i].isExternal));
                deviceObj.Set("isVirtual", Napi::Boolean::New(env, devices[i].isVirtual));
                deviceObj.Set("isSpoofed", Napi::Boolean::New(env, devices[i].isSpoofed));
                deviceObj.Set("threatLevel", Napi::Number::New(env, devices[i].threatLevel));
                deviceObj.Set("threatReason", Napi::String::New(env, devices[i].threatReason));
                deviceObj.Set("isAllowed", Napi::Boolean::New(env, devices[i].isAllowed));

                result[i] = deviceObj;
            }

            return result;
        } catch (const std::exception& e) {
            Napi::Error::New(env, std::string("Error scanning video devices: ") + e.what()).ThrowAsJavaScriptException();
            return env.Null();
        }
    }));

    // Legacy compatibility
    exports.Set(Napi::String::New(env, "start"), Napi::Function::New(env, Start));
    exports.Set(Napi::String::New(env, "stop"), Napi::Function::New(env, Stop));
    
    return exports;
}

NODE_API_MODULE(proctor_native, Init)