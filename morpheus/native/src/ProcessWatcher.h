#ifndef PROCESS_WATCHER_H
#define PROCESS_WATCHER_H

#include <napi.h>
#include <thread>
#include <chrono>
#include <atomic>
#include <string>
#include <vector>
#include <set>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#undef min
#undef max
#endif

#include "CommonTypes.h"

class ProcessWatcher {
public:
    ProcessWatcher();
    ~ProcessWatcher();
    
    void Start(Napi::Function callback, int intervalMs = 1500);
    void Stop();
    void SetBlacklist(const std::vector<std::string>& blacklist);
    void SetRecordingBlacklist(const std::vector<std::string>& recordingBlacklist);
    bool IsRunning() const;
    
    // Public snapshot methods for polling mode
    std::vector<ProcessInfo> GetProcessSnapshot();
    
    // Recording/Overlay detection methods
    RecordingDetectionResult DetectRecordingAndOverlays();
    std::vector<std::string> GetVirtualCameras();
    std::vector<OverlayWindow> GetOverlayWindows();

private:
    std::atomic<bool> running_;
    std::atomic<int> counter_;
    std::thread worker_thread_;
    Napi::FunctionReference callback_;
    Napi::ThreadSafeFunction tsfn_;
    std::set<std::string> blacklist_;
    std::set<std::string> recordingBlacklist_;
    int intervalMs_;
    bool lastDetectionState_;
    std::vector<ProcessInfo> lastBlacklistedProcesses_;
    
    // Recording/Overlay detection state
    bool lastRecordingState_;
    std::vector<OverlayWindow> lastOverlayWindows_;
    double recordingConfidenceThreshold_;
    double overlayConfidenceThreshold_;
    
    void WatcherLoop();
    std::vector<ProcessInfo> GetRunningProcesses();
    std::vector<ProcessInfo> FilterBlacklistedProcesses(const std::vector<ProcessInfo>& processes);
    void EmitDetectionEvent(bool detected, const std::vector<ProcessInfo>& blacklistedProcesses);
    
    // Recording/Overlay detection methods
    std::vector<ProcessInfo> DetectRecordingProcesses(const std::vector<ProcessInfo>& processes);
    std::vector<OverlayWindow> DetectOverlayWindows();
    double CalculateRecordingConfidence(const std::vector<ProcessInfo>& recordingProcesses, const std::vector<std::string>& virtualCameras);
    double CalculateOverlayConfidence(const std::vector<OverlayWindow>& overlayWindows);
    void EmitRecordingOverlayEvent(const RecordingDetectionResult& result);
    void InitializeRecordingBlacklist();
    
    // Platform-specific helper methods
#ifdef _WIN32
    std::string GetProcessPath(DWORD processID);
    std::vector<std::string> GetProcessModules(DWORD processID);
    std::vector<OverlayWindow> EnumerateWindowsForOverlays();
    std::vector<std::string> EnumerateVirtualCameras();
#elif __APPLE__
    std::string ExtractProcessName(const std::string& fullPath);
    std::vector<std::string> GetProcessLibraries(int pid);
    std::vector<OverlayWindow> EnumerateWindowsForOverlays();
    std::vector<std::string> EnumerateVirtualCameras();
#endif
    
    // Utility methods
    std::string EscapeJson(const std::string& str);
    std::string CreateRecordingOverlayEventJson(const RecordingDetectionResult& result);
};

#endif // PROCESS_WATCHER_H