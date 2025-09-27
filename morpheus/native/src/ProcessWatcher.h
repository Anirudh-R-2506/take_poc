#ifndef PROCESS_WATCHER_H
#define PROCESS_WATCHER_H

#include <napi.h>
#include <thread>
#include <chrono>
#include <atomic>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <memory>
#include <regex>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wininet.h>
#include <iphlpapi.h>
#undef min
#undef max
#elif __APPLE__
#include <sys/proc_info.h>
#include <libproc.h>
#include <ApplicationServices/ApplicationServices.h>
#include <CoreFoundation/CoreFoundation.h>
#endif

#include "CommonTypes.h"

// System-based threat levels for 2025
enum class ThreatLevel {
    NONE = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

// Process categories for system-based classification
enum class ProcessCategory {
    SAFE = 0,
    AI_TOOL = 1,
    BROWSER = 2,
    SCREEN_SHARING = 3,
    REMOTE_ACCESS = 4,
    VPN_TOOL = 5,
    DEVELOPMENT = 6,
    VIRTUAL_MACHINE = 7,
    RECORDING = 8,
    COMMUNICATION = 9,
    OVERLAY_TOOL = 10
};


// Network traffic pattern detection
struct NetworkPattern {
    std::string processName;
    std::vector<std::string> remoteAddresses;
    uint64_t bytesTransferred;
    bool isVideoStream;
    bool isWebRTC;
    bool isVPN;
};

class ProcessWatcher {
public:
    ProcessWatcher();
    ~ProcessWatcher();

    // Core functionality
    void Start(Napi::Function callback, int intervalMs = 1500);
    void Stop();
    void SetBlacklist(const std::vector<std::string>& blacklist);
    void SetRecordingBlacklist(const std::vector<std::string>& recordingBlacklist);
    bool IsRunning() const;

    // 2025 detection methods
    std::vector<ProcessInfo> GetProcessSnapshot();
    RecordingDetectionResult DetectRecordingAndOverlays();
    std::vector<std::string> GetVirtualCameras();
    std::vector<OverlayWindow> GetOverlayWindows();

    // New system-based detection methods
    ThreatLevel ClassifyProcess(const ProcessInfo& process);
    std::vector<ProcessInfo> DetectSuspiciousBehavior();
    std::vector<NetworkPattern> DetectNetworkPatterns();
    std::vector<std::string> ScanBrowserExtensions();
    bool DetectProcessInjection();

private:
    // Core state
    std::atomic<bool> running_;
    std::atomic<int> counter_;
    std::thread worker_thread_;
    Napi::FunctionReference callback_;
    Napi::ThreadSafeFunction tsfn_;
    int intervalMs_;

    // Blacklists for 2025
    std::map<std::string, ProcessCategory> comprehensiveBlacklist_;
    std::map<std::string, ThreatLevel> threatDatabase_;
    std::set<std::string> aiToolPatterns_;
    std::set<std::string> browserExtensionPatterns_;
    std::set<std::string> remoteAccessPatterns_;
    std::set<std::string> screenSharingPatterns_;
    std::set<std::string> vpnPatterns_;

    // Legacy compatibility
    std::set<std::string> blacklist_;
    std::set<std::string> recordingBlacklist_;

    // Detection state
    bool lastDetectionState_;
    std::vector<ProcessInfo> lastBlacklistedProcesses_;
    std::vector<ProcessInfo> lastProcesses_;

    // Recording/Overlay detection state
    bool lastRecordingState_;
    std::vector<OverlayWindow> lastOverlayWindows_;
    double recordingConfidenceThreshold_;
    double overlayConfidenceThreshold_;

    // System classification state
    std::map<std::string, ThreatLevel> processRiskCache_;
    std::vector<NetworkPattern> networkPatterns_;
    std::chrono::steady_clock::time_point lastNetworkScan_;

    // Core loop and detection
    void WatcherLoop();
    std::vector<ProcessInfo> GetRunningProcesses();
    std::vector<ProcessInfo> FilterBlacklistedProcesses(const std::vector<ProcessInfo>& processes);
    std::vector<ProcessInfo> ClassifyProcesses(const std::vector<ProcessInfo>& processes);
    void EmitDetectionEvent(bool detected, const std::vector<ProcessInfo>& blacklistedProcesses);
    void EmitClassifiedDetectionEvent(const std::vector<ProcessInfo>& classifiedProcesses);

    // Recording/Overlay detection
    std::vector<ProcessInfo> DetectRecordingProcesses(const std::vector<ProcessInfo>& processes);
    std::vector<OverlayWindow> DetectOverlayWindows();
    double CalculateRecordingConfidence(const std::vector<ProcessInfo>& recordingProcesses, const std::vector<std::string>& virtualCameras);
    double CalculateOverlayConfidence(const std::vector<OverlayWindow>& overlayWindows);
    void EmitRecordingOverlayEvent(const RecordingDetectionResult& result);

    // Initialization methods
    void InitializeComprehensiveBlacklist2025();
    void InitializeAIToolPatterns();
    void InitializeBrowserPatterns();
    void InitializeRemoteAccessPatterns();
    void InitializeScreenSharingPatterns();
    void InitializeVPNPatterns();
    void InitializeRecordingBlacklist(); // Legacy

    // System-based analysis methods
    ProcessCategory CategorizeProcess(const ProcessInfo& process);
    ThreatLevel CalculateThreatLevel(const ProcessInfo& process, ProcessCategory category);
    bool HasScreenCaptureCapability(const ProcessInfo& process);
    bool HasRemoteAccessCapability(const ProcessInfo& process);
    std::string GenerateRiskReason(const ProcessInfo& process, ProcessCategory category, ThreatLevel level);

    // Network analysis methods
    std::vector<NetworkPattern> ScanNetworkConnections();
    bool IsVideoStreamTraffic(const NetworkPattern& pattern);
    bool IsWebRTCConnection(const NetworkPattern& pattern);
    bool IsVPNConnection(const NetworkPattern& pattern);

    // Browser extension detection
    std::vector<std::string> ScanChromeExtensions();
    std::vector<std::string> ScanFirefoxAddons();
    std::vector<std::string> ScanEdgeExtensions();
    bool IsScreenSharingExtension(const std::string& extension);
    bool IsCheatingExtension(const std::string& extension);
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

    std::string EscapeJson(const std::string& str);
    std::string CreateRecordingOverlayEventJson(const RecordingDetectionResult& result);
};

#endif // PROCESS_WATCHER_H