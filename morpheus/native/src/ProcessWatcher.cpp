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
                                   lastRecordingState_(false), recordingConfidenceThreshold_(0.75), overlayConfidenceThreshold_(0.6),
                                   lastNetworkScan_(std::chrono::steady_clock::now()) {

    // Initialize comprehensive 2025 blacklists
    InitializeComprehensiveBlacklist2025();
    InitializeAIToolPatterns();
    InitializeBrowserPatterns();
    InitializeRemoteAccessPatterns();
    InitializeScreenSharingPatterns();
    InitializeVPNPatterns();

    // Legacy compatibility
    InitializeRecordingBlacklist();

    // Legacy blacklist for backward compatibility
    blacklist_.insert("chrome");
    blacklist_.insert("chrome.exe");
    blacklist_.insert("Google Chrome");
    blacklist_.insert("Google Chrome Helper");
    blacklist_.insert("Google Chrome Helper (Renderer)");
    blacklist_.insert("Chromium");
    blacklist_.insert("chromium");
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
        } catch (const std::exception&) {
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

// COMPREHENSIVE 2025 BLACKLIST INITIALIZATION METHODS

void ProcessWatcher::InitializeComprehensiveBlacklist2025() {
    // Initialize comprehensive threat database with categories and levels

    // AI Tools - CRITICAL THREAT LEVEL
    comprehensiveBlacklist_["ChatGPT"] = ProcessCategory::AI_TOOL;
    comprehensiveBlacklist_["claude"] = ProcessCategory::AI_TOOL;
    comprehensiveBlacklist_["gemini"] = ProcessCategory::AI_TOOL;
    comprehensiveBlacklist_["copilot"] = ProcessCategory::AI_TOOL;
    comprehensiveBlacklist_["perplexity"] = ProcessCategory::AI_TOOL;
    comprehensiveBlacklist_["grok"] = ProcessCategory::AI_TOOL;
    comprehensiveBlacklist_["monica"] = ProcessCategory::AI_TOOL;
    comprehensiveBlacklist_["sider"] = ProcessCategory::AI_TOOL;
    comprehensiveBlacklist_["harpa"] = ProcessCategory::AI_TOOL;
    comprehensiveBlacklist_["jasper"] = ProcessCategory::AI_TOOL;
    comprehensiveBlacklist_["writesonic"] = ProcessCategory::AI_TOOL;
    comprehensiveBlacklist_["copy.ai"] = ProcessCategory::AI_TOOL;
    comprehensiveBlacklist_["grammarly"] = ProcessCategory::AI_TOOL;
    comprehensiveBlacklist_["quillbot"] = ProcessCategory::AI_TOOL;
    comprehensiveBlacklist_["notion-ai"] = ProcessCategory::AI_TOOL;
    comprehensiveBlacklist_["github-copilot"] = ProcessCategory::AI_TOOL;
    comprehensiveBlacklist_["codeium"] = ProcessCategory::AI_TOOL;

    // Set threat levels for AI tools
    threatDatabase_["ChatGPT"] = ThreatLevel::CRITICAL;
    threatDatabase_["claude"] = ThreatLevel::CRITICAL;
    threatDatabase_["gemini"] = ThreatLevel::CRITICAL;
    threatDatabase_["copilot"] = ThreatLevel::CRITICAL;
    threatDatabase_["perplexity"] = ThreatLevel::CRITICAL;
    threatDatabase_["grok"] = ThreatLevel::CRITICAL;
    threatDatabase_["monica"] = ThreatLevel::HIGH;
    threatDatabase_["sider"] = ThreatLevel::HIGH;
    threatDatabase_["harpa"] = ThreatLevel::HIGH;
    threatDatabase_["jasper"] = ThreatLevel::HIGH;
    threatDatabase_["writesonic"] = ThreatLevel::HIGH;
    threatDatabase_["copy.ai"] = ThreatLevel::HIGH;
    threatDatabase_["grammarly"] = ThreatLevel::MEDIUM;
    threatDatabase_["quillbot"] = ThreatLevel::HIGH;
    threatDatabase_["notion-ai"] = ThreatLevel::HIGH;
    threatDatabase_["github-copilot"] = ThreatLevel::CRITICAL;
    threatDatabase_["codeium"] = ThreatLevel::HIGH;
}

void ProcessWatcher::InitializeAIToolPatterns() {
    // AI Assistant patterns
    aiToolPatterns_.insert("chatgpt");
    aiToolPatterns_.insert("openai");
    aiToolPatterns_.insert("claude");
    aiToolPatterns_.insert("anthropic");
    aiToolPatterns_.insert("gemini");
    aiToolPatterns_.insert("bard");
    aiToolPatterns_.insert("copilot");
    aiToolPatterns_.insert("github copilot");
    aiToolPatterns_.insert("perplexity");
    aiToolPatterns_.insert("grok");
    aiToolPatterns_.insert("monica");
    aiToolPatterns_.insert("sider");
    aiToolPatterns_.insert("harpa");
    aiToolPatterns_.insert("jasper");
    aiToolPatterns_.insert("writesonic");
    aiToolPatterns_.insert("copy.ai");
    aiToolPatterns_.insert("copyai");
    aiToolPatterns_.insert("grammarly");
    aiToolPatterns_.insert("quillbot");
    aiToolPatterns_.insert("notion ai");
    aiToolPatterns_.insert("codeium");
    aiToolPatterns_.insert("tabnine");
    aiToolPatterns_.insert("cursor");
    aiToolPatterns_.insert("replit");
    aiToolPatterns_.insert("codewhisperer");

    // AI Browser Extensions
    aiToolPatterns_.insert("chatgpt-extension");
    aiToolPatterns_.insert("claude-extension");
    aiToolPatterns_.insert("gemini-extension");
    aiToolPatterns_.insert("copilot-extension");
    aiToolPatterns_.insert("monica-extension");
    aiToolPatterns_.insert("sider-extension");
    aiToolPatterns_.insert("harpa-ai");
    aiToolPatterns_.insert("merlin");
    aiToolPatterns_.insert("wiseone");
    aiToolPatterns_.insert("compose-ai");
    aiToolPatterns_.insert("wordtune");
}

void ProcessWatcher::InitializeBrowserPatterns() {
    // Primary Browsers - HIGH THREAT
    comprehensiveBlacklist_["chrome"] = ProcessCategory::BROWSER;
    comprehensiveBlacklist_["firefox"] = ProcessCategory::BROWSER;
    comprehensiveBlacklist_["safari"] = ProcessCategory::BROWSER;
    comprehensiveBlacklist_["edge"] = ProcessCategory::BROWSER;
    comprehensiveBlacklist_["opera"] = ProcessCategory::BROWSER;
    comprehensiveBlacklist_["brave"] = ProcessCategory::BROWSER;
    comprehensiveBlacklist_["arc"] = ProcessCategory::BROWSER;
    comprehensiveBlacklist_["vivaldi"] = ProcessCategory::BROWSER;
    comprehensiveBlacklist_["tor"] = ProcessCategory::BROWSER;
    comprehensiveBlacklist_["waterfox"] = ProcessCategory::BROWSER;
    comprehensiveBlacklist_["librewolf"] = ProcessCategory::BROWSER;

    // Developer/Alternative Browsers
    comprehensiveBlacklist_["chromium"] = ProcessCategory::BROWSER;
    comprehensiveBlacklist_["chrome-dev"] = ProcessCategory::BROWSER;
    comprehensiveBlacklist_["chrome-canary"] = ProcessCategory::BROWSER;
    comprehensiveBlacklist_["firefox-dev"] = ProcessCategory::BROWSER;
    comprehensiveBlacklist_["firefox-nightly"] = ProcessCategory::BROWSER;
    comprehensiveBlacklist_["safari-technology-preview"] = ProcessCategory::BROWSER;
    comprehensiveBlacklist_["edge-dev"] = ProcessCategory::BROWSER;
    comprehensiveBlacklist_["edge-beta"] = ProcessCategory::BROWSER;
    comprehensiveBlacklist_["opera-gx"] = ProcessCategory::BROWSER;
    comprehensiveBlacklist_["opera-developer"] = ProcessCategory::BROWSER;
    comprehensiveBlacklist_["brave-nightly"] = ProcessCategory::BROWSER;

    // Set threat levels for browsers
    threatDatabase_["chrome"] = ThreatLevel::HIGH;
    threatDatabase_["firefox"] = ThreatLevel::HIGH;
    threatDatabase_["safari"] = ThreatLevel::HIGH;
    threatDatabase_["edge"] = ThreatLevel::HIGH;
    threatDatabase_["opera"] = ThreatLevel::HIGH;
    threatDatabase_["brave"] = ThreatLevel::MEDIUM;
    threatDatabase_["arc"] = ThreatLevel::HIGH;
    threatDatabase_["vivaldi"] = ThreatLevel::HIGH;
    threatDatabase_["tor"] = ThreatLevel::CRITICAL;

    // Browser process patterns
    browserExtensionPatterns_.insert("chrome.exe");
    browserExtensionPatterns_.insert("firefox.exe");
    browserExtensionPatterns_.insert("msedge.exe");
    browserExtensionPatterns_.insert("safari.exe");
    browserExtensionPatterns_.insert("opera.exe");
    browserExtensionPatterns_.insert("brave.exe");
    browserExtensionPatterns_.insert("arc.exe");
    browserExtensionPatterns_.insert("vivaldi.exe");
}

void ProcessWatcher::InitializeRemoteAccessPatterns() {
    // Remote Access Tools - CRITICAL THREAT
    comprehensiveBlacklist_["teamviewer"] = ProcessCategory::REMOTE_ACCESS;
    comprehensiveBlacklist_["anydesk"] = ProcessCategory::REMOTE_ACCESS;
    comprehensiveBlacklist_["chrome-remote-desktop"] = ProcessCategory::REMOTE_ACCESS;
    comprehensiveBlacklist_["parsec"] = ProcessCategory::REMOTE_ACCESS;
    comprehensiveBlacklist_["splashtop"] = ProcessCategory::REMOTE_ACCESS;
    comprehensiveBlacklist_["logmein"] = ProcessCategory::REMOTE_ACCESS;
    comprehensiveBlacklist_["remotepc"] = ProcessCategory::REMOTE_ACCESS;
    comprehensiveBlacklist_["ammyy"] = ProcessCategory::REMOTE_ACCESS;
    comprehensiveBlacklist_["ultraviewer"] = ProcessCategory::REMOTE_ACCESS;
    comprehensiveBlacklist_["supremo"] = ProcessCategory::REMOTE_ACCESS;
    comprehensiveBlacklist_["connectwise"] = ProcessCategory::REMOTE_ACCESS;
    comprehensiveBlacklist_["bomgar"] = ProcessCategory::REMOTE_ACCESS;
    comprehensiveBlacklist_["jump-desktop"] = ProcessCategory::REMOTE_ACCESS;
    comprehensiveBlacklist_["screens"] = ProcessCategory::REMOTE_ACCESS;
    comprehensiveBlacklist_["gotomypc"] = ProcessCategory::REMOTE_ACCESS;
    comprehensiveBlacklist_["join.me"] = ProcessCategory::REMOTE_ACCESS;
    comprehensiveBlacklist_["dameware"] = ProcessCategory::REMOTE_ACCESS;
    comprehensiveBlacklist_["radmin"] = ProcessCategory::REMOTE_ACCESS;

    // Set threat levels
    threatDatabase_["teamviewer"] = ThreatLevel::CRITICAL;
    threatDatabase_["anydesk"] = ThreatLevel::CRITICAL;
    threatDatabase_["chrome-remote-desktop"] = ThreatLevel::CRITICAL;
    threatDatabase_["parsec"] = ThreatLevel::CRITICAL;
    threatDatabase_["splashtop"] = ThreatLevel::CRITICAL;
    threatDatabase_["logmein"] = ThreatLevel::CRITICAL;
    threatDatabase_["remotepc"] = ThreatLevel::CRITICAL;
    threatDatabase_["ammyy"] = ThreatLevel::CRITICAL;
    threatDatabase_["ultraviewer"] = ThreatLevel::CRITICAL;
    threatDatabase_["supremo"] = ThreatLevel::CRITICAL;

    remoteAccessPatterns_.insert("teamviewer");
    remoteAccessPatterns_.insert("anydesk");
    remoteAccessPatterns_.insert("chrome-remote");
    remoteAccessPatterns_.insert("parsec");
    remoteAccessPatterns_.insert("splashtop");
    remoteAccessPatterns_.insert("logmein");
    remoteAccessPatterns_.insert("remotepc");
    remoteAccessPatterns_.insert("ammyy");
    remoteAccessPatterns_.insert("ultraviewer");
    remoteAccessPatterns_.insert("supremo");
    remoteAccessPatterns_.insert("connectwise");
    remoteAccessPatterns_.insert("bomgar");
    remoteAccessPatterns_.insert("jump desktop");
    remoteAccessPatterns_.insert("screens");
    remoteAccessPatterns_.insert("gotomypc");
    remoteAccessPatterns_.insert("join.me");
    remoteAccessPatterns_.insert("dameware");
    remoteAccessPatterns_.insert("radmin");
}

void ProcessWatcher::InitializeScreenSharingPatterns() {
    // Video Conferencing & Screen Sharing - HIGH THREAT
    comprehensiveBlacklist_["zoom"] = ProcessCategory::SCREEN_SHARING;
    comprehensiveBlacklist_["teams"] = ProcessCategory::SCREEN_SHARING;
    comprehensiveBlacklist_["slack"] = ProcessCategory::SCREEN_SHARING;
    comprehensiveBlacklist_["discord"] = ProcessCategory::SCREEN_SHARING;
    comprehensiveBlacklist_["skype"] = ProcessCategory::SCREEN_SHARING;
    comprehensiveBlacklist_["webex"] = ProcessCategory::SCREEN_SHARING;
    comprehensiveBlacklist_["gotomeeting"] = ProcessCategory::SCREEN_SHARING;
    comprehensiveBlacklist_["bluejeans"] = ProcessCategory::SCREEN_SHARING;
    comprehensiveBlacklist_["jitsi"] = ProcessCategory::SCREEN_SHARING;
    comprehensiveBlacklist_["whereby"] = ProcessCategory::SCREEN_SHARING;
    comprehensiveBlacklist_["meet"] = ProcessCategory::SCREEN_SHARING;
    comprehensiveBlacklist_["facetime"] = ProcessCategory::SCREEN_SHARING;
    comprehensiveBlacklist_["whatsapp"] = ProcessCategory::SCREEN_SHARING;
    comprehensiveBlacklist_["telegram"] = ProcessCategory::SCREEN_SHARING;
    comprehensiveBlacklist_["signal"] = ProcessCategory::SCREEN_SHARING;
    comprehensiveBlacklist_["viber"] = ProcessCategory::SCREEN_SHARING;

    // Gaming & Streaming
    comprehensiveBlacklist_["obs-studio"] = ProcessCategory::RECORDING;
    comprehensiveBlacklist_["streamlabs"] = ProcessCategory::RECORDING;
    comprehensiveBlacklist_["xsplit"] = ProcessCategory::RECORDING;
    comprehensiveBlacklist_["nvidia-broadcast"] = ProcessCategory::RECORDING;
    comprehensiveBlacklist_["elgato-stream-deck"] = ProcessCategory::RECORDING;
    comprehensiveBlacklist_["twitch-studio"] = ProcessCategory::RECORDING;
    comprehensiveBlacklist_["restream"] = ProcessCategory::RECORDING;
    comprehensiveBlacklist_["streamyard"] = ProcessCategory::RECORDING;
    comprehensiveBlacklist_["wirecast"] = ProcessCategory::RECORDING;
    comprehensiveBlacklist_["vmix"] = ProcessCategory::RECORDING;
    comprehensiveBlacklist_["bandicam"] = ProcessCategory::RECORDING;
    comprehensiveBlacklist_["camtasia"] = ProcessCategory::RECORDING;
    comprehensiveBlacklist_["screenflow"] = ProcessCategory::RECORDING;

    // Set threat levels
    threatDatabase_["zoom"] = ThreatLevel::HIGH;
    threatDatabase_["teams"] = ThreatLevel::HIGH;
    threatDatabase_["slack"] = ThreatLevel::HIGH;
    threatDatabase_["discord"] = ThreatLevel::HIGH;
    threatDatabase_["skype"] = ThreatLevel::HIGH;
    threatDatabase_["obs-studio"] = ThreatLevel::CRITICAL;
    threatDatabase_["streamlabs"] = ThreatLevel::CRITICAL;
    threatDatabase_["xsplit"] = ThreatLevel::CRITICAL;

    screenSharingPatterns_.insert("zoom");
    screenSharingPatterns_.insert("teams");
    screenSharingPatterns_.insert("microsoft teams");
    screenSharingPatterns_.insert("slack");
    screenSharingPatterns_.insert("discord");
    screenSharingPatterns_.insert("skype");
    screenSharingPatterns_.insert("webex");
    screenSharingPatterns_.insert("gotomeeting");
    screenSharingPatterns_.insert("bluejeans");
    screenSharingPatterns_.insert("jitsi");
    screenSharingPatterns_.insert("whereby");
    screenSharingPatterns_.insert("meet");
    screenSharingPatterns_.insert("google meet");
    screenSharingPatterns_.insert("facetime");
    screenSharingPatterns_.insert("whatsapp");
    screenSharingPatterns_.insert("telegram");
    screenSharingPatterns_.insert("signal");
    screenSharingPatterns_.insert("viber");
}

void ProcessWatcher::InitializeVPNPatterns() {
    // VPN Applications - MEDIUM to HIGH THREAT
    comprehensiveBlacklist_["nordvpn"] = ProcessCategory::VPN_TOOL;
    comprehensiveBlacklist_["expressvpn"] = ProcessCategory::VPN_TOOL;
    comprehensiveBlacklist_["surfshark"] = ProcessCategory::VPN_TOOL;
    comprehensiveBlacklist_["cyberghost"] = ProcessCategory::VPN_TOOL;
    comprehensiveBlacklist_["ipvanish"] = ProcessCategory::VPN_TOOL;
    comprehensiveBlacklist_["private-internet-access"] = ProcessCategory::VPN_TOOL;
    comprehensiveBlacklist_["tunnelbear"] = ProcessCategory::VPN_TOOL;
    comprehensiveBlacklist_["windscribe"] = ProcessCategory::VPN_TOOL;
    comprehensiveBlacklist_["protonvpn"] = ProcessCategory::VPN_TOOL;
    comprehensiveBlacklist_["mullvad"] = ProcessCategory::VPN_TOOL;
    comprehensiveBlacklist_["hotspot-shield"] = ProcessCategory::VPN_TOOL;
    comprehensiveBlacklist_["zenmate"] = ProcessCategory::VPN_TOOL;

    // Set threat levels
    threatDatabase_["nordvpn"] = ThreatLevel::MEDIUM;
    threatDatabase_["expressvpn"] = ThreatLevel::MEDIUM;
    threatDatabase_["surfshark"] = ThreatLevel::MEDIUM;
    threatDatabase_["cyberghost"] = ThreatLevel::MEDIUM;
    threatDatabase_["protonvpn"] = ThreatLevel::HIGH;
    threatDatabase_["mullvad"] = ThreatLevel::HIGH;

    vpnPatterns_.insert("nordvpn");
    vpnPatterns_.insert("expressvpn");
    vpnPatterns_.insert("surfshark");
    vpnPatterns_.insert("cyberghost");
    vpnPatterns_.insert("ipvanish");
    vpnPatterns_.insert("pia");
    vpnPatterns_.insert("private internet access");
    vpnPatterns_.insert("tunnelbear");
    vpnPatterns_.insert("windscribe");
    vpnPatterns_.insert("protonvpn");
    vpnPatterns_.insert("mullvad");
    vpnPatterns_.insert("hotspot shield");
    vpnPatterns_.insert("zenmate");
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

    } catch (const std::exception&) {
        result.eventType = "error";
    }

    return result;
}

std::vector<OverlayWindow> ProcessWatcher::DetectOverlayWindows() {
    std::vector<OverlayWindow> overlays;

#ifdef _WIN32
    // Process-centric overlay detection focuses on windows created by suspicious processes
    // This complements ScreenWatcher's window-centric overlay detection
    std::vector<ProcessInfo> currentProcesses = GetRunningProcesses();

    // First, identify suspicious processes that might create overlays
    std::vector<ProcessInfo> suspiciousProcesses;
    std::set<std::string> suspiciousPatterns = {
        "cheat", "hack", "trainer", "mod", "inject", "dll", "hook",
        "overlay", "bot", "assist", "auto", "exploit", "bypass",
        "memory", "edit", "scan", "patch", "debug"
    };

    for (const auto& process : currentProcesses) {
        std::string lowerName = process.name;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

        for (const auto& pattern : suspiciousPatterns) {
            if (lowerName.find(pattern) != std::string::npos) {
                suspiciousProcesses.push_back(process);
                break;
            }
        }
    }

    // Now enumerate windows and correlate with suspicious processes
    auto contextPair = std::make_pair(&overlays, &suspiciousProcesses);
    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto* context = reinterpret_cast<std::pair<std::vector<OverlayWindow>*, std::vector<ProcessInfo>*>*>(lParam);
        auto* overlaysPtr = context->first;
        auto* suspiciousProcessesPtr = context->second;

        if (!IsWindowVisible(hwnd)) {
            return TRUE;
        }

        // Get window's process ID
        DWORD windowPid;
        GetWindowThreadProcessId(hwnd, &windowPid);

        // Check if this window belongs to a suspicious process
        bool isSuspiciousProcess = false;
        std::string suspiciousProcessName;
        for (const auto& suspProcess : *suspiciousProcessesPtr) {
            if (suspProcess.pid == static_cast<int>(windowPid)) {
                isSuspiciousProcess = true;
                suspiciousProcessName = suspProcess.name;
                break;
            }
        }

        LONG_PTR style = GetWindowLongPtrW(hwnd, GWL_STYLE);
        LONG_PTR exStyle = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);

        bool isLayered = (exStyle & WS_EX_LAYERED) != 0;
        bool isTopmost = (exStyle & WS_EX_TOPMOST) != 0;
        bool isToolWindow = (exStyle & WS_EX_TOOLWINDOW) != 0;
        bool isTransparent = (exStyle & WS_EX_TRANSPARENT) != 0;
        bool isNoActivate = (exStyle & WS_EX_NOACTIVATE) != 0;

        // Process-centric detection: Focus on overlay characteristics + suspicious processes
        bool hasOverlayCharacteristics = isLayered || isTopmost || isToolWindow ||
                                        isTransparent || isNoActivate;

        // Include windows that either:
        // 1. Belong to suspicious processes (regardless of overlay characteristics)
        // 2. Have overlay characteristics (regardless of process)
        if (!isSuspiciousProcess && !hasOverlayCharacteristics) {
            return TRUE;
        }

        OverlayWindow overlay;

        // Get process information
        overlay.pid = static_cast<int>(windowPid);
        if (isSuspiciousProcess) {
            overlay.processName = suspiciousProcessName;
        } else {
            // Get process name for non-suspicious processes with overlay characteristics
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, windowPid);
            if (hProcess) {
                wchar_t processPath[MAX_PATH];
                DWORD pathSize = MAX_PATH;
                if (QueryFullProcessImageNameW(hProcess, 0, processPath, &pathSize)) {
                    std::wstring processPathW(processPath);
                    std::string processPathStr(processPathW.begin(), processPathW.end());
                    size_t lastSlash = processPathStr.find_last_of("\\/");
                    overlay.processName = (lastSlash != std::string::npos) ?
                        processPathStr.substr(lastSlash + 1) : processPathStr;
                }
                CloseHandle(hProcess);
            }
        }

        // Get window geometry
        RECT rect;
        if (GetWindowRect(hwnd, &rect)) {
            overlay.bounds.x = rect.left;
            overlay.bounds.y = rect.top;
            overlay.bounds.w = rect.right - rect.left;
            overlay.bounds.h = rect.bottom - rect.top;
        }

        // Get window handle
        std::ostringstream oss;
        oss << "0x" << std::hex << reinterpret_cast<uintptr_t>(hwnd);
        overlay.windowHandle = oss.str();

        // Calculate confidence with process-centric weighting
        overlay.confidence = 0.0;

        // Heavy penalty for suspicious process names
        if (isSuspiciousProcess) {
            overlay.confidence += 0.60;  // Very high base confidence for known suspicious processes
        }

        // Standard overlay characteristics
        if (isLayered) overlay.confidence += 0.20;
        if (isTopmost) overlay.confidence += 0.25;
        if (isToolWindow) overlay.confidence += 0.15;
        if (isTransparent) overlay.confidence += 0.30;  // Click-through overlays are very suspicious
        if (isNoActivate) overlay.confidence += 0.15;

        // Size-based scoring (small overlays are more suspicious)
        int area = overlay.bounds.w * overlay.bounds.h;
        if (area > 0 && area < 10000) {  // Very small windows
            overlay.confidence += 0.20;
        } else if (area < 50000) {  // Small windows
            overlay.confidence += 0.10;
        }

        // Transparency analysis for layered windows
        if (isLayered) {
            COLORREF colorKey;
            BYTE alpha;
            DWORD flags;
            if (GetLayeredWindowAttributes(hwnd, &colorKey, &alpha, &flags)) {
                overlay.alpha = alpha / 255.0;
                if (alpha < 255 && alpha > 0) {
                    float transparencyScore = (255.0f - alpha) / 255.0f;
                    overlay.confidence += transparencyScore * 0.25;
                }
            }
        }

        // Cap confidence
        overlay.confidence = std::min(overlay.confidence, 1.0);

        // Process-centric threshold: lower threshold due to process correlation
        if (overlay.confidence >= 0.25) {
            overlaysPtr->push_back(overlay);
        }

        return TRUE;
    }, reinterpret_cast<LPARAM>(&contextPair));

#endif // _WIN32

    return overlays;
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

ProcessCategory ProcessWatcher::CategorizeProcess(const ProcessInfo& process) {
    std::string lowerName = process.name;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

    std::string lowerPath = process.path;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::tolower);

    // Check comprehensive blacklist first
    auto it = comprehensiveBlacklist_.find(lowerName);
    if (it != comprehensiveBlacklist_.end()) {
        return it->second;
    }

    // Pattern-based detection for unlisted processes
    if (aiToolPatterns_.count(lowerName) ||
        lowerName.find("chatgpt") != std::string::npos ||
        lowerName.find("claude") != std::string::npos ||
        lowerName.find("gemini") != std::string::npos ||
        lowerName.find("copilot") != std::string::npos) {
        return ProcessCategory::AI_TOOL;
    }

    if (browserExtensionPatterns_.count(lowerName) ||
        lowerName.find("chrome") != std::string::npos ||
        lowerName.find("firefox") != std::string::npos ||
        lowerName.find("safari") != std::string::npos ||
        lowerName.find("edge") != std::string::npos) {
        return ProcessCategory::BROWSER;
    }

    if (screenSharingPatterns_.count(lowerName) ||
        lowerName.find("zoom") != std::string::npos ||
        lowerName.find("teams") != std::string::npos ||
        lowerName.find("meet") != std::string::npos ||
        lowerName.find("webex") != std::string::npos) {
        return ProcessCategory::SCREEN_SHARING;
    }

    if (remoteAccessPatterns_.count(lowerName) ||
        lowerName.find("teamviewer") != std::string::npos ||
        lowerName.find("anydesk") != std::string::npos ||
        lowerName.find("rdp") != std::string::npos ||
        lowerName.find("vnc") != std::string::npos) {
        return ProcessCategory::REMOTE_ACCESS;
    }

    if (vpnPatterns_.count(lowerName) ||
        lowerName.find("vpn") != std::string::npos ||
        lowerName.find("nordvpn") != std::string::npos ||
        lowerName.find("expressvpn") != std::string::npos) {
        return ProcessCategory::VPN_TOOL;
    }

    // Development tools
    if (lowerName.find("code") != std::string::npos ||
        lowerName.find("studio") != std::string::npos ||
        lowerName.find("terminal") != std::string::npos ||
        lowerName.find("cmd") != std::string::npos ||
        lowerName.find("powershell") != std::string::npos) {
        return ProcessCategory::DEVELOPMENT;
    }

    // Virtual machines
    if (lowerName.find("vmware") != std::string::npos ||
        lowerName.find("virtualbox") != std::string::npos ||
        lowerName.find("parallels") != std::string::npos) {
        return ProcessCategory::VIRTUAL_MACHINE;
    }

    // Recording tools
    if (lowerName.find("obs") != std::string::npos ||
        lowerName.find("camtasia") != std::string::npos ||
        lowerName.find("bandicam") != std::string::npos ||
        lowerName.find("fraps") != std::string::npos) {
        return ProcessCategory::RECORDING;
    }

    return ProcessCategory::SAFE;
}

ThreatLevel ProcessWatcher::CalculateThreatLevel(const ProcessInfo& process, ProcessCategory category) {
    std::string lowerName = process.name;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

    // Check threat database first
    auto it = threatDatabase_.find(lowerName);
    if (it != threatDatabase_.end()) {
        return it->second;
    }

    // Category-based threat levels
    switch (category) {
        case ProcessCategory::AI_TOOL:
            return ThreatLevel::CRITICAL;
        case ProcessCategory::REMOTE_ACCESS:
            return ThreatLevel::CRITICAL;
        case ProcessCategory::SCREEN_SHARING:
            return ThreatLevel::HIGH;
        case ProcessCategory::BROWSER:
            return ThreatLevel::HIGH;
        case ProcessCategory::VPN_TOOL:
            return ThreatLevel::HIGH;
        case ProcessCategory::RECORDING:
            return ThreatLevel::HIGH;
        case ProcessCategory::DEVELOPMENT:
            return ThreatLevel::MEDIUM;
        case ProcessCategory::VIRTUAL_MACHINE:
            return ThreatLevel::MEDIUM;
        case ProcessCategory::COMMUNICATION:
            return ThreatLevel::MEDIUM;
        case ProcessCategory::OVERLAY_TOOL:
            return ThreatLevel::LOW;
        case ProcessCategory::SAFE:
        default:
            return ThreatLevel::NONE;
    }
}

bool ProcessWatcher::HasScreenCaptureCapability(const ProcessInfo& process) {
    std::string lowerName = process.name;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

    // Check loaded modules for screen capture APIs
    for (const auto& module : process.loadedModules) {
        std::string lowerModule = module;
        std::transform(lowerModule.begin(), lowerModule.end(), lowerModule.begin(), ::tolower);

#ifdef _WIN32
        if (lowerModule.find("dxgi") != std::string::npos ||
            lowerModule.find("d3d11") != std::string::npos ||
            lowerModule.find("gdi32") != std::string::npos ||
            lowerModule.find("user32") != std::string::npos) {
            return true;
        }
#elif __APPLE__
        if (lowerModule.find("screencapturekit") != std::string::npos ||
            lowerModule.find("coregraphics") != std::string::npos ||
            lowerModule.find("avfoundation") != std::string::npos) {
            return true;
        }
#endif
    }

    // Check process name patterns
    return screenSharingPatterns_.count(lowerName) > 0 ||
           lowerName.find("screen") != std::string::npos ||
           lowerName.find("capture") != std::string::npos ||
           lowerName.find("record") != std::string::npos;
}

bool ProcessWatcher::HasRemoteAccessCapability(const ProcessInfo& process) {
    std::string lowerName = process.name;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

    // Check loaded modules for remote access APIs
    for (const auto& module : process.loadedModules) {
        std::string lowerModule = module;
        std::transform(lowerModule.begin(), lowerModule.end(), lowerModule.begin(), ::tolower);

        if (lowerModule.find("rdp") != std::string::npos ||
            lowerModule.find("vnc") != std::string::npos ||
            lowerModule.find("remote") != std::string::npos) {
            return true;
        }
    }

    // Check process name patterns
    return remoteAccessPatterns_.count(lowerName) > 0 ||
           lowerName.find("remote") != std::string::npos ||
           lowerName.find("teamviewer") != std::string::npos ||
           lowerName.find("anydesk") != std::string::npos;
}

std::string ProcessWatcher::GenerateRiskReason(const ProcessInfo& process, ProcessCategory category, ThreatLevel level) {
    std::string reason = "Process: " + process.name;

    switch (category) {
        case ProcessCategory::AI_TOOL:
            reason += " - AI/ML tool that can provide answers or assistance";
            break;
        case ProcessCategory::BROWSER:
            reason += " - Web browser that can access external resources";
            break;
        case ProcessCategory::SCREEN_SHARING:
            reason += " - Screen sharing application that can transmit exam content";
            break;
        case ProcessCategory::REMOTE_ACCESS:
            reason += " - Remote access tool allowing external control";
            break;
        case ProcessCategory::VPN_TOOL:
            reason += " - VPN software that can mask network activity";
            break;
        case ProcessCategory::DEVELOPMENT:
            reason += " - Development tool with potential for code execution";
            break;
        case ProcessCategory::VIRTUAL_MACHINE:
            reason += " - Virtual machine that can run hidden applications";
            break;
        case ProcessCategory::RECORDING:
            reason += " - Recording software that can capture exam content";
            break;
        case ProcessCategory::COMMUNICATION:
            reason += " - Communication app that can be used for cheating";
            break;
        case ProcessCategory::OVERLAY_TOOL:
            reason += " - Overlay tool that can display unauthorized content";
            break;
        default:
            reason += " - Unclassified process";
            break;
    }

    switch (level) {
        case ThreatLevel::CRITICAL:
            reason += " (CRITICAL THREAT)";
            break;
        case ThreatLevel::HIGH:
            reason += " (HIGH THREAT)";
            break;
        case ThreatLevel::MEDIUM:
            reason += " (MEDIUM THREAT)";
            break;
        case ThreatLevel::LOW:
            reason += " (LOW THREAT)";
            break;
        default:
            break;
    }

    return reason;
}

ThreatLevel ProcessWatcher::ClassifyProcess(const ProcessInfo& process) {
    ProcessCategory category = CategorizeProcess(process);
    return CalculateThreatLevel(process, category);
}

std::vector<ProcessInfo> ProcessWatcher::DetectSuspiciousBehavior() {
    std::vector<ProcessInfo> suspiciousProcesses;
    std::vector<ProcessInfo> currentProcesses = GetRunningProcesses();

    for (auto& process : currentProcesses) {
        ProcessCategory category = CategorizeProcess(process);
        ThreatLevel threat = CalculateThreatLevel(process, category);

        if (threat > ThreatLevel::NONE) {
            // Update the process with classification data
            process.threatLevel = static_cast<int>(threat);
            process.category = static_cast<int>(category);
            process.confidence = 0.85; // System-based detection confidence
            process.riskReason = GenerateRiskReason(process, category, threat);
            process.flagged = true;
            process.suspicious = true;
            process.blacklisted = (threat >= ThreatLevel::HIGH);

            suspiciousProcesses.push_back(process);
        }
    }

    return suspiciousProcesses;
}

std::vector<ProcessInfo> ProcessWatcher::GetProcessSnapshot() {
    std::vector<ProcessInfo> currentProcesses = GetRunningProcesses();

    // Classify all processes
    for (auto& process : currentProcesses) {
        ProcessCategory category = CategorizeProcess(process);
        ThreatLevel threat = CalculateThreatLevel(process, category);

        // Update the process with classification data
        process.threatLevel = static_cast<int>(threat);
        process.category = static_cast<int>(category);
        process.confidence = 0.80;
        process.riskReason = GenerateRiskReason(process, category, threat);
        process.flagged = (threat > ThreatLevel::NONE);
        process.suspicious = (threat >= ThreatLevel::MEDIUM);
        process.blacklisted = (threat >= ThreatLevel::HIGH);
    }

    return currentProcesses;
}