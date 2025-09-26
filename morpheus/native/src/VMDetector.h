#ifndef VM_DETECTOR_H
#define VM_DETECTOR_H

#include <napi.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <functional>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <intrin.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#elif __APPLE__
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <mach/mach.h>
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#endif

struct VMDetectionResult {
    bool isInsideVM;
    std::string detectedVM;
    std::vector<std::string> runningVMProcesses;
    std::string detectionMethod;
    std::vector<std::string> vmIndicators;
};

class VMDetector {
public:
    VMDetector();
    ~VMDetector();

    VMDetectionResult detectVirtualMachine();
    void Start(Napi::Function callback, int intervalMs = 10000);
    void Stop();
    bool IsRunning() const;
    bool isPlatformSupported();

private:
#ifdef _WIN32
    bool checkWindowsHypervisorBit();
    bool checkWindowsBIOS();
    bool checkWindowsMAC();
    std::vector<std::string> checkWindowsVMProcesses();
    std::string identifyWindowsVM(const std::vector<std::string>& indicators);
#elif __APPLE__
    bool checkMacOSSystemProfiler();
    bool checkMacOSIORegistry();
    bool checkMacOSHypervisorFramework();
    std::vector<std::string> checkMacOSVMProcesses();
    std::string identifyMacOSVM(const std::vector<std::string>& indicators);
#endif

    std::vector<std::string> getRunningProcesses();
    bool containsVMIndicator(const std::string& text);
    std::string determineVMType(const std::vector<std::string>& indicators);
    std::vector<std::string> vmVendorStrings;
    std::vector<std::string> vmProcessNames;
    std::vector<std::string> vmMACPrefixes;
    std::atomic<bool> running_;
    std::atomic<int> counter_;
    std::thread worker_thread_;
    Napi::FunctionReference callback_;
    Napi::ThreadSafeFunction tsfn_;
    int intervalMs_;
    VMDetectionResult lastResult_;

    void initializeVMSignatures();
    void WatcherLoop();
    void EmitVMEvent(const VMDetectionResult& result);
    std::string CreateEventJson(const VMDetectionResult& result);
    std::string EscapeJson(const std::string& str);
};

#endif // VM_DETECTOR_H