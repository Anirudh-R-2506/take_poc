#ifndef SMART_DEVICE_DETECTOR_H
#define SMART_DEVICE_DETECTOR_H

#include <napi.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <chrono>
#include <atomic>
#include <thread>
#include "CommonTypes.h"
#include "SystemDetector.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <setupapi.h>
#include <winusb.h>
#include <bluetoothapis.h>
#include <iphlpapi.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <oleauto.h>
#include <dshow.h>
#elif __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/hid/IOHIDLib.h>
#include <IOKit/usb/IOUSBLib.h>
#include <IOKit/network/IOEthernetInterface.h>
#include <IOKit/storage/IOBlockStorageDriver.h>
#include <IOKit/graphics/IOGraphicsLib.h>
#include <SystemConfiguration/SystemConfiguration.h>
#endif

struct DeviceViolation
{
    std::string deviceId;
    std::string deviceName;
    std::string violationType;
    int severity; // 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL
    std::string reason;
    std::string evidence;
    std::chrono::milliseconds timestamp;
    bool persistent; // True if device remains connected

    DeviceViolation() : severity(1), persistent(false),
                        timestamp(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())) {}
};

struct SystemSecurityProfile
{
    SystemType systemType;
    int allowedMice;
    int allowedKeyboards;
    int allowedDisplays;
    bool allowBluetooth;
    bool allowWireless;
    bool allowVirtualDevices;
    bool allowExternalStorage;
    bool allowExternalWebcams;
    bool strictMode;

    SystemSecurityProfile() : systemType(SystemType::UNKNOWN), allowedMice(0), allowedKeyboards(0),
                              allowedDisplays(1), allowBluetooth(false), allowWireless(false),
                              allowVirtualDevices(false), allowExternalStorage(false),
                              allowExternalWebcams(true), strictMode(true) {}
};

class SmartDeviceDetector
{
public:
    SmartDeviceDetector();
    ~SmartDeviceDetector();

    void Start(Napi::Function callback, int intervalMs = 1000);
    void Stop();
    bool IsRunning() const;

    // Device Detection Methods
    std::vector<InputDeviceInfo> ScanAllInputDevices();
    std::vector<StorageDeviceInfo> ScanAllStorageDevices();
    std::vector<DeviceViolation> GetActiveViolations();
    SystemSecurityProfile GetSecurityProfile();

    // Threat Analysis
    bool AnalyzeDeviceThreat(const InputDeviceInfo &device);
    int CalculateThreatLevel(const InputDeviceInfo &device);
    std::string GetThreatReason(const InputDeviceInfo &device);

    // Security Policy
    void SetSystemType(SystemType type);
    void UpdateSecurityProfile();
    bool IsDeviceAllowed(const InputDeviceInfo &device);

    // Advanced Detection
    bool DetectVirtualDevices();
    bool DetectSpoofedDevices();
    bool DetectSecondaryDisplays();
    bool DetectNetworkInterfaces();
    bool DetectMobileDevices();
    bool DetectBluetoothSpoofers();

    // Webcam Detection & Analysis
    std::vector<InputDeviceInfo> ScanVideoDevices();
    bool IsLegitimateWebcam(const InputDeviceInfo &device);
    bool IsVirtualCamera(const InputDeviceInfo &device);
    bool IsWebcamAllowed(const InputDeviceInfo &device);

private:
    std::atomic<bool> running_;
    std::atomic<int> counter_;
    std::thread worker_thread_;
    Napi::FunctionReference callback_;
    Napi::ThreadSafeFunction tsfn_;
    int intervalMs_;

    SystemDetector *systemDetector_;
    SystemSecurityProfile securityProfile_;
    std::vector<DeviceViolation> activeViolations_;
    std::vector<InputDeviceInfo> lastKnownDevices_;
    std::set<std::string> allowedDeviceIds_;
    std::set<std::string> suspiciousVendors_;
    std::set<std::string> virtualDevicePatterns_;
    std::map<std::string, std::string> knownSpoofers_;

    void MonitoringLoop();
    void ScanAndAnalyzeDevices();
    void EmitViolation(const DeviceViolation &violation);
    void EmitHeartbeat();

    // Platform-specific implementations
#ifdef _WIN32
    std::vector<InputDeviceInfo> ScanWindowsInputDevices();
    std::vector<StorageDeviceInfo> ScanWindowsStorageDevices();
    bool DetectWindowsVirtualDevices();
    bool DetectWindowsSecondaryDisplays();
    bool DetectWindowsNetworkInterfaces();
    bool DetectWindowsMobileDevices();
    bool DetectWindowsBluetoothDevices();
    void ScanWMIDevices(IWbemServices *pSvc, const wchar_t *query, std::vector<InputDeviceInfo> &devices, const std::string &deviceType);
    bool DetectExternalDevice(const InputDeviceInfo &device);
    std::string ConvertBSTRToString(BSTR bstr);
    void ExtractVendorProductIds(const std::string &deviceId, std::string &vendorId, std::string &productId);
    bool IsBuiltInCamera(const InputDeviceInfo &device);
#elif __APPLE__
    std::vector<InputDeviceInfo> ScanMacOSInputDevices();
    std::vector<StorageDeviceInfo> ScanMacOSStorageDevices();
    bool DetectMacOSVirtualDevices();
    bool DetectMacOSSecondaryDisplays();
    bool DetectMacOSNetworkInterfaces();
    bool DetectMacOSMobileDevices();
    bool DetectMacOSBluetoothDevices();
    std::string GetIORegistryProperty(io_service_t service, const char *property);
    bool IsVirtualIOService(io_service_t service);
#endif

    // Threat Detection Patterns
    void InitializeThreatPatterns();
    void InitializeSuspiciousVendors();
    void InitializeVirtualDevicePatterns();
    void InitializeKnownSpoofers();

    // Device Classification
    bool IsMouseDevice(const InputDeviceInfo &device);
    bool IsKeyboardDevice(const InputDeviceInfo &device);
    bool IsVirtualDevice(const InputDeviceInfo &device);
    bool IsSpoofedDevice(const InputDeviceInfo &device);
    bool IsBluetoothDevice(const InputDeviceInfo &device);
    bool IsWirelessDevice(const InputDeviceInfo &device);

    // Wired Device Detection
    bool HasWiredMouse();
    bool HasWiredKeyboard();
    int CountBluetoothMice();
    int CountBluetoothKeyboards();

    // Enhanced Bluetooth Detection
#ifdef _WIN32
    bool DetectNonInputBluetoothDevices();
#elif __APPLE__
    bool DetectNonInputBluetoothDevices();
#endif

    // Video Device Classification
    int CalculateVideoDeviceThreatLevel(const InputDeviceInfo &device);
    std::string GetVideoDeviceThreatReason(const InputDeviceInfo &device);

    // Security Utilities
    std::string NormalizeDeviceName(const std::string &name);
    std::string ExtractVendorFromName(const std::string &name);
    bool MatchesPattern(const std::string &text, const std::string &pattern);
    void LogSecurityEvent(const std::string &event, int severity);
};

#endif // SMART_DEVICE_DETECTOR_H