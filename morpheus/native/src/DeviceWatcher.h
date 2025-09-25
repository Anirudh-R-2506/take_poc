#ifndef DEVICE_WATCHER_H
#define DEVICE_WATCHER_H

#include <napi.h>
#include <thread>
#include <chrono>
#include <atomic>
#include <string>
#include <vector>
#include <map>
#include <set>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif
#include <windows.h>
#include <dbt.h>
#include <winioctl.h>
#include <setupapi.h>
#include <devguid.h>
#pragma comment(lib, "setupapi.lib")
#endif

#include "CommonTypes.h"
#elif __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#include <DiskArbitration/DiskArbitration.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>
#include <IOKit/storage/IOBlockStorageDriver.h>
#endif

class DeviceWatcher {
public:
    DeviceWatcher();
    ~DeviceWatcher();
    
    void Start(Napi::Function callback, int intervalMs = 2000);
    void Stop();
    bool IsRunning() const;
    std::vector<StorageDeviceInfo> GetConnectedDevices();

private:
    std::atomic<bool> running_;
    std::atomic<int> counter_;
    std::thread worker_thread_;
    Napi::FunctionReference callback_;
    Napi::ThreadSafeFunction tsfn_;
    int intervalMs_;
    std::vector<StorageDeviceInfo> lastKnownDevices_;
    std::atomic<bool> usePolling_;
    
#ifdef _WIN32
    HWND messageWindow_;
    HDEVNOTIFY deviceNotification_;
    MSG msg_;
    
    void InitializeWindowsNotifications();
    void CleanupWindowsNotifications();
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    void HandleDeviceChange(WPARAM wParam, LPARAM lParam);
    std::vector<StorageDeviceInfo> EnumerateWindowsDevices();
    std::string GetDeviceDescription(const std::string& devicePath);
    std::string GetVolumeLabel(const std::string& driveLetter);
#elif __APPLE__
    DASessionRef diskSession_;
    CFRunLoopRef runLoop_;
    
    void InitializeMacOSNotifications();
    void CleanupMacOSNotifications();
    static void DiskAppearedCallback(DADiskRef disk, void* context);
    static void DiskDisappearedCallback(DADiskRef disk, void* context);
    void HandleDiskAppeared(DADiskRef disk);
    void HandleDiskDisappeared(DADiskRef disk);
    std::vector<StorageDeviceInfo> EnumerateMacOSDevices();
    StorageDeviceInfo CreateStorageDeviceInfoFromDisk(DADiskRef disk);
    bool IsExternalDevice(DADiskRef disk);
#endif
    
    // Cross-platform methods
    void WatcherLoop();
    void PollingLoop();
    void EmitDeviceEvent(const std::string& eventType, const StorageDeviceInfo& device);
    void EmitHeartbeat();
    void CompareAndEmitChanges(const std::vector<StorageDeviceInfo>& currentDevices);
    std::string CreateEventJson(const std::string& eventType, const StorageDeviceInfo& device = StorageDeviceInfo("", "", "", ""));
    std::string EscapeJson(const std::string& str);
    
    // Utility methods
    bool DeviceExists(const std::vector<StorageDeviceInfo>& devices, const StorageDeviceInfo& target);
    std::string GenerateDeviceId(const std::string& name, const std::string& path);
};

#endif // DEVICE_WATCHER_H