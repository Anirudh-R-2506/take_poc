#include "DeviceWatcher.h"
#include <sstream>
#include <ctime>
#include <algorithm>
#include <iomanip>

DeviceWatcher::DeviceWatcher()
    : running_(false), counter_(0), intervalMs_(2000), usePolling_(false) {
#ifdef _WIN32
    messageWindow_ = nullptr;
    deviceNotification_ = nullptr;
#elif __APPLE__
    diskSession_ = nullptr;
    runLoop_ = nullptr;
#endif
}

DeviceWatcher::~DeviceWatcher() {
    Stop();
}

void DeviceWatcher::Start(Napi::Function callback, int intervalMs) {
    if (running_.load()) {
        return;
    }

    running_.store(true);
    intervalMs_ = intervalMs;
    callback_ = Napi::Persistent(callback);

    tsfn_ = Napi::ThreadSafeFunction::New(
        callback.Env(),
        callback,
        "DeviceWatcher",
        0,
        1,
        [](Napi::Env) {
        }
    );

    bool notificationsSuccessful = false;

#ifdef _WIN32
    try {
        InitializeWindowsNotifications();
        notificationsSuccessful = (messageWindow_ != nullptr);
    } catch (...) {
        notificationsSuccessful = false;
    }
#elif __APPLE__
    try {
        InitializeMacOSNotifications();
        notificationsSuccessful = (diskSession_ != nullptr);
    } catch (...) {
        notificationsSuccessful = false;
    }
#endif

    if (notificationsSuccessful) {
        usePolling_.store(false);
        worker_thread_ = std::thread([this]() {
            WatcherLoop();
        });
    } else {
        usePolling_.store(true);
        worker_thread_ = std::thread([this]() {
            PollingLoop();
        });
    }
}

void DeviceWatcher::Stop() {
    if (!running_.load()) {
        return;
    }

    running_.store(false);

#ifdef _WIN32
    CleanupWindowsNotifications();
#elif __APPLE__
    CleanupMacOSNotifications();
#endif

    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }

    if (tsfn_) {
        tsfn_.Release();
    }

    callback_.Reset();
}

bool DeviceWatcher::IsRunning() const {
    return running_.load();
}

std::vector<StorageDeviceInfo> DeviceWatcher::GetConnectedDevices() {
#ifdef _WIN32
    return EnumerateWindowsDevices();
#elif __APPLE__
    return EnumerateMacOSDevices();
#else
    return std::vector<StorageDeviceInfo>();
#endif
}

void DeviceWatcher::WatcherLoop() {
    lastKnownDevices_ = GetConnectedDevices();
    EmitHeartbeat();

#ifdef _WIN32
    while (running_.load()) {
        if (PeekMessage(&msg_, messageWindow_, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg_);
            DispatchMessage(&msg_);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
#elif __APPLE__
    if (runLoop_) {
        while (running_.load()) {
            CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.1, false);
        }
    }
#endif
}

void DeviceWatcher::PollingLoop() {
    lastKnownDevices_ = GetConnectedDevices();
    EmitHeartbeat();

    auto lastHeartbeat = std::chrono::steady_clock::now();

    while (running_.load()) {
        try {
            auto currentDevices = GetConnectedDevices();
            CompareAndEmitChanges(currentDevices);

            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - lastHeartbeat).count() >= 5000) {
                EmitHeartbeat();
                lastHeartbeat = now;
            }

            counter_++;
        } catch (const std::exception& e) {
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs_));
    }
}

void DeviceWatcher::CompareAndEmitChanges(const std::vector<StorageDeviceInfo>& currentDevices) {
    for (const auto& current : currentDevices) {
        if (!DeviceExists(lastKnownDevices_, current)) {
            EmitDeviceEvent("device-connected", current);
        }
    }

    for (const auto& previous : lastKnownDevices_) {
        if (!DeviceExists(currentDevices, previous)) {
            EmitDeviceEvent("device-removed", previous);
        }
    }

    lastKnownDevices_ = currentDevices;
}

bool DeviceWatcher::DeviceExists(const std::vector<StorageDeviceInfo>& devices, const StorageDeviceInfo& target) {
    return std::find(devices.begin(), devices.end(), target) != devices.end();
}

void DeviceWatcher::EmitDeviceEvent(const std::string& eventType, const StorageDeviceInfo& device) {
    if (!tsfn_) return;

    std::string json_str = CreateEventJson(eventType, device);

    tsfn_.NonBlockingCall([json_str](Napi::Env env, Napi::Function callback) {
        callback.Call({Napi::String::New(env, json_str)});
    });
}

void DeviceWatcher::EmitHeartbeat() {
    if (!tsfn_) return;

    std::string json_str = CreateEventJson("heartbeat");

    tsfn_.NonBlockingCall([json_str](Napi::Env env, Napi::Function callback) {
        callback.Call({Napi::String::New(env, json_str)});
    });
}

std::string DeviceWatcher::CreateEventJson(const std::string& eventType, const StorageDeviceInfo& device) {
    std::time_t now = std::time(nullptr);
    std::ostringstream json;

    json << "{"
         << "\"module\": \"device-watch\","
         << "\"event\": \"" << eventType << "\","
         << "\"ts\": " << (now * 1000) << ","
         << "\"count\": " << counter_.load() << ","
         << "\"source\": \"native\"";

    if (eventType == "heartbeat") {
        json << ",\"devices\": [";
        auto devices = lastKnownDevices_;
        for (size_t i = 0; i < devices.size(); i++) {
            if (i > 0) json << ",";
            json << "{"
                 << "\"id\": \"" << EscapeJson(devices[i].id) << "\","
                 << "\"type\": \"" << EscapeJson(devices[i].type) << "\","
                 << "\"name\": \"" << EscapeJson(devices[i].name) << "\","
                 << "\"path\": \"" << EscapeJson(devices[i].path) << "\","
                 << "\"isExternal\": " << (devices[i].isExternal ? "true" : "false")
                 << "}";
        }
        json << "]";
    } else if (!device.id.empty()) {
        json << ",\"device\": {"
             << "\"id\": \"" << EscapeJson(device.id) << "\","
             << "\"type\": \"" << EscapeJson(device.type) << "\","
             << "\"name\": \"" << EscapeJson(device.name) << "\","
             << "\"path\": \"" << EscapeJson(device.path) << "\","
             << "\"isExternal\": " << (device.isExternal ? "true" : "false")
             << "}";
    }

    json << "}";
    return json.str();
}

std::string DeviceWatcher::EscapeJson(const std::string& str) {
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

std::string DeviceWatcher::GenerateDeviceId(const std::string& name, const std::string& path) {
    return name + "_" + path;
}

#ifdef _WIN32

void DeviceWatcher::InitializeWindowsNotifications() {
    const char* className = "DeviceWatcherWindowClass";

    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = className;

    RegisterClass(&wc);

    messageWindow_ = CreateWindow(
        className, "DeviceWatcher", 0, 0, 0, 0, 0,
        HWND_MESSAGE, nullptr, GetModuleHandle(nullptr), this
    );

    if (messageWindow_) {
        DEV_BROADCAST_DEVICEINTERFACE notificationFilter = {};
        notificationFilter.dbcc_size = sizeof(DEV_BROADCAST_DEVICEINTERFACE);
        notificationFilter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
        notificationFilter.dbcc_classguid = GUID_DEVINTERFACE_DISK;

        deviceNotification_ = RegisterDeviceNotification(
            messageWindow_, &notificationFilter,
            DEVICE_NOTIFY_WINDOW_HANDLE
        );
    }
}

void DeviceWatcher::CleanupWindowsNotifications() {
    if (deviceNotification_) {
        UnregisterDeviceNotification(deviceNotification_);
        deviceNotification_ = nullptr;
    }

    if (messageWindow_) {
        DestroyWindow(messageWindow_);
        messageWindow_ = nullptr;
    }
}

LRESULT CALLBACK DeviceWatcher::WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    if (uMsg == WM_CREATE) {
        CREATESTRUCT* cs = reinterpret_cast<CREATESTRUCT*>(lParam);
        DeviceWatcher* watcher = static_cast<DeviceWatcher*>(cs->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(watcher));
        return 0;
    }

    DeviceWatcher* watcher = reinterpret_cast<DeviceWatcher*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    if (watcher && uMsg == WM_DEVICECHANGE) {
        watcher->HandleDeviceChange(wParam, lParam);
    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

void DeviceWatcher::HandleDeviceChange(WPARAM wParam, LPARAM lParam) {
    if (wParam == DBT_DEVICEARRIVAL || wParam == DBT_DEVICEREMOVECOMPLETE) {
        auto currentDevices = GetConnectedDevices();
        CompareAndEmitChanges(currentDevices);
    }
}

std::vector<StorageDeviceInfo> DeviceWatcher::EnumerateWindowsDevices() {
    std::vector<StorageDeviceInfo> devices;

    HDEVINFO hDevInfo = SetupDiGetClassDevsW(&GUID_DEVINTERFACE_DISK, NULL, NULL,
                                            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);

    if (hDevInfo == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        return devices;
    }

    SP_DEVICE_INTERFACE_DATA interfaceData = {0};
    interfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

    for (DWORD index = 0;
         SetupDiEnumDeviceInterfaces(hDevInfo, NULL, &GUID_DEVINTERFACE_DISK, index, &interfaceData);
         index++) {

        DWORD requiredSize = 0;
        SetupDiGetDeviceInterfaceDetailW(hDevInfo, &interfaceData, NULL, 0, &requiredSize, NULL);

        if (requiredSize == 0) continue;

        std::vector<BYTE> buffer(requiredSize);
        PSP_DEVICE_INTERFACE_DETAIL_DATA_W detailData =
            reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA_W>(buffer.data());
        detailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

        SP_DEVINFO_DATA deviceInfoData = {0};
        deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

        if (SetupDiGetDeviceInterfaceDetailW(hDevInfo, &interfaceData, detailData,
                                           requiredSize, NULL, &deviceInfoData)) {

            wchar_t description[256] = {0};
            if (SetupDiGetDeviceRegistryPropertyW(hDevInfo, &deviceInfoData,
                                                 SPDRP_DEVICEDESC, NULL,
                                                 (PBYTE)description, sizeof(description), NULL)) {

                std::wstring descW(description);
                std::string descUtf8;
                if (!descW.empty()) {
                    int utf8Size = WideCharToMultiByte(CP_UTF8, 0, descW.c_str(), -1, nullptr, 0, nullptr, nullptr);
                    if (utf8Size > 0) {
                        descUtf8.resize(utf8Size - 1);
                        WideCharToMultiByte(CP_UTF8, 0, descW.c_str(), -1, &descUtf8[0], utf8Size, nullptr, nullptr);
                    }
                }

                DWORD removalPolicy = 0;
                DWORD dataType;
                DWORD dataSize = sizeof(removalPolicy);
                bool isRemovable = false;

                if (SetupDiGetDeviceRegistryPropertyW(hDevInfo, &deviceInfoData,
                                                     SPDRP_REMOVAL_POLICY, &dataType,
                                                     (PBYTE)&removalPolicy, dataSize, NULL)) {
                    isRemovable = (removalPolicy == CM_REMOVAL_POLICY_EXPECT_SURPRISE_REMOVAL ||
                                  removalPolicy == CM_REMOVAL_POLICY_EXPECT_ORDERLY_REMOVAL);
                }

                if (isRemovable) {
                    std::wstring devicePathW(detailData->DevicePath);
                    std::string devicePath;
                    if (!devicePathW.empty()) {
                        int utf8Size = WideCharToMultiByte(CP_UTF8, 0, devicePathW.c_str(), -1, nullptr, 0, nullptr, nullptr);
                        if (utf8Size > 0) {
                            devicePath.resize(utf8Size - 1);
                            WideCharToMultiByte(CP_UTF8, 0, devicePathW.c_str(), -1, &devicePath[0], utf8Size, nullptr, nullptr);
                        }
                    }

                    devices.emplace_back(
                        GenerateDeviceId(descUtf8, devicePath),
                        "storage",
                        descUtf8.empty() ? "Storage Device" : descUtf8,
                        devicePath,
                        true
                    );
                }
            }
        }
    }

    SetupDiDestroyDeviceInfoList(hDevInfo);
    return devices;
}

std::string DeviceWatcher::GetVolumeLabel(const std::string& driveLetter) {
    std::wstring drivePathW = std::wstring(driveLetter.begin(), driveLetter.end()) + L"\\";
    wchar_t volumeNameW[MAX_PATH + 1] = {0};

    if (GetVolumeInformationW(
        drivePathW.c_str(), volumeNameW, MAX_PATH + 1,
        nullptr, nullptr, nullptr, nullptr, 0)) {

        std::wstring volNameW(volumeNameW);
        if (!volNameW.empty()) {
            int utf8Size = WideCharToMultiByte(CP_UTF8, 0, volNameW.c_str(), -1, nullptr, 0, nullptr, nullptr);
            if (utf8Size > 0) {
                std::string result(utf8Size - 1, '\0');
                WideCharToMultiByte(CP_UTF8, 0, volNameW.c_str(), -1, &result[0], utf8Size, nullptr, nullptr);
                return result;
            }
        }
    } else {
        DWORD error = GetLastError();
    }

    return "";
}

#elif __APPLE__

void DeviceWatcher::InitializeMacOSNotifications() {
    diskSession_ = DASessionCreate(kCFAllocatorDefault);
    if (!diskSession_) {
        return;
    }

    runLoop_ = CFRunLoopGetCurrent();
    DASessionScheduleWithRunLoop(diskSession_, runLoop_, kCFRunLoopDefaultMode);

    DARegisterDiskAppearedCallback(diskSession_, nullptr, DiskAppearedCallback, this);
    DARegisterDiskDisappearedCallback(diskSession_, nullptr, DiskDisappearedCallback, this);
}

void DeviceWatcher::CleanupMacOSNotifications() {
    if (diskSession_) {
        DASessionUnscheduleFromRunLoop(diskSession_, runLoop_, kCFRunLoopDefaultMode);
        CFRelease(diskSession_);
        diskSession_ = nullptr;
    }
}

void DeviceWatcher::DiskAppearedCallback(DADiskRef disk, void* context) {
    DeviceWatcher* watcher = static_cast<DeviceWatcher*>(context);
    watcher->HandleDiskAppeared(disk);
}

void DeviceWatcher::DiskDisappearedCallback(DADiskRef disk, void* context) {
    DeviceWatcher* watcher = static_cast<DeviceWatcher*>(context);
    watcher->HandleDiskDisappeared(disk);
}

void DeviceWatcher::HandleDiskAppeared(DADiskRef disk) {
    if (IsExternalDevice(disk)) {
        auto currentDevices = GetConnectedDevices();
        CompareAndEmitChanges(currentDevices);
    }
}

void DeviceWatcher::HandleDiskDisappeared(DADiskRef disk) {
    if (IsExternalDevice(disk)) {
        auto currentDevices = GetConnectedDevices();
        CompareAndEmitChanges(currentDevices);
    }
}

std::vector<StorageDeviceInfo> DeviceWatcher::EnumerateMacOSDevices() {
    std::vector<StorageDeviceInfo> devices;

    CFMutableDictionaryRef matchingDict = IOServiceMatching("IOMedia");
    if (!matchingDict) {
        return devices;
    }

    io_iterator_t iterator;
    kern_return_t result = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iterator);
    if (result != KERN_SUCCESS) {
        return devices;
    }

    io_object_t service;
    while ((service = IOIteratorNext(iterator)) != 0) {
        CFMutableDictionaryRef properties = nullptr;

        if (IORegistryEntryCreateCFProperties(service, &properties, kCFAllocatorDefault, kNilOptions) == KERN_SUCCESS) {
            CFBooleanRef isWholeRef = (CFBooleanRef)CFDictionaryGetValue(properties, CFSTR("Whole"));
            if (isWholeRef && CFBooleanGetValue(isWholeRef)) {

                CFBooleanRef removableRef = (CFBooleanRef)CFDictionaryGetValue(properties, CFSTR("Removable"));
                if (removableRef && CFBooleanGetValue(removableRef)) {

                    CFStringRef nameRef = (CFStringRef)CFDictionaryGetValue(properties, CFSTR("BSD Name"));
                    std::string deviceName = "External Device";
                    if (nameRef) {
                        char buffer[256];
                        if (CFStringGetCString(nameRef, buffer, sizeof(buffer), kCFStringEncodingUTF8)) {
                            deviceName = std::string(buffer);
                        }
                    }

                    DADiskRef disk = DADiskCreateFromIOMedia(kCFAllocatorDefault, diskSession_, service);
                    if (disk) {
                        CFDictionaryRef diskDescription = DADiskCopyDescription(disk);
                        if (diskDescription) {
                            CFStringRef volumeNameRef = (CFStringRef)CFDictionaryGetValue(diskDescription, kDADiskDescriptionVolumeNameKey);
                            if (volumeNameRef) {
                                char volumeBuffer[256];
                                if (CFStringGetCString(volumeNameRef, volumeBuffer, sizeof(volumeBuffer), kCFStringEncodingUTF8)) {
                                    deviceName = std::string(volumeBuffer);
                                }
                            }

                            CFURLRef mountPointRef = (CFURLRef)CFDictionaryGetValue(diskDescription, kDADiskDescriptionVolumePathKey);
                            std::string mountPoint = "";
                            if (mountPointRef) {
                                char pathBuffer[PATH_MAX];
                                if (CFURLGetFileSystemRepresentation(mountPointRef, false, (UInt8*)pathBuffer, sizeof(pathBuffer))) {
                                    mountPoint = std::string(pathBuffer);
                                }
                            }

                            devices.emplace_back(
                                GenerateDeviceId(deviceName, mountPoint),
                                "usb",
                                deviceName,
                                mountPoint,
                                true
                            );

                            CFRelease(diskDescription);
                        }
                        CFRelease(disk);
                    }
                }
            }
            CFRelease(properties);
        }
        IOObjectRelease(service);
    }

    IOObjectRelease(iterator);
    return devices;
}

bool DeviceWatcher::IsExternalDevice(DADiskRef disk) {
    CFDictionaryRef description = DADiskCopyDescription(disk);
    if (!description) {
        return false;
    }

    CFBooleanRef removable = (CFBooleanRef)CFDictionaryGetValue(description, kDADiskDescriptionMediaRemovableKey);
    bool isExternal = removable && CFBooleanGetValue(removable);

    CFRelease(description);
    return isExternal;
}

#endif