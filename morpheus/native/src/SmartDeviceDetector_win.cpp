#include "SmartDeviceDetector.h"
#include <sstream>
#include <algorithm>
#include <regex>
#include <vector>
#include <string>
#include <set>
#include <map>
#include <cctype>
#include <cstdio>
#include <comdef.h>
#include <Wbemidl.h>
#include <oleauto.h>
#include <dshow.h>
#include <bluetoothapis.h>
#include <ws2bth.h>

#ifdef _WIN32
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "strmiids.lib")
#pragma comment(lib, "Bthprops.lib")
#pragma comment(lib, "ws2_32.lib")
#endif

// Helper function for wide string to UTF-8 conversion (from BluetoothWatcher)
static std::string WideStringToUtf8(const wchar_t* wideStr) {
    if (!wideStr) return "";

    int utf8Length = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, nullptr, 0, nullptr, nullptr);
    if (utf8Length <= 0) return "";

    std::vector<char> utf8Buffer(utf8Length);
    WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, utf8Buffer.data(), utf8Length, nullptr, nullptr);
    return std::string(utf8Buffer.data());
}

SmartDeviceDetector::SmartDeviceDetector() : running_(false), counter_(0), intervalMs_(1000) {
    systemDetector_ = new SystemDetector();
    InitializeThreatPatterns();
    UpdateSecurityProfile();
}

SmartDeviceDetector::~SmartDeviceDetector() {
    Stop();
    delete systemDetector_;
}

void SmartDeviceDetector::Start(Napi::Function callback, int intervalMs) {
    if (running_.load()) {
        return;
    }

    running_.store(true);
    intervalMs_ = intervalMs;
    callback_ = Napi::Persistent(callback);

    tsfn_ = Napi::ThreadSafeFunction::New(
        callback.Env(),
        callback,
        "SmartDeviceDetector",
        0,
        1,
        [this](Napi::Env) {}
    );

    worker_thread_ = std::thread([this]() {
        MonitoringLoop();
    });
}

void SmartDeviceDetector::Stop() {
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

bool SmartDeviceDetector::IsRunning() const {
    return running_.load();
}

void SmartDeviceDetector::SetSystemType(SystemType type) {
    securityProfile_.systemType = type;
    UpdateSecurityProfile();
}

void SmartDeviceDetector::UpdateSecurityProfile() {
    SystemInfo systemInfo = systemDetector_->DetectSystemType();
    securityProfile_.systemType = systemInfo.type;

    // High-stakes proctoring security rules
    if (systemInfo.type == SystemType::LAPTOP) {
        // Laptops: No external input devices allowed (built-in only)
        securityProfile_.allowedMice = 0;          // Only trackpad
        securityProfile_.allowedKeyboards = 0;     // Only built-in keyboard
        securityProfile_.allowedDisplays = 1;      // Only built-in display
        securityProfile_.allowBluetooth = false;   // No BT devices
        securityProfile_.allowWireless = false;    // No wireless devices
    } else if (systemInfo.type == SystemType::DESKTOP) {
        // Desktops: Minimal external device allowance
        securityProfile_.allowedMice = 1;          // One mouse allowed
        securityProfile_.allowedKeyboards = 1;     // One keyboard allowed
        securityProfile_.allowedDisplays = 1;      // Primary display only
        securityProfile_.allowBluetooth = false;   // No BT devices
        securityProfile_.allowWireless = false;    // No wireless devices
    }

    // Universal restrictions for high-stakes environment
    securityProfile_.allowVirtualDevices = false;   // No virtual devices
    securityProfile_.allowExternalStorage = false;  // No USB drives/external storage
    securityProfile_.strictMode = true;             // Maximum security

    // Webcam policy: Allow legitimate external webcams but detect virtual/spoofed cameras
    securityProfile_.allowExternalWebcams = true;   // External webcams allowed for legitimate use
}

std::vector<InputDeviceInfo> SmartDeviceDetector::ScanAllInputDevices() {
#ifdef _WIN32
    return ScanWindowsInputDevices();
#elif __APPLE__
    return ScanMacOSInputDevices();
#else
    return std::vector<InputDeviceInfo>();
#endif
}

#ifdef _WIN32
std::vector<InputDeviceInfo> SmartDeviceDetector::ScanWindowsInputDevices() {
    std::vector<InputDeviceInfo> devices;

    // Initialize COM
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);

    // Initialize WMI
    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;

    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (SUCCEEDED(hr)) {
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr, 0, NULL, 0, 0, &pSvc);
        if (SUCCEEDED(hr)) {
            CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

            // Query for input devices
            ScanWMIDevices(pSvc, L"SELECT * FROM Win32_PointingDevice", devices, "mouse");
            ScanWMIDevices(pSvc, L"SELECT * FROM Win32_Keyboard", devices, "keyboard");
            ScanWMIDevices(pSvc, L"SELECT * FROM Win32_PnPEntity WHERE Service='HidUsb'", devices, "hid");

            pSvc->Release();
        }
        pLoc->Release();
    }

    // Also scan storage devices for comprehensive coverage
    std::vector<StorageDeviceInfo> storageDevices = ScanWindowsStorageDevices();
    for (const auto& storage : storageDevices) {
        InputDeviceInfo device;
        device.name = storage.name;
        device.type = storage.type;
        device.deviceId = storage.id;
        device.isExternal = storage.isExternal;
        device.threatLevel = storage.isExternal ? 3 : 0; // External storage is high threat
        device.threatReason = storage.isExternal ? "External storage device detected" : "Built-in storage";
        device.isAllowed = !storage.isExternal; // External storage not allowed in strict mode
        devices.push_back(device);
    }

    CoUninitialize();
    return devices;
}

void SmartDeviceDetector::ScanWMIDevices(IWbemServices* pSvc, const wchar_t* query, std::vector<InputDeviceInfo>& devices, const std::string& deviceType) {
    IEnumWbemClassObject* pEnumerator = nullptr;
    HRESULT hr = pSvc->ExecQuery(bstr_t("WQL"), bstr_t(query), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &pEnumerator);

    if (SUCCEEDED(hr)) {
        IWbemClassObject* pclsObj = nullptr;
        ULONG uReturn = 0;

        while (pEnumerator) {
            hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (uReturn == 0) break;

            InputDeviceInfo device;
            device.type = deviceType;

            // Get device properties
            VARIANT vtProp;
            VariantInit(&vtProp);

            // Device Name
            hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                device.name = ConvertBSTRToString(vtProp.bstrVal);
            }
            VariantClear(&vtProp);

            // Manufacturer
            hr = pclsObj->Get(L"Manufacturer", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                device.manufacturer = ConvertBSTRToString(vtProp.bstrVal);
            }
            VariantClear(&vtProp);

            // Device ID
            hr = pclsObj->Get(L"DeviceID", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                device.deviceId = ConvertBSTRToString(vtProp.bstrVal);
                ExtractVendorProductIds(device.deviceId, device.vendorId, device.productId);
            }
            VariantClear(&vtProp);

            // Status
            hr = pclsObj->Get(L"Status", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                std::string status = ConvertBSTRToString(vtProp.bstrVal);
                if (status != "OK") {
                    device.threatLevel = (std::max)(device.threatLevel, 2); // Suspicious status
                    device.threatReason += "Device status: " + status + "; ";
                }
            }
            VariantClear(&vtProp);

            // Advanced threat analysis
            device.isVirtual = IsVirtualDevice(device);
            device.isSpoofed = IsSpoofedDevice(device);
            device.isBluetooth = IsBluetoothDevice(device);
            device.isWireless = IsWirelessDevice(device);
            device.isExternal = DetectExternalDevice(device);

            // Calculate threat level
            device.threatLevel = CalculateThreatLevel(device);
            device.threatReason = GetThreatReason(device);
            device.isAllowed = IsDeviceAllowed(device);

            if (!device.name.empty()) {
                devices.push_back(device);
            }

            pclsObj->Release();
        }

        pEnumerator->Release();
    }
}

std::vector<StorageDeviceInfo> SmartDeviceDetector::ScanWindowsStorageDevices() {
    std::vector<StorageDeviceInfo> devices;

    // Use WMI to get logical disks
    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;

    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (SUCCEEDED(hr)) {
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr, 0, NULL, 0, 0, &pSvc);
        if (SUCCEEDED(hr)) {
            CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

            // Query for removable drives
            IEnumWbemClassObject* pEnumerator = nullptr;
            hr = pSvc->ExecQuery(bstr_t("WQL"), bstr_t(L"SELECT * FROM Win32_LogicalDisk WHERE DriveType=2"), // Removable disk
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &pEnumerator);

            if (SUCCEEDED(hr)) {
                IWbemClassObject* pclsObj = nullptr;
                ULONG uReturn = 0;

                while (pEnumerator) {
                    hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                    if (uReturn == 0) break;

                    VARIANT vtProp;
                    VariantInit(&vtProp);

                    std::string deviceId, name, path;

                    // Device ID
                    hr = pclsObj->Get(L"DeviceID", 0, &vtProp, 0, 0);
                    if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                        deviceId = ConvertBSTRToString(vtProp.bstrVal);
                        path = deviceId;
                    }
                    VariantClear(&vtProp);

                    // Volume Label
                    hr = pclsObj->Get(L"VolumeName", 0, &vtProp, 0, 0);
                    if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                        name = ConvertBSTRToString(vtProp.bstrVal);
                    }
                    VariantClear(&vtProp);

                    if (name.empty()) {
                        name = "Removable Drive (" + deviceId + ")";
                    }

                    devices.emplace_back(deviceId, "storage", name, path, true);

                    pclsObj->Release();
                }

                pEnumerator->Release();
            }

            pSvc->Release();
        }
        pLoc->Release();
    }

    return devices;
}

bool SmartDeviceDetector::DetectExternalDevice(const InputDeviceInfo& device) {
    // Check device ID patterns for external devices
    if (device.deviceId.find("USB") != std::string::npos ||
        device.deviceId.find("HID") != std::string::npos) {
        return true;
    }

    // Check for built-in device patterns
    if (device.name.find("Built-in") != std::string::npos ||
        device.name.find("Internal") != std::string::npos ||
        device.manufacturer.find("Microsoft") != std::string::npos) {
        return false;
    }

    // Default to external for safety
    return true;
}

std::string SmartDeviceDetector::ConvertBSTRToString(BSTR bstr) {
    if (!bstr) return "";

    int len = WideCharToMultiByte(CP_UTF8, 0, bstr, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";

    std::string result(len - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, bstr, -1, &result[0], len, nullptr, nullptr);
    return result;
}

void SmartDeviceDetector::ExtractVendorProductIds(const std::string& deviceId, std::string& vendorId, std::string& productId) {
    std::regex vidPattern(R"(VID_([0-9A-F]{4}))");
    std::regex pidPattern(R"(PID_([0-9A-F]{4}))");
    std::smatch match;

    if (std::regex_search(deviceId, match, vidPattern)) {
        vendorId = "0x" + match[1].str();
    }

    if (std::regex_search(deviceId, match, pidPattern)) {
        productId = "0x" + match[1].str();
    }
}

// Video Device Detection for Windows
std::vector<InputDeviceInfo> SmartDeviceDetector::ScanVideoDevices() {
    std::vector<InputDeviceInfo> videoDevices;

#ifdef _WIN32
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);

    // Use DirectShow to enumerate video devices
    ICreateDevEnum* pCreateDevEnum = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_SystemDeviceEnum, nullptr, CLSCTX_INPROC_SERVER, IID_ICreateDevEnum, (void**)&pCreateDevEnum);

    if (SUCCEEDED(hr)) {
        IEnumMoniker* pEnumMoniker = nullptr;
        hr = pCreateDevEnum->CreateClassEnumerator(CLSID_VideoInputDeviceCategory, &pEnumMoniker, 0);

        if (SUCCEEDED(hr) && pEnumMoniker) {
            IMoniker* pMoniker = nullptr;
            ULONG fetched = 0;

            while (pEnumMoniker->Next(1, &pMoniker, &fetched) == S_OK) {
                IPropertyBag* pPropertyBag = nullptr;
                hr = pMoniker->BindToStorage(0, 0, IID_IPropertyBag, (void**)&pPropertyBag);

                if (SUCCEEDED(hr)) {
                    InputDeviceInfo device;
                    device.type = "video";

                    VARIANT var;
                    VariantInit(&var);

                    // Get device name
                    hr = pPropertyBag->Read(L"FriendlyName", &var, 0);
                    if (SUCCEEDED(hr)) {
                        device.name = ConvertBSTRToString(var.bstrVal);
                    }
                    VariantClear(&var);

                    // Get device path
                    hr = pPropertyBag->Read(L"DevicePath", &var, 0);
                    if (SUCCEEDED(hr)) {
                        device.deviceId = ConvertBSTRToString(var.bstrVal);
                        ExtractVendorProductIds(device.deviceId, device.vendorId, device.productId);
                    }
                    VariantClear(&var);

                    // Analyze video device
                    device.isExternal = !IsBuiltInCamera(device);
                    device.isVirtual = IsVirtualCamera(device);
                    device.isSpoofed = IsSpoofedDevice(device);
                    device.threatLevel = CalculateVideoDeviceThreatLevel(device);
                    device.threatReason = GetVideoDeviceThreatReason(device);
                    device.isAllowed = IsWebcamAllowed(device);

                    if (!device.name.empty()) {
                        videoDevices.push_back(device);
                    }

                    pPropertyBag->Release();
                }

                pMoniker->Release();
            }

            pEnumMoniker->Release();
        }

        pCreateDevEnum->Release();
    }

    CoUninitialize();
#endif

    return videoDevices;
}

bool SmartDeviceDetector::IsBuiltInCamera(const InputDeviceInfo& device) {
    std::string nameLower = device.name;
    std::string manufacturerLower = device.manufacturer;
    std::string modelLower = device.model;

    std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);
    std::transform(manufacturerLower.begin(), manufacturerLower.end(), manufacturerLower.begin(), ::tolower);
    std::transform(modelLower.begin(), modelLower.end(), modelLower.begin(), ::tolower);

    // Enhanced built-in camera patterns for Windows
    std::vector<std::string> builtInPatterns = {
        "built-in", "integrated", "internal", "embedded", "onboard",
        "laptop", "notebook", "facetime hd", "front camera", "webcam",
        "usb2.0", "usb 2.0", "hd camera", "camera module", "system camera",
        "chicony", "realtek", "microdia", "azurewave", "sunplus",
        "bison", "suyin", "alcor micro", "sonix", "primax",
        "quanta", "liteon", "foxconn", "importek", "genesys logic"
    };

    // Check device name against built-in patterns
    for (const auto& pattern : builtInPatterns) {
        if (nameLower.find(pattern) != std::string::npos) {
            return true;
        }
    }

    // Check manufacturer against known built-in camera manufacturers
    std::vector<std::string> builtInManufacturers = {
        "microsoft", "realtek", "chicony", "microdia", "azurewave",
        "sunplus", "bison", "suyin", "alcor micro", "sonix",
        "primax", "quanta", "liteon", "foxconn", "importek",
        "genesys logic", "imc networks", "cheng uei precision"
    };

    for (const auto& manufacturer : builtInManufacturers) {
        if (manufacturerLower.find(manufacturer) != std::string::npos && !device.isExternal) {
            return true;
        }
    }

    // Check for built-in vendor IDs (common laptop camera manufacturers)
    std::set<std::string> builtInVendorIds = {
        "0x04f2", // Chicony Electronics
        "0x13d3", // IMC Networks
        "0x0c45", // Microdia
        "0x064e", // Suyin
        "0x174f", // Syntek
        "0x1bcf", // Sunplus Innovation Technology
        "0x05c8", // Cheng Uei Precision Industry
        "0x0bda", // Realtek
        "0x058f", // Alcor Micro
        "0x0ac8", // Z-Star Microelectronics
        "0x145f", // Trust International B.V.
        "0x18ec", // Arkmicro Technologies Inc.
        "0x1415"  // Nam Tai E&E Products Ltd.
    };

    if (!device.isExternal && builtInVendorIds.find(device.vendorId) != builtInVendorIds.end()) {
        return true;
    }

    // Final check: if device is not external and has legitimate patterns, likely built-in
    if (!device.isExternal && IsLegitimateWebcam(device) && !IsVirtualCamera(device)) {
        return true;
    }

    return false;
}


// Windows-specific legitimate webcam detection
bool SmartDeviceDetector::IsLegitimateWebcam(const InputDeviceInfo& device) {
    // Known legitimate webcam manufacturers
    std::set<std::string> legitimateManufacturers = {
        "Logitech", "Microsoft", "Creative Technology", "Creative",
        "Razer", "ASUS", "HP", "Dell", "Lenovo", "Sony", "Canon",
        "Elgato", "Corsair", "SteelSeries", "HyperX", "Anker",
        "Ausdom", "Wansview", "NexiGo", "EMEET", "Papalook"
    };

    // Check manufacturer (case-insensitive)
    std::string manufacturerLower = device.manufacturer;
    std::transform(manufacturerLower.begin(), manufacturerLower.end(), manufacturerLower.begin(), ::tolower);

    for (const auto& manufacturer : legitimateManufacturers) {
        std::string legitLower = manufacturer;
        std::transform(legitLower.begin(), legitLower.end(), legitLower.begin(), ::tolower);

        if (manufacturerLower.find(legitLower) != std::string::npos) {
            return true;
        }
    }

    // Check for legitimate product patterns
    std::string nameLower = device.name;
    std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);

    if (nameLower.find("hd webcam") != std::string::npos ||
        nameLower.find("pro webcam") != std::string::npos ||
        nameLower.find("4k webcam") != std::string::npos ||
        nameLower.find("1080p") != std::string::npos ||
        nameLower.find("lifecam") != std::string::npos ||  // Microsoft LifeCam series
        nameLower.find("c920") != std::string::npos ||     // Popular Logitech model
        nameLower.find("c922") != std::string::npos ||     // Popular Logitech model
        nameLower.find("c930") != std::string::npos ||     // Popular Logitech model
        nameLower.find("brio") != std::string::npos) {     // Logitech Brio series
        return true;
    }

    // Built-in cameras are considered legitimate
    if (IsBuiltInCamera(device)) {
        return true;
    }

    return false;
}

bool SmartDeviceDetector::DetectWindowsSecondaryDisplays() {
    DWORD displayCount = 0;

    // Method 1: Use EnumDisplayDevices to count active displays
    DISPLAY_DEVICE displayDevice;
    displayDevice.cb = sizeof(DISPLAY_DEVICE);

    for (DWORD deviceIndex = 0; EnumDisplayDevices(NULL, deviceIndex, &displayDevice, 0); deviceIndex++) {
        if (displayDevice.StateFlags & DISPLAY_DEVICE_ACTIVE) {
            displayCount++;
        }
    }

    // Method 2: Alternative using GetSystemMetrics for validation
    int screenCount = GetSystemMetrics(SM_CMONITORS);

    // Use the higher count for safety
    displayCount = (std::max)(displayCount, static_cast<DWORD>(screenCount));

    if (displayCount > 1) {
        DeviceViolation violation;
        violation.deviceId = "DISPLAY_SECONDARY";
        violation.deviceName = "Secondary Display(s)";
        violation.violationType = "multiple-displays";
        violation.severity = 3; // HIGH
        violation.reason = std::to_string(displayCount) + " displays detected - potential content sharing or cheating aid";
        violation.evidence = "Windows EnumDisplayDevices API reported " + std::to_string(displayCount) + " active displays";
        violation.persistent = true;

        // Check if violation already exists
        bool alreadyExists = false;
        for (const auto& existing : activeViolations_) {
            if (existing.deviceId == violation.deviceId) {
                alreadyExists = true;
                break;
            }
        }

        if (!alreadyExists) {
            activeViolations_.push_back(violation);
        }

        return true;
    }

    // Remove any existing display violations if only one display is now detected
    activeViolations_.erase(
        std::remove_if(activeViolations_.begin(), activeViolations_.end(),
            [](const DeviceViolation& v) { return v.deviceId == "DISPLAY_SECONDARY"; }),
        activeViolations_.end()
    );

    return false;
}

#endif

// Common methods shared between platforms...
// Rest of common implementation would be here - similar to macOS version but adapted for cross-platform use

// Windows-specific network interface detection
bool SmartDeviceDetector::DetectWindowsNetworkInterfaces() {
    HRESULT hres;

    // Initialize COM
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        return false;
    }

    // Set general COM security levels
    hres = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_NONE,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL
    );

    if (FAILED(hres)) {
        CoUninitialize();
        return false;
    }

    // Obtain the initial locator to WMI
    IWbemLocator *pLoc = NULL;
    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID *)&pLoc);

    if (FAILED(hres)) {
        CoUninitialize();
        return false;
    }

    // Connect to WMI through the IWbemLocator::ConnectServer method
    IWbemServices *pSvc = NULL;
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc
    );

    if (FAILED(hres)) {
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    // Set security levels on the proxy
    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );

    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    bool violationDetected = false;

    // Query for network adapters
    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_NetworkAdapter WHERE NetEnabled=True"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (SUCCEEDED(hres)) {
        IWbemClassObject *pclsObj = NULL;
        ULONG uReturn = 0;

        while (pEnumerator) {
            HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (0 == uReturn) {
                break;
            }

            VARIANT vtProp;
            VariantInit(&vtProp);

            // Get adapter name
            std::string adapterName;
            hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                adapterName = ConvertBSTRToString(vtProp.bstrVal);
            }
            VariantClear(&vtProp);

            // Get adapter type
            std::string adapterType;
            hr = pclsObj->Get(L"AdapterType", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                adapterType = ConvertBSTRToString(vtProp.bstrVal);
            }
            VariantClear(&vtProp);

            // Get PNP device ID
            std::string pnpDeviceId;
            hr = pclsObj->Get(L"PNPDeviceID", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                pnpDeviceId = ConvertBSTRToString(vtProp.bstrVal);
            }
            VariantClear(&vtProp);

            // Analyze for wireless/hotspot characteristics
            std::string adapterNameLower = adapterName;
            std::transform(adapterNameLower.begin(), adapterNameLower.end(), adapterNameLower.begin(), ::tolower);

            std::string pnpDeviceIdLower = pnpDeviceId;
            std::transform(pnpDeviceIdLower.begin(), pnpDeviceIdLower.end(), pnpDeviceIdLower.begin(), ::tolower);

            bool isWireless = false;
            bool isSuspicious = false;
            std::string reason;

            // Check for wireless indicators
            if (adapterNameLower.find("wireless") != std::string::npos ||
                adapterNameLower.find("wifi") != std::string::npos ||
                adapterNameLower.find("wi-fi") != std::string::npos ||
                adapterNameLower.find("802.11") != std::string::npos ||
                adapterNameLower.find("wlan") != std::string::npos) {
                isWireless = true;
            }

            // Check for mobile hotspot indicators
            if (adapterNameLower.find("hotspot") != std::string::npos ||
                adapterNameLower.find("mobile") != std::string::npos ||
                adapterNameLower.find("tethering") != std::string::npos ||
                adapterNameLower.find("shared") != std::string::npos ||
                adapterNameLower.find("internet connection sharing") != std::string::npos ||
                adapterNameLower.find("ics") != std::string::npos) {
                isSuspicious = true;
                reason = "Mobile hotspot or tethering detected";
            }

            // Check for USB tethering devices
            if (pnpDeviceIdLower.find("usb") != std::string::npos &&
                (adapterNameLower.find("rndis") != std::string::npos ||
                 adapterNameLower.find("tether") != std::string::npos ||
                 adapterNameLower.find("android") != std::string::npos ||
                 adapterNameLower.find("iphone") != std::string::npos)) {
                isSuspicious = true;
                reason = "USB tethering device detected";
            }

            // Check for virtual/bridge adapters that might indicate connection sharing
            if (adapterNameLower.find("bridge") != std::string::npos ||
                adapterNameLower.find("virtual") != std::string::npos ||
                adapterNameLower.find("vmware") != std::string::npos ||
                adapterNameLower.find("virtualbox") != std::string::npos ||
                adapterNameLower.find("hyper-v") != std::string::npos) {
                if (adapterNameLower.find("nat") != std::string::npos ||
                    adapterNameLower.find("host-only") != std::string::npos) {
                    // These virtual adapters are typically for VM networking, flag as suspicious
                    isSuspicious = true;
                    reason = "Virtual network adapter detected - potential VM or network sharing";
                }
            }

            // Flag wireless adapters in strict mode
            if (!securityProfile_.allowWireless && isWireless && !isSuspicious) {
                isSuspicious = true;
                reason = "Wireless network adapter detected in strict mode";
            }

            if (isSuspicious) {
                DeviceViolation violation;
                violation.deviceId = "NET_" + pnpDeviceId;
                violation.deviceName = adapterName;
                violation.violationType = "network-interface";
                violation.severity = isWireless ? 2 : 3; // MEDIUM for wireless, HIGH for tethering/hotspot
                violation.reason = reason;
                violation.evidence = "Adapter: " + adapterName + ", Type: " + adapterType + ", PNP ID: " + pnpDeviceId;
                violation.persistent = true;

                activeViolations_.push_back(violation);
                EmitViolation(violation);
                violationDetected = true;
            }

            pclsObj->Release();
        }
        pEnumerator->Release();
    }

    // Query for active network connections to detect tethering
    pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (SUCCEEDED(hres)) {
        IWbemClassObject *pclsObj = NULL;
        ULONG uReturn = 0;

        while (pEnumerator) {
            HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (0 == uReturn) {
                break;
            }

            VARIANT vtProp;
            VariantInit(&vtProp);

            // Check for suspicious IP ranges that might indicate mobile tethering
            hr = pclsObj->Get(L"IPAddress", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr) && vtProp.vt == (VT_ARRAY | VT_BSTR)) {
                SAFEARRAY *psa = vtProp.parray;
                long lLower, lUpper;
                SafeArrayGetLBound(psa, 1, &lLower);
                SafeArrayGetUBound(psa, 1, &lUpper);

                for (long i = lLower; i <= lUpper; i++) {
                    BSTR bstrIP;
                    SafeArrayGetElement(psa, &i, &bstrIP);
                    std::string ipAddress = ConvertBSTRToString(bstrIP);
                    SysFreeString(bstrIP);

                    // Check for common mobile hotspot IP ranges
                    if (ipAddress.find("192.168.43.") == 0 ||  // Android hotspot default
                        ipAddress.find("172.20.10.") == 0 ||   // iPhone hotspot default
                        ipAddress.find("192.168.137.") == 0) { // Windows mobile hotspot default

                        DeviceViolation violation;
                        violation.deviceId = "NET_HOTSPOT_IP";
                        violation.deviceName = "Mobile Hotspot Connection";
                        violation.violationType = "mobile-hotspot";
                        violation.severity = 4; // CRITICAL
                        violation.reason = "Mobile hotspot IP range detected - " + ipAddress;
                        violation.evidence = "Active IP address in mobile hotspot range: " + ipAddress;
                        violation.persistent = true;

                        activeViolations_.push_back(violation);
                        EmitViolation(violation);
                        violationDetected = true;
                    }
                }
            }
            VariantClear(&vtProp);

            pclsObj->Release();
        }
        pEnumerator->Release();
    }

    // Cleanup
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    return violationDetected;
}

// Windows-specific mobile device detection
bool SmartDeviceDetector::DetectWindowsMobileDevices() {
    HRESULT hres;

    // Initialize COM
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        return false;
    }

    // Set general COM security levels
    hres = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_NONE,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL
    );

    if (FAILED(hres)) {
        CoUninitialize();
        return false;
    }

    // Obtain the initial locator to WMI
    IWbemLocator *pLoc = NULL;
    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID *)&pLoc);

    if (FAILED(hres)) {
        CoUninitialize();
        return false;
    }

    // Connect to WMI through the IWbemLocator::ConnectServer method
    IWbemServices *pSvc = NULL;
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc
    );

    if (FAILED(hres)) {
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    // Set security levels on the proxy
    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );

    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    bool violationDetected = false;

    // Query for USB devices that might be mobile devices
    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE 'USB%'"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (SUCCEEDED(hres)) {
        IWbemClassObject *pclsObj = NULL;
        ULONG uReturn = 0;

        while (pEnumerator) {
            HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (0 == uReturn) {
                break;
            }

            VARIANT vtProp;
            VariantInit(&vtProp);

            // Get device name
            std::string deviceName;
            hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                deviceName = ConvertBSTRToString(vtProp.bstrVal);
            }
            VariantClear(&vtProp);

            // Get device ID
            std::string deviceId;
            hr = pclsObj->Get(L"DeviceID", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                deviceId = ConvertBSTRToString(vtProp.bstrVal);
            }
            VariantClear(&vtProp);

            // Get manufacturer
            std::string manufacturer;
            hr = pclsObj->Get(L"Manufacturer", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                manufacturer = ConvertBSTRToString(vtProp.bstrVal);
            }
            VariantClear(&vtProp);

            // Convert to lowercase for pattern matching
            std::string deviceNameLower = deviceName;
            std::transform(deviceNameLower.begin(), deviceNameLower.end(), deviceNameLower.begin(), ::tolower);

            std::string deviceIdLower = deviceId;
            std::transform(deviceIdLower.begin(), deviceIdLower.end(), deviceIdLower.begin(), ::tolower);

            std::string manufacturerLower = manufacturer;
            std::transform(manufacturerLower.begin(), manufacturerLower.end(), manufacturerLower.begin(), ::tolower);

            bool isMobileDevice = false;
            std::string reason;
            int severity = 3; // HIGH by default

            // Check for iPhone indicators
            if (deviceNameLower.find("iphone") != std::string::npos ||
                deviceNameLower.find("apple mobile device") != std::string::npos ||
                deviceNameLower.find("apple inc.") != std::string::npos ||
                manufacturerLower.find("apple") != std::string::npos) {
                isMobileDevice = true;
                reason = "iPhone or Apple mobile device detected";
            }

            // Check for Android device indicators
            else if (deviceNameLower.find("android") != std::string::npos ||
                     deviceNameLower.find("adb interface") != std::string::npos ||
                     deviceNameLower.find("samsung") != std::string::npos ||
                     deviceNameLower.find("lg mobile") != std::string::npos ||
                     deviceNameLower.find("htc") != std::string::npos ||
                     deviceNameLower.find("motorola") != std::string::npos ||
                     deviceNameLower.find("oneplus") != std::string::npos ||
                     deviceNameLower.find("pixel") != std::string::npos ||
                     deviceNameLower.find("nexus") != std::string::npos) {
                isMobileDevice = true;
                reason = "Android mobile device detected";
            }

            // Check for tablet indicators
            else if (deviceNameLower.find("ipad") != std::string::npos ||
                     deviceNameLower.find("tablet") != std::string::npos ||
                     deviceNameLower.find("surface") != std::string::npos) {
                isMobileDevice = true;
                reason = "Tablet device detected";
            }

            // Check for mobile device vendor IDs in device ID
            else if (deviceIdLower.find("vid_05ac") != std::string::npos ||  // Apple
                     deviceIdLower.find("vid_18d1") != std::string::npos ||  // Google
                     deviceIdLower.find("vid_04e8") != std::string::npos ||  // Samsung
                     deviceIdLower.find("vid_0bb4") != std::string::npos ||  // HTC
                     deviceIdLower.find("vid_22b8") != std::string::npos ||  // Motorola
                     deviceIdLower.find("vid_1004") != std::string::npos ||  // LG
                     deviceIdLower.find("vid_2717") != std::string::npos ||  // Xiaomi
                     deviceIdLower.find("vid_2a70") != std::string::npos) {  // OnePlus
                isMobileDevice = true;
                reason = "Mobile device detected via USB vendor ID";
            }

            // Check for MTP (Media Transfer Protocol) which is common on phones
            else if (deviceNameLower.find("mtp") != std::string::npos ||
                     deviceNameLower.find("media transfer protocol") != std::string::npos ||
                     deviceNameLower.find("portable device") != std::string::npos) {
                isMobileDevice = true;
                reason = "MTP/Portable device detected (likely mobile device)";
                severity = 2; // MEDIUM for less certain detection
            }

            // Check for USB debugging/development tools
            else if (deviceNameLower.find("adb") != std::string::npos ||
                     deviceNameLower.find("fastboot") != std::string::npos ||
                     deviceNameLower.find("bootloader") != std::string::npos) {
                isMobileDevice = true;
                reason = "Mobile development/debugging interface detected";
                severity = 4; // CRITICAL for development tools
            }

            if (isMobileDevice) {
                DeviceViolation violation;
                violation.deviceId = deviceId;
                violation.deviceName = deviceName;
                violation.violationType = "mobile-device";
                violation.severity = severity;
                violation.reason = reason;
                violation.evidence = "Device: " + deviceName + ", Manufacturer: " + manufacturer + ", ID: " + deviceId;
                violation.persistent = true;

                activeViolations_.push_back(violation);
                EmitViolation(violation);
                violationDetected = true;
            }

            pclsObj->Release();
        }
        pEnumerator->Release();
    }

    // Query for Bluetooth devices that might be mobile
    pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE 'BTHENUM%'"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (SUCCEEDED(hres)) {
        IWbemClassObject *pclsObj = NULL;
        ULONG uReturn = 0;

        while (pEnumerator) {
            HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (0 == uReturn) {
                break;
            }

            VARIANT vtProp;
            VariantInit(&vtProp);

            // Get device name
            std::string deviceName;
            hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                deviceName = ConvertBSTRToString(vtProp.bstrVal);
            }
            VariantClear(&vtProp);

            // Get device ID
            std::string deviceId;
            hr = pclsObj->Get(L"DeviceID", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                deviceId = ConvertBSTRToString(vtProp.bstrVal);
            }
            VariantClear(&vtProp);

            // Convert to lowercase for pattern matching
            std::string deviceNameLower = deviceName;
            std::transform(deviceNameLower.begin(), deviceNameLower.end(), deviceNameLower.begin(), ::tolower);

            bool isMobileDevice = false;
            std::string reason;

            // Check for mobile device patterns in Bluetooth devices
            if (deviceNameLower.find("iphone") != std::string::npos ||
                deviceNameLower.find("ipad") != std::string::npos ||
                deviceNameLower.find("android") != std::string::npos ||
                deviceNameLower.find("samsung") != std::string::npos ||
                deviceNameLower.find("lg") != std::string::npos ||
                deviceNameLower.find("motorola") != std::string::npos ||
                deviceNameLower.find("htc") != std::string::npos ||
                deviceNameLower.find("oneplus") != std::string::npos ||
                deviceNameLower.find("pixel") != std::string::npos ||
                deviceNameLower.find("galaxy") != std::string::npos ||
                deviceNameLower.find("note") != std::string::npos) {
                isMobileDevice = true;
                reason = "Mobile device detected via Bluetooth";
            }

            if (isMobileDevice) {
                DeviceViolation violation;
                violation.deviceId = deviceId;
                violation.deviceName = deviceName;
                violation.violationType = "mobile-device-bluetooth";
                violation.severity = 3; // HIGH
                violation.reason = reason;
                violation.evidence = "Bluetooth device: " + deviceName + ", ID: " + deviceId;
                violation.persistent = true;

                activeViolations_.push_back(violation);
                EmitViolation(violation);
                violationDetected = true;
            }

            pclsObj->Release();
        }
        pEnumerator->Release();
    }

    // Cleanup
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    return violationDetected;
}

// Helper methods for enhanced Bluetooth business logic
bool SmartDeviceDetector::HasWiredMouse() {
    std::vector<InputDeviceInfo> devices = ScanAllInputDevices();
    for (const auto& device : devices) {
        if (IsMouseDevice(device) && !device.isBluetooth && !device.isWireless && !device.isVirtual) {
            return true;
        }
    }
    return false;
}

bool SmartDeviceDetector::HasWiredKeyboard() {
    std::vector<InputDeviceInfo> devices = ScanAllInputDevices();
    for (const auto& device : devices) {
        if (IsKeyboardDevice(device) && !device.isBluetooth && !device.isWireless && !device.isVirtual) {
            return true;
        }
    }
    return false;
}

int SmartDeviceDetector::CountBluetoothMice() {
    int count = 0;

    // Use Bluetooth API to enumerate devices
    BLUETOOTH_FIND_RADIO_PARAMS radioParams = { sizeof(BLUETOOTH_FIND_RADIO_PARAMS) };
    HANDLE hRadio;
    HBLUETOOTH_RADIO_FIND hFind = BluetoothFindFirstRadio(&radioParams, &hRadio);

    if (hFind != NULL) {
        CloseHandle(hRadio);
        BluetoothFindRadioClose(hFind);

        BLUETOOTH_DEVICE_SEARCH_PARAMS deviceSearchParams = { 0 };
        deviceSearchParams.dwSize = sizeof(BLUETOOTH_DEVICE_SEARCH_PARAMS);
        deviceSearchParams.fReturnAuthenticated = TRUE;
        deviceSearchParams.fReturnRemembered = TRUE;
        deviceSearchParams.fReturnConnected = TRUE;
        deviceSearchParams.fReturnUnknown = FALSE;
        deviceSearchParams.fIssueInquiry = FALSE;
        deviceSearchParams.cTimeoutMultiplier = 2;

        BLUETOOTH_DEVICE_INFO deviceInfo = { 0 };
        deviceInfo.dwSize = sizeof(BLUETOOTH_DEVICE_INFO);

        HBLUETOOTH_DEVICE_FIND hDeviceFind = BluetoothFindFirstDevice(&deviceSearchParams, &deviceInfo);
        if (hDeviceFind != NULL) {
            do {
                std::string deviceName = WideStringToUtf8(deviceInfo.szName);
                std::string deviceNameLower = deviceName;
                std::transform(deviceNameLower.begin(), deviceNameLower.end(), deviceNameLower.begin(), ::tolower);

                if (deviceNameLower.find("mouse") != std::string::npos) {
                    count++;
                }
            } while (BluetoothFindNextDevice(hDeviceFind, &deviceInfo));

            BluetoothFindDeviceClose(hDeviceFind);
        }
    }

    return count;
}

int SmartDeviceDetector::CountBluetoothKeyboards() {
    int count = 0;

    // Use Bluetooth API to enumerate devices
    BLUETOOTH_FIND_RADIO_PARAMS radioParams = { sizeof(BLUETOOTH_FIND_RADIO_PARAMS) };
    HANDLE hRadio;
    HBLUETOOTH_RADIO_FIND hFind = BluetoothFindFirstRadio(&radioParams, &hRadio);

    if (hFind != NULL) {
        CloseHandle(hRadio);
        BluetoothFindRadioClose(hFind);

        BLUETOOTH_DEVICE_SEARCH_PARAMS deviceSearchParams = { 0 };
        deviceSearchParams.dwSize = sizeof(BLUETOOTH_DEVICE_SEARCH_PARAMS);
        deviceSearchParams.fReturnAuthenticated = TRUE;
        deviceSearchParams.fReturnRemembered = TRUE;
        deviceSearchParams.fReturnConnected = TRUE;
        deviceSearchParams.fReturnUnknown = FALSE;
        deviceSearchParams.fIssueInquiry = FALSE;
        deviceSearchParams.cTimeoutMultiplier = 2;

        BLUETOOTH_DEVICE_INFO deviceInfo = { 0 };
        deviceInfo.dwSize = sizeof(BLUETOOTH_DEVICE_INFO);

        HBLUETOOTH_DEVICE_FIND hDeviceFind = BluetoothFindFirstDevice(&deviceSearchParams, &deviceInfo);
        if (hDeviceFind != NULL) {
            do {
                std::string deviceName = WideStringToUtf8(deviceInfo.szName);
                std::string deviceNameLower = deviceName;
                std::transform(deviceNameLower.begin(), deviceNameLower.end(), deviceNameLower.begin(), ::tolower);

                if (deviceNameLower.find("keyboard") != std::string::npos) {
                    count++;
                }
            } while (BluetoothFindNextDevice(hDeviceFind, &deviceInfo));

            BluetoothFindDeviceClose(hDeviceFind);
        }
    }

    return count;
}

bool SmartDeviceDetector::DetectNonInputBluetoothDevices() {
    bool violationDetected = false;

    // Check if Bluetooth is available using the proper Bluetooth API
    BLUETOOTH_FIND_RADIO_PARAMS radioParams = { sizeof(BLUETOOTH_FIND_RADIO_PARAMS) };
    HANDLE hRadio;
    HBLUETOOTH_RADIO_FIND hFind = BluetoothFindFirstRadio(&radioParams, &hRadio);

    if (hFind != NULL) {
        CloseHandle(hRadio);
        BluetoothFindRadioClose(hFind);

        // Enumerate connected/paired devices
        BLUETOOTH_DEVICE_SEARCH_PARAMS deviceSearchParams = { 0 };
        deviceSearchParams.dwSize = sizeof(BLUETOOTH_DEVICE_SEARCH_PARAMS);
        deviceSearchParams.fReturnAuthenticated = TRUE;
        deviceSearchParams.fReturnRemembered = TRUE;
        deviceSearchParams.fReturnConnected = TRUE;
        deviceSearchParams.fReturnUnknown = FALSE;
        deviceSearchParams.fIssueInquiry = FALSE;
        deviceSearchParams.cTimeoutMultiplier = 2;

        BLUETOOTH_DEVICE_INFO deviceInfo = { 0 };
        deviceInfo.dwSize = sizeof(BLUETOOTH_DEVICE_INFO);

        HBLUETOOTH_DEVICE_FIND hDeviceFind = BluetoothFindFirstDevice(&deviceSearchParams, &deviceInfo);
        if (hDeviceFind != NULL) {
            do {
                std::string deviceName = WideStringToUtf8(deviceInfo.szName);
                std::string deviceNameLower = deviceName;
                std::transform(deviceNameLower.begin(), deviceNameLower.end(), deviceNameLower.begin(), ::tolower);

                // Skip input devices (mouse/keyboard) as they're handled by business logic
                if (deviceNameLower.find("mouse") != std::string::npos ||
                    deviceNameLower.find("keyboard") != std::string::npos ||
                    deviceNameLower.find("trackpad") != std::string::npos) {
                    continue;
                }

                // Format address
                char addressStr[20];
                int result = _snprintf_s(addressStr, sizeof(addressStr), _TRUNCATE,
                    "%02X:%02X:%02X:%02X:%02X:%02X",
                    deviceInfo.Address.rgBytes[5],
                    deviceInfo.Address.rgBytes[4],
                    deviceInfo.Address.rgBytes[3],
                    deviceInfo.Address.rgBytes[2],
                    deviceInfo.Address.rgBytes[1],
                    deviceInfo.Address.rgBytes[0]);

                std::string deviceAddress = (result > 0) ? std::string(addressStr) : "Unknown";

                if (!deviceName.empty() && deviceName != "Unknown" &&
                    deviceAddress != "Unknown" && deviceAddress.length() == 17) {

                    // Determine device type and severity for non-input devices
                    int severity = 2; // MEDIUM by default
                    std::string deviceType = "Unknown Bluetooth Device";
                    std::string reason = "Non-input Bluetooth device detected in strict mode";

                    // Classify non-input device types
                    if (deviceNameLower.find("headphone") != std::string::npos ||
                        deviceNameLower.find("earphone") != std::string::npos ||
                        deviceNameLower.find("earbuds") != std::string::npos ||
                        deviceNameLower.find("airpods") != std::string::npos ||
                        deviceNameLower.find("speaker") != std::string::npos ||
                        deviceNameLower.find("audio") != std::string::npos ||
                        deviceNameLower.find("beats") != std::string::npos ||
                        deviceNameLower.find("bose") != std::string::npos ||
                        deviceNameLower.find("sony") != std::string::npos) {
                        deviceType = "Bluetooth Audio Device";
                        severity = 3; // HIGH - audio devices can record/transmit exam content
                        reason = "Bluetooth audio device detected - potential for recording or assistance";
                    }
                    else if (deviceNameLower.find("phone") != std::string::npos ||
                             deviceNameLower.find("tablet") != std::string::npos ||
                             deviceNameLower.find("mobile") != std::string::npos ||
                             deviceNameLower.find("iphone") != std::string::npos ||
                             deviceNameLower.find("ipad") != std::string::npos ||
                             deviceNameLower.find("android") != std::string::npos) {
                        deviceType = "Bluetooth Mobile Device";
                        severity = 4; // CRITICAL - mobile devices are high risk
                        reason = "Bluetooth mobile device detected - high cheating risk";
                    }
                    else if (deviceNameLower.find("watch") != std::string::npos ||
                             deviceNameLower.find("fitness") != std::string::npos ||
                             deviceNameLower.find("band") != std::string::npos) {
                        deviceType = "Bluetooth Wearable Device";
                        severity = 3; // HIGH - wearables can have communication features
                        reason = "Bluetooth wearable device detected - potential communication risk";
                    }

                    DeviceViolation violation;
                    violation.deviceId = "BT_" + deviceAddress;
                    violation.deviceName = deviceName;
                    violation.violationType = "bluetooth-device";
                    violation.severity = severity;
                    violation.reason = reason;
                    violation.evidence = "Type: " + deviceType + ", Device: " + deviceName +
                                       ", Address: " + deviceAddress + ", Connected: " +
                                       (deviceInfo.fConnected ? "Yes" : "No");
                    violation.persistent = true;

                    activeViolations_.push_back(violation);
                    EmitViolation(violation);
                    violationDetected = true;
                }

            } while (BluetoothFindNextDevice(hDeviceFind, &deviceInfo));

            BluetoothFindDeviceClose(hDeviceFind);
        }
    }

    return violationDetected;
}

// Windows-specific Bluetooth device detection using Bluetooth APIs (from BluetoothWatcher)
bool SmartDeviceDetector::DetectWindowsBluetoothDevices() {
    // Enhanced business logic: Check system type and wired device presence
    SystemInfo systemInfo = systemDetector_->DetectSystemType();
    bool hasWiredMouse = HasWiredMouse();
    bool hasWiredKeyboard = HasWiredKeyboard();
    int btMouseCount = CountBluetoothMice();
    int btKeyboardCount = CountBluetoothKeyboards();

    // Special case for desktop systems
    if (systemInfo.type == SystemType::DESKTOP) {
        // If no wired mouse and keyboard, allow 1 BT mouse and 1 BT keyboard
        if (!hasWiredMouse && !hasWiredKeyboard) {
            // Allow up to 1 BT mouse and 1 BT keyboard, but flag if exceeded
            if (btMouseCount <= 1 && btKeyboardCount <= 1) {
                // Check for non-input Bluetooth devices only
                return DetectNonInputBluetoothDevices();
            }
        }
        // If wired devices present, flag any BT input devices
        else if (hasWiredMouse || hasWiredKeyboard) {
            // Any BT input devices are violations when wired devices present
            // Continue with normal detection
        }
    }

    // For laptops or when BT device limits exceeded, use strict detection
    if (securityProfile_.allowBluetooth) {
        return false; // Bluetooth is allowed, no violation
    }

    bool violationDetected = false;

    // Check if Bluetooth is available using the proper Bluetooth API
    BLUETOOTH_FIND_RADIO_PARAMS radioParams = { sizeof(BLUETOOTH_FIND_RADIO_PARAMS) };
    HANDLE hRadio;
    HBLUETOOTH_RADIO_FIND hFind = BluetoothFindFirstRadio(&radioParams, &hRadio);

    if (hFind != NULL) {
        // Bluetooth adapter is enabled - this itself is a violation in strict mode
        DeviceViolation adapterViolation;
        adapterViolation.deviceId = "BT_ADAPTER_ENABLED";
        adapterViolation.deviceName = "Bluetooth Adapter";
        adapterViolation.violationType = "bluetooth-adapter";
        adapterViolation.severity = 2; // MEDIUM
        adapterViolation.reason = "Bluetooth adapter enabled in strict mode";
        adapterViolation.evidence = "Bluetooth radio detected and enabled";
        adapterViolation.persistent = true;

        activeViolations_.push_back(adapterViolation);
        EmitViolation(adapterViolation);
        violationDetected = true;

        // Clean up radio handle
        CloseHandle(hRadio);
        BluetoothFindRadioClose(hFind);

        // Enumerate connected/paired devices
        BLUETOOTH_DEVICE_SEARCH_PARAMS deviceSearchParams = { 0 };
        deviceSearchParams.dwSize = sizeof(BLUETOOTH_DEVICE_SEARCH_PARAMS);
        deviceSearchParams.fReturnAuthenticated = TRUE;
        deviceSearchParams.fReturnRemembered = TRUE;
        deviceSearchParams.fReturnConnected = TRUE;
        deviceSearchParams.fReturnUnknown = FALSE;
        deviceSearchParams.fIssueInquiry = FALSE;
        deviceSearchParams.cTimeoutMultiplier = 2;

        BLUETOOTH_DEVICE_INFO deviceInfo = { 0 };
        deviceInfo.dwSize = sizeof(BLUETOOTH_DEVICE_INFO);

        HBLUETOOTH_DEVICE_FIND hDeviceFind = BluetoothFindFirstDevice(&deviceSearchParams, &deviceInfo);
        if (hDeviceFind != NULL) {
            do {
                // Convert wide string to UTF-8
                std::string deviceName = WideStringToUtf8(deviceInfo.szName);

                // Format address
                char addressStr[20];
                int result = _snprintf_s(addressStr, sizeof(addressStr), _TRUNCATE,
                    "%02X:%02X:%02X:%02X:%02X:%02X",
                    deviceInfo.Address.rgBytes[5],
                    deviceInfo.Address.rgBytes[4],
                    deviceInfo.Address.rgBytes[3],
                    deviceInfo.Address.rgBytes[2],
                    deviceInfo.Address.rgBytes[1],
                    deviceInfo.Address.rgBytes[0]);

                std::string deviceAddress = (result > 0) ? std::string(addressStr) : "Unknown";

                // Enhanced device filtering
                if (!deviceName.empty() && deviceName != "Unknown" &&
                    deviceAddress != "Unknown" && deviceAddress.length() == 17) {

                    // Convert to lowercase for pattern matching
                    std::string deviceNameLower = deviceName;
                    std::transform(deviceNameLower.begin(), deviceNameLower.end(), deviceNameLower.begin(), ::tolower);

                    // Determine device type and severity
                    int severity = 2; // MEDIUM by default
                    std::string deviceType = "Unknown Bluetooth Device";
                    std::string reason = "Bluetooth device detected in strict mode";

                    // Classify device type for better reporting and risk assessment
                    if (deviceNameLower.find("headphone") != std::string::npos ||
                        deviceNameLower.find("earphone") != std::string::npos ||
                        deviceNameLower.find("earbuds") != std::string::npos ||
                        deviceNameLower.find("airpods") != std::string::npos ||
                        deviceNameLower.find("speaker") != std::string::npos ||
                        deviceNameLower.find("audio") != std::string::npos ||
                        deviceNameLower.find("beats") != std::string::npos ||
                        deviceNameLower.find("bose") != std::string::npos ||
                        deviceNameLower.find("sony") != std::string::npos) {
                        deviceType = "Bluetooth Audio Device";
                        severity = 3; // HIGH - audio devices can record/transmit exam content
                        reason = "Bluetooth audio device detected - potential for recording or assistance";
                    }
                    else if (deviceNameLower.find("mouse") != std::string::npos ||
                             deviceNameLower.find("keyboard") != std::string::npos ||
                             deviceNameLower.find("trackpad") != std::string::npos) {
                        deviceType = "Bluetooth Input Device";
                        severity = 2; // MEDIUM - input devices less concerning than audio
                        reason = "Bluetooth input device detected in strict mode";

                        // Apply enhanced business logic for desktop systems
                        SystemInfo sysInfo = systemDetector_->DetectSystemType();
                        if (sysInfo.type == SystemType::DESKTOP) {
                            bool wiredMouse = HasWiredMouse();
                            bool wiredKeyboard = HasWiredKeyboard();

                            if (!wiredMouse && !wiredKeyboard) {
                                // Check if this is within allowed limits
                                bool isMouse = deviceNameLower.find("mouse") != std::string::npos;
                                bool isKeyboard = deviceNameLower.find("keyboard") != std::string::npos;

                                int totalBtMice = CountBluetoothMice();
                                int totalBtKeyboards = CountBluetoothKeyboards();

                                if ((isMouse && totalBtMice <= 1) || (isKeyboard && totalBtKeyboards <= 1)) {
                                    // This device is allowed, skip violation
                                    continue;
                                } else {
                                    reason = "Bluetooth input device limit exceeded on desktop (max 1 mouse + 1 keyboard when no wired devices)";
                                    severity = 3; // HIGH for exceeding limits
                                }
                            } else {
                                reason = "Bluetooth input device detected on desktop with wired devices present";
                                severity = 3; // HIGH when wired devices present
                            }
                        }
                    }
                    else if (deviceNameLower.find("phone") != std::string::npos ||
                             deviceNameLower.find("tablet") != std::string::npos ||
                             deviceNameLower.find("mobile") != std::string::npos ||
                             deviceNameLower.find("iphone") != std::string::npos ||
                             deviceNameLower.find("ipad") != std::string::npos ||
                             deviceNameLower.find("android") != std::string::npos) {
                        deviceType = "Bluetooth Mobile Device";
                        severity = 4; // CRITICAL - mobile devices are high risk
                        reason = "Bluetooth mobile device detected - high cheating risk";
                    }
                    else if (deviceNameLower.find("watch") != std::string::npos ||
                             deviceNameLower.find("fitness") != std::string::npos ||
                             deviceNameLower.find("band") != std::string::npos) {
                        deviceType = "Bluetooth Wearable Device";
                        severity = 3; // HIGH - wearables can have communication features
                        reason = "Bluetooth wearable device detected - potential communication risk";
                    }

                    DeviceViolation violation;
                    violation.deviceId = "BT_" + deviceAddress;
                    violation.deviceName = deviceName;
                    violation.violationType = "bluetooth-device";
                    violation.severity = severity;
                    violation.reason = reason;
                    violation.evidence = "Type: " + deviceType + ", Device: " + deviceName +
                                       ", Address: " + deviceAddress + ", Connected: " +
                                       (deviceInfo.fConnected ? "Yes" : "No");
                    violation.persistent = true;

                    activeViolations_.push_back(violation);
                    EmitViolation(violation);
                    violationDetected = true;
                }

            } while (BluetoothFindNextDevice(hDeviceFind, &deviceInfo));

            BluetoothFindDeviceClose(hDeviceFind);
        }
    }

    return violationDetected;
}

void SmartDeviceDetector::ScanAndAnalyzeDevices() {
    // Clear previous violations
    activeViolations_.clear();

    // Scan all input devices
    std::vector<InputDeviceInfo> currentDevices = ScanAllInputDevices();

    // Check for violations
    for (const auto& device : currentDevices) {
        if (!IsDeviceAllowed(device)) {
            DeviceViolation violation;
            violation.deviceId = device.deviceId;
            violation.deviceName = device.name;
            violation.violationType = "unauthorized-device";
            violation.severity = device.threatLevel;
            violation.reason = device.threatReason;
            violation.persistent = true;

            activeViolations_.push_back(violation);
        }
    }

    // Scan video devices for webcam analysis
    std::vector<InputDeviceInfo> videoDevices = ScanVideoDevices();
    for (const auto& device : videoDevices) {
        if (!IsWebcamAllowed(device)) {
            DeviceViolation violation;
            violation.deviceId = device.deviceId;
            violation.deviceName = device.name;
            violation.violationType = "unauthorized-video-device";
            violation.severity = device.threatLevel;
            violation.reason = device.threatReason;
            violation.persistent = true;

            activeViolations_.push_back(violation);
        }
    }

    // Advanced threat detection
    if (DetectWindowsVirtualDevices()) {
        // Violation already added in detection method
    }

    if (DetectWindowsSecondaryDisplays()) {
        // Violation already added in detection method
    }

    if (DetectWindowsNetworkInterfaces()) {
        // Violation already added in detection method
    }

    if (DetectWindowsMobileDevices()) {
        // Violation already added in detection method
    }

    if (DetectWindowsBluetoothDevices()) {
        // Violation already added in detection method
    }

    // Emit violations
    for (const auto& violation : activeViolations_) {
        EmitViolation(violation);
    }

    // Store current devices
    lastKnownDevices_ = currentDevices;
}

// Cross-platform secondary display detection
bool SmartDeviceDetector::DetectSecondaryDisplays() {
#ifdef _WIN32
    return DetectWindowsSecondaryDisplays();
#elif __APPLE__
    return DetectMacOSSecondaryDisplays();
#else
    return false;
#endif
}

// Cross-platform network interface detection
bool SmartDeviceDetector::DetectNetworkInterfaces() {
#ifdef _WIN32
    return DetectWindowsNetworkInterfaces();
#elif __APPLE__
    return DetectMacOSNetworkInterfaces();
#else
    return false;
#endif
}

// Cross-platform mobile device detection
bool SmartDeviceDetector::DetectMobileDevices() {
#ifdef _WIN32
    return DetectWindowsMobileDevices();
#elif __APPLE__
    return DetectMacOSMobileDevices();
#else
    return false;
#endif
}

// Cross-platform Bluetooth device detection
bool SmartDeviceDetector::DetectBluetoothSpoofers() {
#ifdef _WIN32
    return DetectWindowsBluetoothDevices();
#elif __APPLE__
    return DetectMacOSBluetoothDevices();
#else
    return false;
#endif
}

// Windows-specific virtual device detection
bool SmartDeviceDetector::DetectWindowsVirtualDevices() {
    bool violationDetected = false;

    // Initialize COM
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);

    // Initialize WMI
    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;

    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (SUCCEEDED(hr)) {
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr, 0, NULL, 0, 0, &pSvc);
        if (SUCCEEDED(hr)) {
            CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

            // CRITICAL: Check for virtual audio devices first (matches macOS logic)
            IEnumWbemClassObject* pAudioEnumerator = nullptr;
            hr = pSvc->ExecQuery(bstr_t("WQL"),
                bstr_t(L"SELECT * FROM Win32_SoundDevice"),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &pAudioEnumerator);

            if (SUCCEEDED(hr)) {
                IWbemClassObject* pclsObj = nullptr;
                ULONG uReturn = 0;

                while (pAudioEnumerator) {
                    hr = pAudioEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                    if (uReturn == 0) break;

                    VARIANT vtProp;
                    VariantInit(&vtProp);

                    std::string deviceName, manufacturer;

                    // Get device name
                    hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
                    if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                        deviceName = ConvertBSTRToString(vtProp.bstrVal);
                    }
                    VariantClear(&vtProp);

                    // Get manufacturer
                    hr = pclsObj->Get(L"Manufacturer", 0, &vtProp, 0, 0);
                    if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                        manufacturer = ConvertBSTRToString(vtProp.bstrVal);
                    }
                    VariantClear(&vtProp);

                    // Check for virtual audio device indicators (exact same logic as macOS)
                    std::string deviceNameLower = deviceName;
                    std::string manufacturerLower = manufacturer;
                    std::transform(deviceNameLower.begin(), deviceNameLower.end(), deviceNameLower.begin(), ::tolower);
                    std::transform(manufacturerLower.begin(), manufacturerLower.end(), manufacturerLower.begin(), ::tolower);

                    if (deviceNameLower.find("virtual") != std::string::npos ||
                        deviceNameLower.find("loopback") != std::string::npos ||
                        deviceNameLower.find("vb-audio") != std::string::npos ||
                        deviceNameLower.find("voicemeeter") != std::string::npos ||
                        manufacturerLower.find("rogue amoeba") != std::string::npos ||
                        manufacturerLower.find("soundflower") != std::string::npos ||
                        manufacturerLower.find("vb-audio") != std::string::npos) {

                        DeviceViolation violation;
                        violation.deviceName = deviceName;
                        violation.violationType = "virtual-audio-device";
                        violation.severity = 4; // CRITICAL (matches macOS)
                        violation.reason = "Virtual audio device detected - potential audio manipulation";
                        violation.persistent = true;

                        activeViolations_.push_back(violation);
                        EmitViolation(violation);
                        pclsObj->Release();
                        pAudioEnumerator->Release();
                        pSvc->Release();
                        pLoc->Release();
                        CoUninitialize();
                        return true; // Match macOS early return behavior
                    }

                    pclsObj->Release();
                }

                pAudioEnumerator->Release();
            }

            // Then check for general virtual devices
            IEnumWbemClassObject* pEnumerator = nullptr;
            hr = pSvc->ExecQuery(bstr_t("WQL"),
                bstr_t(L"SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE '%ROOT\\%' OR Name LIKE '%Virtual%' OR Name LIKE '%VMware%' OR Name LIKE '%VirtualBox%'"),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &pEnumerator);

            if (SUCCEEDED(hr)) {
                IWbemClassObject* pclsObj = nullptr;
                ULONG uReturn = 0;

                while (pEnumerator) {
                    hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                    if (uReturn == 0) break;

                    VARIANT vtProp;
                    VariantInit(&vtProp);

                    std::string deviceName, deviceId;

                    // Get device name
                    hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
                    if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                        deviceName = ConvertBSTRToString(vtProp.bstrVal);
                    }
                    VariantClear(&vtProp);

                    // Get device ID
                    hr = pclsObj->Get(L"DeviceID", 0, &vtProp, 0, 0);
                    if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                        deviceId = ConvertBSTRToString(vtProp.bstrVal);
                    }
                    VariantClear(&vtProp);

                    // Check if this is a virtual device we should flag
                    std::string deviceNameLower = deviceName;
                    std::transform(deviceNameLower.begin(), deviceNameLower.end(), deviceNameLower.begin(), ::tolower);

                    if (!securityProfile_.allowVirtualDevices &&
                        (deviceNameLower.find("virtual") != std::string::npos ||
                         deviceNameLower.find("vmware") != std::string::npos ||
                         deviceNameLower.find("virtualbox") != std::string::npos ||
                         deviceNameLower.find("hyper-v") != std::string::npos ||
                         deviceId.find("ROOT\\") == 0)) {

                        DeviceViolation violation;
                        violation.deviceId = deviceId;
                        violation.deviceName = deviceName;
                        violation.violationType = "virtual-device";
                        violation.severity = 3; // HIGH
                        violation.reason = "Virtual device detected in strict mode";
                        violation.evidence = "Device: " + deviceName + ", ID: " + deviceId;
                        violation.persistent = true;

                        activeViolations_.push_back(violation);
                        EmitViolation(violation);
                        violationDetected = true;
                    }

                    pclsObj->Release();
                }

                pEnumerator->Release();
            }

            pSvc->Release();
        }
        pLoc->Release();
    }

    CoUninitialize();
    return violationDetected;
}

// Windows-specific storage device scanning
std::vector<StorageDeviceInfo> SmartDeviceDetector::ScanAllStorageDevices() {
#ifdef _WIN32
    return ScanWindowsStorageDevices();
#elif __APPLE__
    return ScanMacOSStorageDevices();
#else
    return std::vector<StorageDeviceInfo>();
#endif
}

// Windows-specific virtual device detection method
bool SmartDeviceDetector::DetectVirtualDevices() {
#ifdef _WIN32
    return DetectWindowsVirtualDevices();
#elif __APPLE__
    return DetectMacOSVirtualDevices();
#else
    return false;
#endif
}

// Device classification helper methods (need to be implemented)
bool SmartDeviceDetector::IsMouseDevice(const InputDeviceInfo& device) {
    std::string typeLower = device.type;
    std::transform(typeLower.begin(), typeLower.end(), typeLower.begin(), ::tolower);

    std::string nameLower = device.name;
    std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);

    return typeLower.find("mouse") != std::string::npos ||
           nameLower.find("mouse") != std::string::npos ||
           nameLower.find("pointing") != std::string::npos;
}

bool SmartDeviceDetector::IsKeyboardDevice(const InputDeviceInfo& device) {
    std::string typeLower = device.type;
    std::transform(typeLower.begin(), typeLower.end(), typeLower.begin(), ::tolower);

    std::string nameLower = device.name;
    std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);

    return typeLower.find("keyboard") != std::string::npos ||
           nameLower.find("keyboard") != std::string::npos;
}

bool SmartDeviceDetector::IsVirtualDevice(const InputDeviceInfo& device) {
    std::string nameLower = device.name;
    std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);

    std::string idLower = device.deviceId;
    std::transform(idLower.begin(), idLower.end(), idLower.begin(), ::tolower);

    return nameLower.find("virtual") != std::string::npos ||
           nameLower.find("vmware") != std::string::npos ||
           nameLower.find("virtualbox") != std::string::npos ||
           nameLower.find("hyper-v") != std::string::npos ||
           idLower.find("root\\") == 0;
}

bool SmartDeviceDetector::IsSpoofedDevice(const InputDeviceInfo& device) {
    std::string nameLower = device.name;
    std::string manufacturerLower = device.manufacturer;
    std::string modelLower = device.model;

    std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);
    std::transform(manufacturerLower.begin(), manufacturerLower.end(), manufacturerLower.begin(), ::tolower);
    std::transform(modelLower.begin(), modelLower.end(), modelLower.begin(), ::tolower);

    // Check for invalid vendor/product IDs (common in spoofed devices)
    if (device.vendorId == "0x0000" || device.productId == "0x0000" ||
        device.vendorId == "0xFFFF" || device.productId == "0xFFFF" ||
        device.vendorId.empty() || device.productId.empty()) {
        return true;
    }

    // Enhanced spoofing patterns
    std::vector<std::string> spoofingPatterns = {
        "generic", "unknown", "fake", "dummy", "test", "emulated",
        "spoof", "virtual", "simulated", "mock", "placeholder",
        "default device", "standard device", "composite device",
        "root device", "null device", "sample device", "demo",
        "debug", "development", "prototype", "experimental"
    };

    // Check device name against spoofing patterns
    for (const auto& pattern : spoofingPatterns) {
        if (nameLower.find(pattern) != std::string::npos) {
            return true;
        }
    }

    // Check manufacturer against known spoofing indicators
    std::vector<std::string> suspiciousManufacturers = {
        "generic", "unknown", "fake", "test", "sample", "debug",
        "null", "default", "standard", "composite", "root"
    };

    for (const auto& manufacturer : suspiciousManufacturers) {
        if (manufacturerLower.find(manufacturer) != std::string::npos) {
            return true;
        }
    }

    // Check for suspicious device ID patterns
    std::string deviceIdLower = device.deviceId;
    std::transform(deviceIdLower.begin(), deviceIdLower.end(), deviceIdLower.begin(), ::tolower);

    if (deviceIdLower.find("null") != std::string::npos ||
        deviceIdLower.find("test") != std::string::npos ||
        deviceIdLower.find("fake") != std::string::npos ||
        deviceIdLower.find("dummy") != std::string::npos) {
        return true;
    }

    // Check for suspiciously short or generic names
    if (device.name.length() < 3 ||
        (device.name.length() < 10 &&
         (nameLower == "device" || nameLower == "camera" ||
          nameLower == "webcam" || nameLower == "usb"))) {
        return true;
    }

    // Check for mismatched vendor ID and manufacturer name
    if (!device.vendorId.empty() && !manufacturerLower.empty()) {
        // Known vendor ID to manufacturer mappings
        std::map<std::string, std::string> knownVendors = {
            {"0x046d", "logitech"},
            {"0x045e", "microsoft"},
            {"0x041e", "creative"},
            {"0x1532", "razer"},
            {"0x0b05", "asus"},
            {"0x03f0", "hp"},
            {"0x413c", "dell"},
            {"0x17ef", "lenovo"},
            {"0x054c", "sony"}
        };

        auto vendorIt = knownVendors.find(device.vendorId);
        if (vendorIt != knownVendors.end()) {
            if (manufacturerLower.find(vendorIt->second) == std::string::npos) {
                // Vendor ID doesn't match manufacturer name - potential spoofing
                return true;
            }
        }
    }

    return false;
}

bool SmartDeviceDetector::IsBluetoothDevice(const InputDeviceInfo& device) {
    std::string idLower = device.deviceId;
    std::transform(idLower.begin(), idLower.end(), idLower.begin(), ::tolower);

    std::string nameLower = device.name;
    std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);

    return idLower.find("bthenum") != std::string::npos ||
           idLower.find("bluetooth") != std::string::npos ||
           nameLower.find("bluetooth") != std::string::npos;
}

bool SmartDeviceDetector::IsWirelessDevice(const InputDeviceInfo& device) {
    std::string nameLower = device.name;
    std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);

    return nameLower.find("wireless") != std::string::npos ||
           nameLower.find("wifi") != std::string::npos ||
           nameLower.find("2.4g") != std::string::npos ||
           nameLower.find("radio") != std::string::npos ||
           device.isBluetooth; // Bluetooth is also wireless
}

// Enhanced virtual camera detection with comprehensive pattern matching
bool SmartDeviceDetector::IsVirtualCamera(const InputDeviceInfo& device) {
    std::string nameLower = device.name;
    std::string manufacturerLower = device.manufacturer;
    std::string modelLower = device.model;

    std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);
    std::transform(manufacturerLower.begin(), manufacturerLower.end(), manufacturerLower.begin(), ::tolower);
    std::transform(modelLower.begin(), modelLower.end(), modelLower.begin(), ::tolower);

    // Comprehensive virtual camera patterns
    std::vector<std::string> virtualPatterns = {
        "virtual", "emulated", "software", "obs", "streamlabs", "manycam", "camtwist",
        "loopback", "snap camera", "nvidia broadcast", "xsplit", "wirecast", "mmhmm",
        "chromacam", "youcam", "virtualbox", "vmware", "bandicam", "droidcam", "iriun",
        "epoccam", "ndi", "dslr", "sparkocam", "altercam", "fake", "test", "dummy",
        "simulator", "unity", "unreal", "blender", "virtual device", "capture card",
        "screen capture", "desktop", "broadcaster", "recording", "stream", "live",
        "webcam plus", "cyberlink", "perfect cam", "webcam max", "photo booth effects",
        "face time hd camera (virtual)", "integrated camera (virtual)", "usb camera (virtual)"
    };

    // Check device name against patterns
    for (const auto& pattern : virtualPatterns) {
        if (nameLower.find(pattern) != std::string::npos) {
            return true;
        }
    }

    // Check manufacturer against known virtual camera creators
    std::vector<std::string> virtualManufacturers = {
        "obs project", "streamlabs", "manycam", "xsplit", "nvidia",
        "cyberlink", "e2esoft", "webcam 7", "fake webcam", "virtual webcam"
    };

    for (const auto& manufacturer : virtualManufacturers) {
        if (manufacturerLower.find(manufacturer) != std::string::npos) {
            return true;
        }
    }

    // Check for suspicious device IDs (common for virtual cameras)
    std::string deviceIdLower = device.deviceId;
    std::transform(deviceIdLower.begin(), deviceIdLower.end(), deviceIdLower.begin(), ::tolower);

    if (deviceIdLower.find("vid_0000&pid_0000") != std::string::npos ||
        deviceIdLower.find("vid_ffff") != std::string::npos ||
        deviceIdLower.find("virtual") != std::string::npos) {
        return true;
    }

    return false;
}

// Additional required methods - EXACT SAME LOGIC AS MACOS
int SmartDeviceDetector::CalculateThreatLevel(const InputDeviceInfo& device) {
    int threat = 0;

    // Critical threats (exact same as macOS)
    if (device.isSpoofed) threat = 4;
    if (device.isVirtual && device.type == "keyboard") threat = 4; // Virtual keyboards are critical

    // High threats (exact same as macOS)
    if (device.isBluetooth) threat = std::max(threat, 3);
    if (device.isWireless) threat = std::max(threat, 3);
    if (device.isVirtual) threat = std::max(threat, 3);

    // Medium threats (exact same as macOS)
    if (device.isExternal && IsKeyboardDevice(device)) threat = std::max(threat, 2);
    if (device.isExternal && IsMouseDevice(device)) threat = std::max(threat, 2);

    // Suspicious vendor patterns (exact same as macOS)
    for (const auto& suspiciousVendor : suspiciousVendors_) {
        if (device.manufacturer.find(suspiciousVendor) != std::string::npos) {
            threat = std::max(threat, 2);
        }
    }

    return threat;
}

std::string SmartDeviceDetector::GetThreatReason(const InputDeviceInfo& device) {
    std::vector<std::string> reasons;

    // EXACT SAME LOGIC AS MACOS
    if (device.isSpoofed) reasons.push_back("Device spoofing detected");
    if (device.isVirtual) reasons.push_back("Virtual device");
    if (device.isBluetooth) reasons.push_back("Bluetooth connection");
    if (device.isWireless) reasons.push_back("Wireless connection");
    if (device.isExternal && !IsDeviceAllowed(device)) reasons.push_back("Unauthorized external device");

    if (reasons.empty()) {
        return "Device appears safe";
    }

    std::string result;
    for (size_t i = 0; i < reasons.size(); ++i) {
        result += reasons[i];
        if (i < reasons.size() - 1) result += "; ";
    }

    return result;
}

bool SmartDeviceDetector::IsDeviceAllowed(const InputDeviceInfo& device) {
    // Check virtual devices
    if (device.isVirtual && !securityProfile_.allowVirtualDevices) {
        return false;
    }

    // Check spoofed devices (never allowed)
    if (device.isSpoofed) {
        return false;
    }

    // Check Bluetooth devices
    if (device.isBluetooth && !securityProfile_.allowBluetooth) {
        return false;
    }

    // Check wireless devices
    if (device.isWireless && !securityProfile_.allowWireless) {
        return false;
    }

    // Check external storage
    if (device.type == "storage" && device.isExternal && !securityProfile_.allowExternalStorage) {
        return false;
    }

    return true; // Device is allowed
}

// Video device specific methods
int SmartDeviceDetector::CalculateVideoDeviceThreatLevel(const InputDeviceInfo& device) {
    int threatLevel = 0;

    if (device.isVirtual) threatLevel += 4; // Virtual cameras are critical
    if (device.isSpoofed) threatLevel += 3;
    if (!IsBuiltInCamera(device) && !securityProfile_.allowExternalWebcams) threatLevel += 1;

    return (std::min)(threatLevel, 4);
}

std::string SmartDeviceDetector::GetVideoDeviceThreatReason(const InputDeviceInfo& device) {
    if (device.isVirtual) return "Virtual camera detected - high spoofing risk";
    if (device.isSpoofed) return "Spoofed camera device detected";
    if (!IsBuiltInCamera(device)) return "External camera detected";

    return "Camera appears legitimate";
}

bool SmartDeviceDetector::IsWebcamAllowed(const InputDeviceInfo& device) {
    if (device.isVirtual) return false; // Virtual cameras not allowed
    if (device.isSpoofed) return false; // Spoofed cameras not allowed

    // External webcams allowed based on policy
    return securityProfile_.allowExternalWebcams || IsBuiltInCamera(device);
}

// Enhanced video device analysis methods
bool SmartDeviceDetector::IsScreenRecordingDevice(const InputDeviceInfo& device) {
    std::string nameLower = device.name;
    std::string manufacturerLower = device.manufacturer;

    std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);
    std::transform(manufacturerLower.begin(), manufacturerLower.end(), manufacturerLower.begin(), ::tolower);

    std::vector<std::string> recordingPatterns = {
        "screen capture", "screen recorder", "desktop capture", "display capture",
        "obs", "streamlabs", "bandicam", "camtasia", "fraps", "nvidia shadowplay",
        "amd relive", "game capture", "streaming", "broadcast", "elgato",
        "capture card", "hdmi capture", "video capture card", "recording device"
    };

    for (const auto& pattern : recordingPatterns) {
        if (nameLower.find(pattern) != std::string::npos ||
            manufacturerLower.find(pattern) != std::string::npos) {
            return true;
        }
    }

    return false;
}

bool SmartDeviceDetector::IsSuspiciousVideoDevice(const InputDeviceInfo& device) {
    // Combination of multiple risk factors
    int suspicionScore = 0;

    if (device.isVirtual) suspicionScore += 3;
    if (device.isSpoofed) suspicionScore += 3;
    if (IsScreenRecordingDevice(device)) suspicionScore += 2;
    if (!IsLegitimateWebcam(device) && !IsBuiltInCamera(device)) suspicionScore += 2;

    // Check for suspicious patterns in device information
    std::string nameLower = device.name;
    std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);

    std::vector<std::string> suspiciousPatterns = {
        "hidden", "stealth", "spy", "covert", "invisible", "backdoor",
        "modified", "hacked", "cracked", "bypass", "exploit"
    };

    for (const auto& pattern : suspiciousPatterns) {
        if (nameLower.find(pattern) != std::string::npos) {
            suspicionScore += 2;
            break;
        }
    }

    return suspicionScore >= 3; // Threshold for suspicious behavior
}

std::string SmartDeviceDetector::GetVideoDeviceRiskAssessment(const InputDeviceInfo& device) {
    std::vector<std::string> risks;

    if (device.isVirtual) risks.push_back("Virtual camera (high spoofing risk)");
    if (device.isSpoofed) risks.push_back("Device spoofing detected");
    if (IsScreenRecordingDevice(device)) risks.push_back("Screen recording capability");
    if (!IsLegitimateWebcam(device)) risks.push_back("Unknown/untrusted manufacturer");
    if (!IsBuiltInCamera(device)) risks.push_back("External device");

    if (risks.empty()) {
        return "Low risk - legitimate built-in camera";
    }

    std::string assessment = "Risk factors: ";
    for (size_t i = 0; i < risks.size(); ++i) {
        if (i > 0) assessment += ", ";
        assessment += risks[i];
    }

    return assessment;
}

// Enhanced device classification methods
std::string SmartDeviceDetector::ClassifyDeviceType(const InputDeviceInfo& device) {
    std::string nameLower = device.name;
    std::string typeLower = device.type;

    std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);
    std::transform(typeLower.begin(), typeLower.end(), typeLower.begin(), ::tolower);

    // Keyboard classification
    if (IsKeyboardDevice(device)) {
        if (nameLower.find("gaming") != std::string::npos ||
            nameLower.find("mechanical") != std::string::npos) {
            return "gaming-keyboard";
        }
        if (nameLower.find("wireless") != std::string::npos ||
            device.isBluetooth || device.isWireless) {
            return "wireless-keyboard";
        }
        return "keyboard";
    }

    // Mouse classification
    if (IsMouseDevice(device)) {
        if (nameLower.find("gaming") != std::string::npos ||
            nameLower.find("optical") != std::string::npos) {
            return "gaming-mouse";
        }
        if (nameLower.find("wireless") != std::string::npos ||
            device.isBluetooth || device.isWireless) {
            return "wireless-mouse";
        }
        return "mouse";
    }

    // Video device classification
    if (typeLower.find("video") != std::string::npos ||
        nameLower.find("camera") != std::string::npos ||
        nameLower.find("webcam") != std::string::npos) {
        if (device.isVirtual) return "virtual-camera";
        if (IsScreenRecordingDevice(device)) return "screen-recorder";
        if (IsBuiltInCamera(device)) return "built-in-camera";
        return "external-camera";
    }

    // Storage device classification
    if (typeLower.find("storage") != std::string::npos ||
        nameLower.find("disk") != std::string::npos ||
        nameLower.find("drive") != std::string::npos) {
        if (nameLower.find("usb") != std::string::npos) return "usb-storage";
        if (nameLower.find("external") != std::string::npos) return "external-storage";
        return "storage-device";
    }

    // Audio device classification
    if (typeLower.find("audio") != std::string::npos ||
        nameLower.find("microphone") != std::string::npos ||
        nameLower.find("headset") != std::string::npos ||
        nameLower.find("speaker") != std::string::npos) {
        if (device.isBluetooth) return "bluetooth-audio";
        if (nameLower.find("microphone") != std::string::npos) return "microphone";
        return "audio-device";
    }

    // Network device classification
    if (nameLower.find("network") != std::string::npos ||
        nameLower.find("ethernet") != std::string::npos ||
        nameLower.find("wifi") != std::string::npos ||
        nameLower.find("bluetooth") != std::string::npos) {
        return "network-device";
    }

    // Generic classifications
    if (device.isVirtual) return "virtual-device";
    if (device.isBluetooth) return "bluetooth-device";
    if (device.isWireless) return "wireless-device";

    return "unknown-device";
}

std::string SmartDeviceDetector::GetDeviceRiskCategory(const InputDeviceInfo& device) {
    int threatLevel = CalculateThreatLevel(device);

    if (device.isVirtual || device.isSpoofed) {
        return "CRITICAL"; // Always critical for virtual/spoofed devices
    }

    switch (threatLevel) {
        case 4: return "CRITICAL";
        case 3: return "HIGH";
        case 2: return "MEDIUM";
        case 1: return "LOW";
        default: return "MINIMAL";
    }
}

bool SmartDeviceDetector::IsHighRiskDeviceCategory(const InputDeviceInfo& device) {
    std::string deviceType = ClassifyDeviceType(device);
    std::string riskCategory = GetDeviceRiskCategory(device);

    // High-risk device categories
    std::set<std::string> highRiskTypes = {
        "virtual-camera", "screen-recorder", "external-camera",
        "usb-storage", "external-storage", "virtual-device",
        "unknown-device"
    };

    // High-risk categories
    std::set<std::string> highRiskCategories = {
        "CRITICAL", "HIGH"
    };

    return highRiskTypes.find(deviceType) != highRiskTypes.end() ||
           highRiskCategories.find(riskCategory) != highRiskCategories.end();
}

// Analysis methods
bool SmartDeviceDetector::AnalyzeDeviceThreat(const InputDeviceInfo& device) {
    return CalculateThreatLevel(device) >= 2; // MEDIUM or higher is a threat
}

// Getter methods
std::vector<DeviceViolation> SmartDeviceDetector::GetActiveViolations() {
    return activeViolations_;
}

SystemSecurityProfile SmartDeviceDetector::GetSecurityProfile() {
    return securityProfile_;
}

// Missing monitoring and emission methods
void SmartDeviceDetector::MonitoringLoop() {
    while (running_.load()) {
        ScanAndAnalyzeDevices();
        EmitHeartbeat();

        std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs_));
    }
}

void SmartDeviceDetector::EmitViolation(const DeviceViolation& violation) {
    if (tsfn_) {
        // Emit violation to JavaScript callback
        tsfn_.BlockingCall([violation](Napi::Env env, Napi::Function jsCallback) {
            Napi::Object eventObj = Napi::Object::New(env);
            eventObj.Set("type", "violation");
            eventObj.Set("deviceId", violation.deviceId);
            eventObj.Set("deviceName", violation.deviceName);
            eventObj.Set("violationType", violation.violationType);
            eventObj.Set("severity", violation.severity);
            eventObj.Set("reason", violation.reason);
            eventObj.Set("evidence", violation.evidence);
            eventObj.Set("persistent", violation.persistent);

            jsCallback.Call({eventObj});
        });
    }
}

void SmartDeviceDetector::EmitHeartbeat() {
    counter_.fetch_add(1);

    if (tsfn_) {
        tsfn_.BlockingCall([this](Napi::Env env, Napi::Function jsCallback) {
            Napi::Object eventObj = Napi::Object::New(env);
            eventObj.Set("type", "heartbeat");
            eventObj.Set("counter", counter_.load());
            eventObj.Set("activeViolations", static_cast<int>(activeViolations_.size()));

            jsCallback.Call({eventObj});
        });
    }
}

// Threat pattern initialization
void SmartDeviceDetector::InitializeThreatPatterns() {
    InitializeSuspiciousVendors();
    InitializeVirtualDevicePatterns();
    InitializeKnownSpoofers();
}

void SmartDeviceDetector::InitializeSuspiciousVendors() {
    suspiciousVendors_.insert("0x0000"); // Invalid vendor ID
    suspiciousVendors_.insert("0xFFFF"); // Invalid vendor ID
    suspiciousVendors_.insert("generic");
    suspiciousVendors_.insert("unknown");
}

void SmartDeviceDetector::InitializeVirtualDevicePatterns() {
    virtualDevicePatterns_.insert("virtual");
    virtualDevicePatterns_.insert("vmware");
    virtualDevicePatterns_.insert("virtualbox");
    virtualDevicePatterns_.insert("hyper-v");
    virtualDevicePatterns_.insert("qemu");
    virtualDevicePatterns_.insert("parallels");
}

void SmartDeviceDetector::InitializeKnownSpoofers() {
    // Add known spoofing device signatures
    knownSpoofers_["fake_mouse_001"] = "Known spoofed mouse device";
    knownSpoofers_["generic_keyboard"] = "Generic keyboard - potential spoof";
}

// Utility methods
std::string SmartDeviceDetector::NormalizeDeviceName(const std::string& name) {
    std::string normalized = name;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::tolower);
    return normalized;
}

std::string SmartDeviceDetector::ExtractVendorFromName(const std::string& name) {
    // Extract vendor name from device name (simplified implementation)
    size_t pos = name.find(' ');
    if (pos != std::string::npos) {
        return name.substr(0, pos);
    }
    return name;
}

bool SmartDeviceDetector::MatchesPattern(const std::string& text, const std::string& pattern) {
    std::string textLower = text;
    std::transform(textLower.begin(), textLower.end(), textLower.begin(), ::tolower);

    std::string patternLower = pattern;
    std::transform(patternLower.begin(), patternLower.end(), patternLower.begin(), ::tolower);

    return textLower.find(patternLower) != std::string::npos;
}

void SmartDeviceDetector::LogSecurityEvent(const std::string& event, int severity) {
    // Log security event (implementation would depend on logging framework)
    // For now, this is a placeholder
}

