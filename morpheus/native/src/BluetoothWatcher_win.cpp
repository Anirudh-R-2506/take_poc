#include "BluetoothWatcher.h"
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bluetoothapis.h>
#include <ws2bth.h>
#pragma comment(lib, "Bthprops.lib")
#pragma comment(lib, "ws2_32.lib")

// Helper function for wide string to UTF-8 conversion (2025 best practice)
static std::string WideStringToUtf8(const wchar_t* wideStr) {
    if (!wideStr) return "";

    int utf8Length = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, nullptr, 0, nullptr, nullptr);
    if (utf8Length <= 0) return "";

    std::vector<char> utf8Buffer(utf8Length);
    WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, utf8Buffer.data(), utf8Length, nullptr, nullptr);
    return std::string(utf8Buffer.data());
}
#endif

#include <sstream>
#include <iostream>
#include <vector>

BluetoothWatcher::BluetoothWatcher() {
    // Constructor
}

BluetoothWatcher::~BluetoothWatcher() {
    // Destructor
}

BluetoothStatus BluetoothWatcher::getCurrentStatus() {
#ifdef _WIN32
    return getBluetoothStatusWindows();
#elif __APPLE__
    return getBluetoothStatusMacOS();
#else
    BluetoothStatus status;
    status.enabled = false;
    status.error = "Unsupported platform";
    return status;
#endif
}

BluetoothStatus BluetoothWatcher::getBluetoothStatusWindows() {
    BluetoothStatus status;
    status.enabled = false;
    status.devices.clear();
    
#ifdef _WIN32
    // Check if Bluetooth is available
    BLUETOOTH_FIND_RADIO_PARAMS radioParams = { sizeof(BLUETOOTH_FIND_RADIO_PARAMS) };
    HANDLE hRadio;
    HBLUETOOTH_RADIO_FIND hFind = BluetoothFindFirstRadio(&radioParams, &hRadio);
    
    if (hFind != NULL) {
        status.enabled = true;
        
        // Clean up radio handle
        CloseHandle(hRadio);
        BluetoothFindRadioClose(hFind);
        
        // Enumerate devices
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
                BluetoothDevice btDevice;
                
                // Convert wide string to UTF-8 (2025 best practice)
                btDevice.name = WideStringToUtf8(deviceInfo.szName);
                
                // Format address with improved error handling (2025 production)
                char addressStr[20]; // Larger buffer for safety
                int result = _snprintf_s(addressStr, sizeof(addressStr), _TRUNCATE,
                    "%02X:%02X:%02X:%02X:%02X:%02X",
                    deviceInfo.Address.rgBytes[5],
                    deviceInfo.Address.rgBytes[4],
                    deviceInfo.Address.rgBytes[3],
                    deviceInfo.Address.rgBytes[2],
                    deviceInfo.Address.rgBytes[1],
                    deviceInfo.Address.rgBytes[0]);

                if (result > 0) {
                    btDevice.address = std::string(addressStr);
                } else {
                    btDevice.address = "Unknown";
                }
                
                btDevice.connected = deviceInfo.fConnected;
                
                // Enhanced device filtering (2025 production)
                if (!btDevice.name.empty() && btDevice.name != "Unknown" &&
                    btDevice.address != "Unknown" && btDevice.address.length() == 17) {
                    status.devices.push_back(btDevice);
                    std::cout << "[BluetoothWatcher] Found device: " << btDevice.name
                              << " (" << btDevice.address << "), connected: "
                              << (btDevice.connected ? "Yes" : "No") << std::endl;
                }
                
            } while (BluetoothFindNextDevice(hDeviceFind, &deviceInfo));
            
            BluetoothFindDeviceClose(hDeviceFind);
        }
    } else {
        DWORD lastError = GetLastError();
        status.error = "No Bluetooth radio found (error: " + std::to_string(lastError) + ")";
        std::cout << "[BluetoothWatcher] No Bluetooth radio found, error: " << lastError << std::endl;
    }
#else
    status.error = "Windows implementation not available on this platform";
#endif
    
    return status;
}

BluetoothStatus BluetoothWatcher::getBluetoothStatusMacOS() {
    // Not implemented for macOS in this file
    BluetoothStatus status;
    status.enabled = false;
    status.error = "macOS implementation not available in .cpp file";
    return status;
}

std::string BluetoothWatcher::toJSON() {
    BluetoothStatus status = getCurrentStatus();

    std::stringstream json;
    json << "{";
    json << "\"module\":\"bluetooth-watcher\",";
    json << "\"enabled\":" << (status.enabled ? "true" : "false") << ",";
    json << "\"error\":\"" << EscapeJsonString(status.error) << "\",";
    json << "\"deviceCount\":" << status.devices.size() << ",";
    json << "\"timestamp\":" << std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() << ",";
    json << "\"source\":\"native\",";
    json << "\"devices\":[";

    for (size_t i = 0; i < status.devices.size(); i++) {
        if (i > 0) json << ",";
        json << "{";
        json << "\"name\":\"" << EscapeJsonString(status.devices[i].name) << "\",";
        json << "\"address\":\"" << EscapeJsonString(status.devices[i].address) << "\",";
        json << "\"connected\":" << (status.devices[i].connected ? "true" : "false");
        json << "}";
    }

    json << "]}";
    return json.str();
}

// JSON string escaping helper (2025 production enhancement)
std::string BluetoothWatcher::EscapeJsonString(const std::string& str) {
    std::string escaped;
    escaped.reserve(str.length() + 10);

    for (char c : str) {
        switch (c) {
            case '"': escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\b': escaped += "\\b"; break;
            case '\f': escaped += "\\f"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default:
                if (c >= 0 && c < 32) {
                    std::stringstream ss;
                    ss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                    escaped += ss.str();
                } else {
                    escaped += c;
                }
                break;
        }
    }

    return escaped;
}

// N-API wrapper
Napi::Value GetBluetoothStatus(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    try {
        BluetoothWatcher watcher;
        std::string jsonResult = watcher.toJSON();
        
        return Napi::String::New(env, jsonResult);
    } catch (const std::exception& e) {
        Napi::TypeError::New(env, std::string("Bluetooth error: ") + e.what())
            .ThrowAsJavaScriptException();
        return env.Null();
    }
}