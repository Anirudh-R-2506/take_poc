#include "BluetoothWatcher.h"
#ifdef _WIN32
#include <windows.h>
#include <bluetoothapis.h>
#include <ws2bth.h>
#pragma comment(lib, "Bthprops.lib")
#pragma comment(lib, "ws2_32.lib")
#endif
#include <sstream>

BluetoothWatcher::BluetoothWatcher() {
    // Constructor
}

BluetoothWatcher::~BluetoothWatcher() {
    // Destructor
}

BluetoothStatus BluetoothWatcher::getCurrentStatus() {
    return getBluetoothStatusWindows();
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
                
                // Convert wide string to string
                std::wstring wName(deviceInfo.szName);
                btDevice.name = std::string(wName.begin(), wName.end());
                
                // Format address
                char addressStr[18];
                sprintf_s(addressStr, "%02X:%02X:%02X:%02X:%02X:%02X",
                    deviceInfo.Address.rgBytes[5],
                    deviceInfo.Address.rgBytes[4],
                    deviceInfo.Address.rgBytes[3],
                    deviceInfo.Address.rgBytes[2],
                    deviceInfo.Address.rgBytes[1],
                    deviceInfo.Address.rgBytes[0]);
                btDevice.address = std::string(addressStr);
                
                btDevice.connected = deviceInfo.fConnected;
                
                if (!btDevice.name.empty()) {
                    status.devices.push_back(btDevice);
                }
                
            } while (BluetoothFindNextDevice(hDeviceFind, &deviceInfo));
            
            BluetoothFindDeviceClose(hDeviceFind);
        }
    } else {
        status.error = "No Bluetooth radio found";
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
    json << "\"enabled\":" << (status.enabled ? "true" : "false") << ",";
    json << "\"error\":\"" << status.error << "\",";
    json << "\"devices\":[";
    
    for (size_t i = 0; i < status.devices.size(); i++) {
        if (i > 0) json << ",";
        json << "{";
        json << "\"name\":\"" << status.devices[i].name << "\",";
        json << "\"address\":\"" << status.devices[i].address << "\",";
        json << "\"connected\":" << (status.devices[i].connected ? "true" : "false");
        json << "}";
    }
    
    json << "]}";
    return json.str();
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