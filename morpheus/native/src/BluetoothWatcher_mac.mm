#include "BluetoothWatcher.h"
#include <IOBluetooth/IOBluetooth.h>
#include <Foundation/Foundation.h>
#include "CommonTypes.h"
#include <sstream>

BluetoothWatcher::BluetoothWatcher() {
    // Constructor
}

BluetoothWatcher::~BluetoothWatcher() {
    // Destructor
}

BluetoothStatus BluetoothWatcher::getCurrentStatus() {
    return getBluetoothStatusMacOS();
}

BluetoothStatus BluetoothWatcher::getBluetoothStatusMacOS() {
    BluetoothStatus status;
    status.enabled = false;
    status.devices.clear();
    
    @autoreleasepool {
        // Check if Bluetooth is enabled
        IOBluetoothHostController* controller = [IOBluetoothHostController defaultController];
        if (controller == nil) {
            status.error = "Bluetooth controller not available";
            return status;
        }
        
        BluetoothHCIPowerState powerState = [controller powerState];
        status.enabled = (powerState == kBluetoothHCIPowerStateON);
        
        if (status.enabled) {
            // Get paired devices
            NSArray* pairedDevices = [IOBluetoothDevice pairedDevices];
            if (pairedDevices != nil) {
                for (IOBluetoothDevice* device in pairedDevices) {
                    BluetoothDevice btDevice;
                    
                    // Get device name
                    NSString* name = [device name];
                    if (name != nil) {
                        btDevice.name = std::string([name UTF8String]);
                    } else {
                        btDevice.name = "Unknown Device";
                    }
                    
                    // Get device address
                    NSString* address = [device addressString];
                    if (address != nil) {
                        btDevice.address = std::string([address UTF8String]);
                    } else {
                        btDevice.address = "Unknown Address";
                    }
                    
                    // Check if device is connected
                    btDevice.connected = [device isConnected];
                    
                    // Only add connected devices or known device types
                    if (btDevice.connected || !btDevice.name.empty()) {
                        status.devices.push_back(btDevice);
                    }
                }
            }
        }
    }
    
    return status;
}

BluetoothStatus BluetoothWatcher::getBluetoothStatusWindows() {
    // Not implemented for Windows in this file
    BluetoothStatus status;
    status.enabled = false;
    status.error = "Windows implementation not available in .mm file";
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