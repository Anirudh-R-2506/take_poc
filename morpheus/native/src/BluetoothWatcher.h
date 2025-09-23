#ifndef BLUETOOTH_WATCHER_H
#define BLUETOOTH_WATCHER_H

#include <napi.h>
#include <string>
#include <vector>

struct BluetoothDevice {
    std::string name;
    std::string address;
    bool connected;
};

struct BluetoothStatus {
    bool enabled;
    std::vector<BluetoothDevice> devices;
    std::string error;
};

class BluetoothWatcher {
public:
    BluetoothWatcher();
    ~BluetoothWatcher();
    
    BluetoothStatus getCurrentStatus();
    std::string toJSON();

private:
    BluetoothStatus getBluetoothStatusMacOS();
    BluetoothStatus getBluetoothStatusWindows();
};

// N-API wrapper functions
Napi::Value GetBluetoothStatus(const Napi::CallbackInfo& info);

#endif // BLUETOOTH_WATCHER_H