#ifndef BLUETOOTH_WATCHER_H
#define BLUETOOTH_WATCHER_H

#include <napi.h>
#include <string>
#include <vector>
#include <chrono>
#include <sstream>
#include <iomanip>

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
    std::string EscapeJsonString(const std::string& str);
};

Napi::Value GetBluetoothStatus(const Napi::CallbackInfo& info);

#endif // BLUETOOTH_WATCHER_H