#include "SmartDeviceDetector.h"
#include <sstream>
#include <algorithm>
#include <regex>
#include <iostream>

#ifdef __APPLE__
#import <Foundation/Foundation.h>
#import <IOKit/graphics/IOGraphicsLib.h>
#import <IOKit/network/IOEthernetInterface.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <CoreGraphics/CoreGraphics.h>
#import <IOBluetooth/IOBluetooth.h>

// Helper function to get IORegistry property from service
std::string GetIORegistryProperty(io_object_t service, const char* propertyName) {
    if (service == IO_OBJECT_NULL || !propertyName) {
        return "";
    }

    CFTypeRef property = IORegistryEntryCreateCFProperty(service,
                                                        CFStringCreateWithCString(kCFAllocatorDefault, propertyName, kCFStringEncodingUTF8),
                                                        kCFAllocatorDefault, 0);
    if (!property) {
        return "";
    }

    std::string result;

    if (CFGetTypeID(property) == CFStringGetTypeID()) {
        char buffer[256];
        if (CFStringGetCString((CFStringRef)property, buffer, sizeof(buffer), kCFStringEncodingUTF8)) {
            result = std::string(buffer);
        }
    } else if (CFGetTypeID(property) == CFNumberGetTypeID()) {
        int value;
        if (CFNumberGetValue((CFNumberRef)property, kCFNumberIntType, &value)) {
            result = std::to_string(value);
        }
    }

    CFRelease(property);
    return result;
}
#endif

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
#ifdef __APPLE__
    return ScanMacOSInputDevices();
#elif _WIN32
    return ScanWindowsInputDevices();
#else
    return std::vector<InputDeviceInfo>();
#endif
}

#ifdef __APPLE__
std::vector<InputDeviceInfo> SmartDeviceDetector::ScanMacOSInputDevices() {
    std::vector<InputDeviceInfo> devices;

    @autoreleasepool {
        // Scan HID devices
        CFMutableDictionaryRef matchDict = IOServiceMatching(kIOHIDDeviceKey);
        io_iterator_t iterator;

        if (IOServiceGetMatchingServices(kIOMasterPortDefault, matchDict, &iterator) == KERN_SUCCESS) {
            io_object_t service;

            while ((service = IOIteratorNext(iterator))) {
                InputDeviceInfo device;

                // Get device properties
                device.name = GetIORegistryProperty(service, kIOHIDProductKey);
                device.manufacturer = GetIORegistryProperty(service, kIOHIDManufacturerKey);
                device.vendorId = GetIORegistryProperty(service, kIOHIDVendorIDKey);
                device.productId = GetIORegistryProperty(service, kIOHIDProductIDKey);

                // Generate device ID
                device.deviceId = device.vendorId + ":" + device.productId + ":" + device.name;

                // Classify device type
                CFTypeRef usagePage = IORegistryEntryCreateCFProperty(service, CFSTR(kIOHIDDeviceUsagePageKey), kCFAllocatorDefault, 0);
                CFTypeRef usage = IORegistryEntryCreateCFProperty(service, CFSTR(kIOHIDDeviceUsageKey), kCFAllocatorDefault, 0);

                if (usagePage && usage) {
                    int pageValue = 0, usageValue = 0;
                    CFNumberGetValue((CFNumberRef)usagePage, kCFNumberIntType, &pageValue);
                    CFNumberGetValue((CFNumberRef)usage, kCFNumberIntType, &usageValue);

                    if (pageValue == kHIDPage_GenericDesktop) {
                        if (usageValue == kHIDUsage_GD_Mouse) {
                            device.type = "mouse";
                        } else if (usageValue == kHIDUsage_GD_Keyboard) {
                            device.type = "keyboard";
                        } else if (usageValue == kHIDUsage_GD_Pointer) {
                            device.type = "trackpad";
                        }
                    }
                }

                if (usagePage) CFRelease(usagePage);
                if (usage) CFRelease(usage);

                // Advanced threat analysis
                device.isVirtual = IsVirtualDevice(device);
                device.isSpoofed = IsSpoofedDevice(device);
                device.isBluetooth = IsBluetoothDevice(device);
                device.isWireless = IsWirelessDevice(device);
                device.isExternal = true; // Assume external unless proven otherwise

                // Check if it's a built-in device
                std::string locationId = GetIORegistryProperty(service, kIOHIDLocationIDKey);
                if (locationId.find("internal") != std::string::npos ||
                    device.name.find("Built-in") != std::string::npos ||
                    device.manufacturer.find("Apple") != std::string::npos) {
                    device.isExternal = false;
                }

                // Calculate threat level
                device.threatLevel = CalculateThreatLevel(device);
                device.threatReason = GetThreatReason(device);
                device.isAllowed = IsDeviceAllowed(device);

                if (!device.name.empty() && !device.type.empty()) {
                    devices.push_back(device);
                }

                IOObjectRelease(service);
            }

            IOObjectRelease(iterator);
        }
    }

    return devices;
}

std::string SmartDeviceDetector::GetIORegistryProperty(io_service_t service, const char* property) {
    @autoreleasepool {
        if (service == IO_OBJECT_NULL || !property) {
            return "";
        }

        CFStringRef key = CFStringCreateWithCString(kCFAllocatorDefault, property, kCFStringEncodingUTF8);
        if (!key) {
            return "";
        }

        CFTypeRef value = IORegistryEntryCreateCFProperty(service, key, kCFAllocatorDefault, 0);
        CFRelease(key);

        if (!value) {
            return "";
        }

        std::string result;
        try {
            if (CFGetTypeID(value) == CFStringGetTypeID()) {
                char buffer[256];
                if (CFStringGetCString((CFStringRef)value, buffer, sizeof(buffer), kCFStringEncodingUTF8)) {
                    result = buffer;
                }
            } else if (CFGetTypeID(value) == CFNumberGetTypeID()) {
                int numberValue;
                if (CFNumberGetValue((CFNumberRef)value, kCFNumberIntType, &numberValue)) {
                    std::ostringstream oss;
                    oss << "0x" << std::hex << numberValue;
                    result = oss.str();
                }
            }
        } catch (...) {
            // Safety net for any CoreFoundation crashes
            result = "";
        }

        CFRelease(value);
        return result;
    }
}

bool SmartDeviceDetector::DetectMacOSVirtualDevices() {
    @autoreleasepool {
        // Check for virtual audio devices
        CFMutableDictionaryRef matchDict = IOServiceMatching("IOAudioDevice");
        io_iterator_t iterator;

        if (IOServiceGetMatchingServices(kIOMasterPortDefault, matchDict, &iterator) == KERN_SUCCESS) {
            io_object_t service;

            while ((service = IOIteratorNext(iterator))) {
                std::string deviceName = GetIORegistryProperty(service, "IOAudioDeviceName");
                std::string manufacturer = GetIORegistryProperty(service, "IOAudioDeviceManufacturerName");

                // Check for virtual device indicators
                if (deviceName.find("Virtual") != std::string::npos ||
                    deviceName.find("Loopback") != std::string::npos ||
                    manufacturer.find("Rogue Amoeba") != std::string::npos ||
                    manufacturer.find("Soundflower") != std::string::npos) {

                    DeviceViolation violation;
                    violation.deviceName = deviceName;
                    violation.violationType = "virtual-audio-device";
                    violation.severity = 4; // CRITICAL
                    violation.reason = "Virtual audio device detected - potential audio manipulation";
                    violation.persistent = true;

                    activeViolations_.push_back(violation);
                    IOObjectRelease(service);
                    IOObjectRelease(iterator);
                    return true;
                }

                IOObjectRelease(service);
            }

            IOObjectRelease(iterator);
        }

        return false;
    }
}

bool SmartDeviceDetector::DetectMacOSSecondaryDisplays() {
    @autoreleasepool {
        uint32_t displayCount;
        CGGetActiveDisplayList(0, nullptr, &displayCount);

        if (displayCount > 1) {
            DeviceViolation violation;
            violation.deviceName = "Secondary Display";
            violation.violationType = "multiple-displays";
            violation.severity = 3; // HIGH
            violation.reason = "Multiple displays detected - potential content sharing";
            violation.persistent = true;

            activeViolations_.push_back(violation);
            return true;
        }

        return false;
    }
}
#endif

bool SmartDeviceDetector::IsDeviceAllowed(const InputDeviceInfo& device) {
    // Critical violations - never allowed
    if (device.isSpoofed || device.threatLevel >= 3) {
        return false;
    }

    // Virtual devices not allowed in strict mode
    if (device.isVirtual && securityProfile_.strictMode) {
        return false;
    }

    // Bluetooth devices
    if (device.isBluetooth && !securityProfile_.allowBluetooth) {
        return false;
    }

    // Wireless devices
    if (device.isWireless && !securityProfile_.allowWireless) {
        return false;
    }

    // External device limits
    if (device.isExternal) {
        if (IsMouseDevice(device) && !securityProfile_.allowedMice) {
            return false;
        }
        if (IsKeyboardDevice(device) && !securityProfile_.allowedKeyboards) {
            return false;
        }
    }

    return true;
}

int SmartDeviceDetector::CalculateThreatLevel(const InputDeviceInfo& device) {
    int threat = 0;

    // Critical threats
    if (device.isSpoofed) threat = 4;
    if (device.isVirtual && device.type == "keyboard") threat = 4; // Virtual keyboards are critical

    // High threats
    if (device.isBluetooth) threat = std::max(threat, 3);
    if (device.isWireless) threat = std::max(threat, 3);
    if (device.isVirtual) threat = std::max(threat, 3);

    // Medium threats
    if (device.isExternal && IsKeyboardDevice(device)) threat = std::max(threat, 2);
    if (device.isExternal && IsMouseDevice(device)) threat = std::max(threat, 2);

    // Suspicious vendor patterns
    for (const auto& suspiciousVendor : suspiciousVendors_) {
        if (device.manufacturer.find(suspiciousVendor) != std::string::npos) {
            threat = std::max(threat, 2);
        }
    }

    return threat;
}

std::string SmartDeviceDetector::GetThreatReason(const InputDeviceInfo& device) {
    std::vector<std::string> reasons;

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

void SmartDeviceDetector::InitializeThreatPatterns() {
    // Suspicious vendors that often make spoofing/hacking devices
    suspiciousVendors_ = {
        "Unknown", "Generic", "USB", "HID", "Virtual", "Emulated",
        "Flipper", "BadUSB", "Rubber Ducky", "DigiSpark", "Teensy",
        "Arduino", "ESP32", "RaspberryPi", "Pi", "Hak5", "WiFi Pineapple"
    };

    // Virtual device patterns
    virtualDevicePatterns_ = {
        "Virtual", "Emulated", "Software", "Loopback", "Bridge",
        "VMware", "VirtualBox", "Parallels", "QEMU", "Hyper-V"
    };

    // Known spoofing device signatures
    knownSpoofers_ = {
        {"04D9:1702", "Spoofed Keyboard"}, // Common spoofed VID:PID
        {"413C:2107", "Fake Dell Mouse"},
        {"046D:C52B", "Fake Logitech Unifying"},
        {"1234:5678", "Generic Spoofed Device"}
    };
}

bool SmartDeviceDetector::IsMouseDevice(const InputDeviceInfo& device) {
    return device.type == "mouse" || device.type == "trackpad" ||
           device.name.find("Mouse") != std::string::npos ||
           device.name.find("Trackpad") != std::string::npos;
}

bool SmartDeviceDetector::IsKeyboardDevice(const InputDeviceInfo& device) {
    return device.type == "keyboard" ||
           device.name.find("Keyboard") != std::string::npos;
}

bool SmartDeviceDetector::IsVirtualDevice(const InputDeviceInfo& device) {
    for (const auto& pattern : virtualDevicePatterns_) {
        if (device.name.find(pattern) != std::string::npos ||
            device.manufacturer.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool SmartDeviceDetector::IsSpoofedDevice(const InputDeviceInfo& device) {
    std::string signature = device.vendorId + ":" + device.productId;

    // Check against known spoofed signatures
    if (knownSpoofers_.find(signature) != knownSpoofers_.end()) {
        return true;
    }

    // Check for suspicious vendor/product combinations
    if (device.vendorId == "0000" || device.productId == "0000") {
        return true; // Invalid VID/PID often indicates spoofing
    }

    return false;
}

bool SmartDeviceDetector::IsBluetoothDevice(const InputDeviceInfo& device) {
    return device.name.find("Bluetooth") != std::string::npos ||
           device.manufacturer.find("Bluetooth") != std::string::npos;
}

bool SmartDeviceDetector::IsWirelessDevice(const InputDeviceInfo& device) {
    return device.name.find("Wireless") != std::string::npos ||
           device.name.find("WiFi") != std::string::npos ||
           device.name.find("RF") != std::string::npos ||
           IsBluetoothDevice(device);
}

void SmartDeviceDetector::MonitoringLoop() {
    while (running_.load()) {
        try {
            @autoreleasepool {
                ScanAndAnalyzeDevices();
                EmitHeartbeat();
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs_));
        } catch (const std::exception& e) {
            // Log error but continue monitoring
            std::cerr << "[SmartDeviceDetector] Error in monitoring loop: " << e.what() << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs_));
        } catch (...) {
            // Catch all other exceptions including system crashes
            std::cerr << "[SmartDeviceDetector] Unknown error in monitoring loop" << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs_));
        }
    }
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
    if (DetectMacOSVirtualDevices()) {
        // Violation already added in detection method
    }

    if (DetectMacOSSecondaryDisplays()) {
        // Violation already added in detection method
    }

    if (DetectMacOSNetworkInterfaces()) {
        // Violation already added in detection method
    }

    if (DetectMacOSMobileDevices()) {
        // Violation already added in detection method
    }

    if (DetectMacOSBluetoothDevices()) {
        // Violation already added in detection method
    }

    // Emit violations
    for (const auto& violation : activeViolations_) {
        EmitViolation(violation);
    }

    lastKnownDevices_ = currentDevices;
}

void SmartDeviceDetector::EmitViolation(const DeviceViolation& violation) {
    if (tsfn_) {
        auto callback = [violation](Napi::Env env, Napi::Function jsCallback) {
            Napi::Object result = Napi::Object::New(env);
            result.Set("type", Napi::String::New(env, "device-violation"));
            result.Set("deviceId", Napi::String::New(env, violation.deviceId));
            result.Set("deviceName", Napi::String::New(env, violation.deviceName));
            result.Set("violationType", Napi::String::New(env, violation.violationType));
            result.Set("severity", Napi::Number::New(env, violation.severity));
            result.Set("reason", Napi::String::New(env, violation.reason));
            result.Set("evidence", Napi::String::New(env, violation.evidence));
            result.Set("timestamp", Napi::Number::New(env, violation.timestamp.count()));
            result.Set("persistent", Napi::Boolean::New(env, violation.persistent));

            jsCallback.Call({result});
        };

        tsfn_.BlockingCall(callback);
    }
}

void SmartDeviceDetector::EmitHeartbeat() {
    if (tsfn_) {
        auto callback = [this](Napi::Env env, Napi::Function jsCallback) {
            Napi::Object result = Napi::Object::New(env);
            result.Set("type", Napi::String::New(env, "heartbeat"));
            result.Set("activeViolations", Napi::Number::New(env, activeViolations_.size()));
            result.Set("timestamp", Napi::Number::New(env, std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()));

            jsCallback.Call({result});
        };

        tsfn_.BlockingCall(callback);
    }
}

std::vector<DeviceViolation> SmartDeviceDetector::GetActiveViolations() {
    return activeViolations_;
}

SystemSecurityProfile SmartDeviceDetector::GetSecurityProfile() {
    return securityProfile_;
}

// ==================== WEBCAM DETECTION & ANALYSIS ====================

std::vector<InputDeviceInfo> SmartDeviceDetector::ScanVideoDevices() {
    std::vector<InputDeviceInfo> videoDevices;

#ifdef __APPLE__
    @autoreleasepool {
        io_iterator_t iterator = IO_OBJECT_NULL;
        try {
            // Scan for video devices using AVFoundation approach via IORegistry
            CFMutableDictionaryRef matchDict = IOServiceMatching("IOVideoDevice");
            if (!matchDict) {
                return videoDevices; // Failed to create match dictionary
            }

            kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchDict, &iterator);

            if (kr != KERN_SUCCESS || iterator == IO_OBJECT_NULL) {
                return videoDevices; // Failed to get matching services
            }

            io_object_t service;
            while ((service = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
                InputDeviceInfo device;

                // Get device properties
                device.name = GetIORegistryProperty(service, "device-name");
                if (device.name.empty()) {
                    device.name = GetIORegistryProperty(service, "USB Product Name");
                }
                if (device.name.empty()) {
                    device.name = GetIORegistryProperty(service, "IORegistryEntryName");
                }

                device.manufacturer = GetIORegistryProperty(service, "USB Vendor Name");
                device.vendorId = GetIORegistryProperty(service, "idVendor");
                device.productId = GetIORegistryProperty(service, "idProduct");
                device.type = "video";

                // Generate device ID
                device.deviceId = "video:" + device.vendorId + ":" + device.productId + ":" + device.name;

                // Check if it's built-in or external
                std::string locationId = GetIORegistryProperty(service, "locationID");
                device.isExternal = true;

                // Built-in camera detection patterns
                if (device.name.find("Built-in") != std::string::npos ||
                    device.name.find("FaceTime") != std::string::npos ||
                    device.name.find("iSight") != std::string::npos ||
                    (device.manufacturer.find("Apple") != std::string::npos && !device.isExternal)) {
                    device.isExternal = false;
                }

                // Advanced threat analysis for video devices
                device.isVirtual = IsVirtualCamera(device);
                device.isSpoofed = IsSpoofedDevice(device);
                device.isBluetooth = IsBluetoothDevice(device);
                device.isWireless = IsWirelessDevice(device);

                // Calculate threat level specifically for video devices
                device.threatLevel = CalculateVideoDeviceThreatLevel(device);
                device.threatReason = GetVideoDeviceThreatReason(device);
                device.isAllowed = IsWebcamAllowed(device);

                if (!device.name.empty()) {
                    videoDevices.push_back(device);
                }

                IOObjectRelease(service);
            }

            if (iterator != IO_OBJECT_NULL) {
                IOObjectRelease(iterator);
                iterator = IO_OBJECT_NULL;
            }

            // Also scan USB devices for external webcams
            matchDict = IOServiceMatching("IOUSBDevice");
            if (!matchDict) {
                return videoDevices; // Failed to create match dictionary
            }

            kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchDict, &iterator);
            if (kr == KERN_SUCCESS && iterator != IO_OBJECT_NULL) {
            io_object_t service;

                while ((service = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
                    std::string deviceClass = GetIORegistryProperty(service, "bDeviceClass");
                    std::string productName = GetIORegistryProperty(service, "USB Product Name");

                    // Check if it's a video device (class 14 = Video)
                    if (deviceClass == "14" || deviceClass == "0xe" ||
                        productName.find("Camera") != std::string::npos ||
                        productName.find("Webcam") != std::string::npos ||
                        productName.find("Video") != std::string::npos) {

                        InputDeviceInfo device;
                        device.name = productName;
                        device.manufacturer = GetIORegistryProperty(service, "USB Vendor Name");
                        device.vendorId = GetIORegistryProperty(service, "idVendor");
                        device.productId = GetIORegistryProperty(service, "idProduct");
                        device.type = "video";
                        device.deviceId = "usb-video:" + device.vendorId + ":" + device.productId + ":" + device.name;
                        device.isExternal = true;

                        // Threat analysis
                        device.isVirtual = IsVirtualCamera(device);
                        device.isSpoofed = IsSpoofedDevice(device);
                        device.threatLevel = CalculateVideoDeviceThreatLevel(device);
                        device.threatReason = GetVideoDeviceThreatReason(device);
                        device.isAllowed = IsWebcamAllowed(device);

                        if (!device.name.empty()) {
                            videoDevices.push_back(device);
                        }
                    }

                    IOObjectRelease(service);
                }

                if (iterator != IO_OBJECT_NULL) {
                    IOObjectRelease(iterator);
                }
            }
        } catch (...) {
            // Clean up any resources and return what we have so far
            if (iterator != IO_OBJECT_NULL) {
                IOObjectRelease(iterator);
            }
        }
    }
#endif

    return videoDevices;
}

bool SmartDeviceDetector::IsLegitimateWebcam(const InputDeviceInfo& device) {
    // Known legitimate webcam manufacturers
    std::set<std::string> legitimateManufacturers = {
        "Apple Inc.", "Apple", "Logitech", "Microsoft", "Creative Technology",
        "Razer", "ASUS", "HP", "Dell", "Lenovo", "Sony", "Canon", "Elgato"
    };

    // Check manufacturer
    for (const auto& manufacturer : legitimateManufacturers) {
        if (device.manufacturer.find(manufacturer) != std::string::npos) {
            return true;
        }
    }

    // Check for legitimate product patterns
    if (device.name.find("HD WebCam") != std::string::npos ||
        device.name.find("Pro Webcam") != std::string::npos ||
        device.name.find("FaceTime") != std::string::npos ||
        device.name.find("iSight") != std::string::npos) {
        return true;
    }

    return false;
}

bool SmartDeviceDetector::IsVirtualCamera(const InputDeviceInfo& device) {
    // Virtual camera detection patterns
    std::vector<std::string> virtualPatterns = {
        "Virtual", "Emulated", "Software", "OBS", "Streamlabs",
        "ManyCam", "CamTwist", "Loopback", "Snap Camera", "NVIDIA Broadcast",
        "XSplit", "Wirecast", "mmhmm", "ChromaCam", "YouCam"
    };

    for (const auto& pattern : virtualPatterns) {
        if (device.name.find(pattern) != std::string::npos ||
            device.manufacturer.find(pattern) != std::string::npos) {
            return true;
        }
    }

    return false;
}

bool SmartDeviceDetector::IsWebcamAllowed(const InputDeviceInfo& device) {
    // Critical violations - never allowed
    if (device.isSpoofed || device.threatLevel >= 4) {
        return false;
    }

    // Virtual cameras are highly suspicious in exam environment
    if (device.isVirtual) {
        return false;
    }

    // Bluetooth/wireless webcams are suspicious
    if (device.isBluetooth || device.isWireless) {
        return false;
    }

    // External webcams policy
    if (device.isExternal) {
        // Allow if explicitly permitted and it's a legitimate device
        if (securityProfile_.allowExternalWebcams && IsLegitimateWebcam(device)) {
            return true;
        }
        // Reject if external webcams not allowed
        if (!securityProfile_.allowExternalWebcams) {
            return false;
        }
    }

    // Built-in cameras are always allowed
    if (!device.isExternal) {
        return true;
    }

    // Default to allowing legitimate external webcams
    return IsLegitimateWebcam(device);
}

int SmartDeviceDetector::CalculateVideoDeviceThreatLevel(const InputDeviceInfo& device) {
    int threat = 0;

    // Critical threats
    if (device.isSpoofed) threat = 4;
    if (device.isVirtual) threat = 4;  // Virtual cameras are critical in proctoring

    // High threats
    if (device.isBluetooth) threat = std::max(threat, 3);
    if (device.isWireless) threat = std::max(threat, 3);

    // Medium threats
    if (device.isExternal && !IsLegitimateWebcam(device)) threat = std::max(threat, 2);

    // Low threats
    if (device.isExternal && IsLegitimateWebcam(device)) threat = std::max(threat, 1);

    return threat;
}

std::string SmartDeviceDetector::GetVideoDeviceThreatReason(const InputDeviceInfo& device) {
    std::vector<std::string> reasons;

    if (device.isSpoofed) reasons.push_back("Spoofed video device");
    if (device.isVirtual) reasons.push_back("Virtual camera detected");
    if (device.isBluetooth) reasons.push_back("Bluetooth video device");
    if (device.isWireless) reasons.push_back("Wireless video device");
    if (device.isExternal && !IsLegitimateWebcam(device)) reasons.push_back("Unknown external camera");

    if (reasons.empty()) {
        if (device.isExternal && IsLegitimateWebcam(device)) {
            return "Legitimate external webcam (allowed)";
        }
        return "Built-in camera (safe)";
    }

    std::string result;
    for (size_t i = 0; i < reasons.size(); ++i) {
        result += reasons[i];
        if (i < reasons.size() - 1) result += "; ";
    }

    return result;
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

// macOS-specific network interface detection
bool SmartDeviceDetector::DetectMacOSNetworkInterfaces() {
    bool violationDetected = false;
    
    // Get network interface list using System Configuration framework
    CFArrayRef interfaceArray = SCNetworkInterfaceCopyAll();
    if (interfaceArray == NULL) {
        return false;
    }
    
    CFIndex interfaceCount = CFArrayGetCount(interfaceArray);
    
    for (CFIndex i = 0; i < interfaceCount; i++) {
        SCNetworkInterfaceRef interface = (SCNetworkInterfaceRef)CFArrayGetValueAtIndex(interfaceArray, i);
        if (interface == NULL) continue;
        
        // Get interface type
        CFStringRef interfaceType = SCNetworkInterfaceGetInterfaceType(interface);
        CFStringRef interfaceName = SCNetworkInterfaceGetLocalizedDisplayName(interface);
        CFStringRef bsdName = SCNetworkInterfaceGetBSDName(interface);
        
        if (interfaceType == NULL || interfaceName == NULL) continue;
        
        // Convert CFStrings to std::string
        char interfaceTypeStr[256] = {0};
        char interfaceNameStr[256] = {0};
        char bsdNameStr[256] = {0};
        
        CFStringGetCString(interfaceType, interfaceTypeStr, sizeof(interfaceTypeStr), kCFStringEncodingUTF8);
        CFStringGetCString(interfaceName, interfaceNameStr, sizeof(interfaceNameStr), kCFStringEncodingUTF8);
        if (bsdName) {
            CFStringGetCString(bsdName, bsdNameStr, sizeof(bsdNameStr), kCFStringEncodingUTF8);
        }
        
        std::string typeStr(interfaceTypeStr);
        std::string nameStr(interfaceNameStr);
        std::string bsdStr(bsdNameStr);
        
        bool isWireless = false;
        bool isSuspicious = false;
        std::string reason;
        
        // Check for wireless interfaces
        if (CFStringCompare(interfaceType, kSCNetworkInterfaceTypeIEEE80211, 0) == kCFCompareEqualTo) {
            isWireless = true;
        }
        
        // Convert to lowercase for pattern matching
        std::string nameLower = nameStr;
        std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);
        
        std::string typeLower = typeStr;
        std::transform(typeLower.begin(), typeLower.end(), typeLower.begin(), ::tolower);
        
        // Check for hotspot/tethering indicators
        if (nameLower.find("hotspot") != std::string::npos ||
            nameLower.find("personal hotspot") != std::string::npos ||
            nameLower.find("tethering") != std::string::npos ||
            nameLower.find("internet sharing") != std::string::npos ||
            nameLower.find("bridge") != std::string::npos ||
            nameLower.find("nat") != std::string::npos) {
            isSuspicious = true;
            reason = "Personal hotspot or internet sharing detected";
        }
        
        // Check for USB tethering (iPhone/Android)
        if (CFStringCompare(interfaceType, kSCNetworkInterfaceTypeWWAN, 0) == kCFCompareEqualTo ||
            (nameLower.find("iphone") != std::string::npos) ||
            (nameLower.find("android") != std::string::npos) ||
            (nameLower.find("usb") != std::string::npos && nameLower.find("modem") != std::string::npos)) {
            isSuspicious = true;
            reason = "USB tethering or cellular modem detected";
        }
        
        // Check for Bluetooth PAN (Personal Area Network)
        if (CFStringCompare(interfaceType, kSCNetworkInterfaceTypeBluetooth, 0) == kCFCompareEqualTo) {
            isSuspicious = true;
            reason = "Bluetooth network interface detected";
        }
        
        // Check for virtual interfaces that might indicate VM networking
        if (nameLower.find("vmware") != std::string::npos ||
            nameLower.find("virtualbox") != std::string::npos ||
            nameLower.find("parallels") != std::string::npos ||
            nameLower.find("docker") != std::string::npos ||
            nameLower.find("vnic") != std::string::npos ||
            bsdStr.find("vmnet") == 0 ||
            bsdStr.find("vboxnet") == 0) {
            isSuspicious = true;
            reason = "Virtual network interface detected - potential VM or container networking";
        }
        
        // Flag wireless in strict mode
        if (!securityProfile_.allowWireless && isWireless && !isSuspicious) {
            isSuspicious = true;
            reason = "Wireless network interface detected in strict mode";
        }
        
        if (isSuspicious) {
            DeviceViolation violation;
            violation.deviceId = "NET_" + bsdStr;
            violation.deviceName = nameStr;
            violation.violationType = "network-interface";
            violation.severity = isWireless ? 2 : 3; // MEDIUM for wireless, HIGH for tethering/hotspot
            violation.reason = reason;
            violation.evidence = "Interface: " + nameStr + ", Type: " + typeStr + ", BSD Name: " + bsdStr;
            violation.persistent = true;
            
            activeViolations_.push_back(violation);
            EmitViolation(violation);
            violationDetected = true;
        }
    }
    
    CFRelease(interfaceArray);
    
    // Additional check for suspicious IP configurations
    // Check for common hotspot IP ranges using ifconfig-like approach
    CFArrayRef serviceArray = SCNetworkServiceCopyAll(SCPreferencesCreate(NULL, CFSTR("SmartDeviceDetector"), NULL));
    if (serviceArray != NULL) {
        CFIndex serviceCount = CFArrayGetCount(serviceArray);
        
        for (CFIndex i = 0; i < serviceCount; i++) {
            SCNetworkServiceRef service = (SCNetworkServiceRef)CFArrayGetValueAtIndex(serviceArray, i);
            if (!SCNetworkServiceGetEnabled(service)) continue;
            
            SCNetworkProtocolRef protocol = SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeIPv4);
            if (protocol == NULL) continue;
            
            CFDictionaryRef configuration = SCNetworkProtocolGetConfiguration(protocol);
            if (configuration == NULL) {
                CFRelease(protocol);
                continue;
            }
            
            CFArrayRef addresses = (CFArrayRef)CFDictionaryGetValue(configuration, kSCPropNetIPv4Addresses);
            if (addresses != NULL) {
                CFIndex addressCount = CFArrayGetCount(addresses);
                for (CFIndex j = 0; j < addressCount; j++) {
                    CFStringRef address = (CFStringRef)CFArrayGetValueAtIndex(addresses, j);
                    char addressStr[256] = {0};
                    CFStringGetCString(address, addressStr, sizeof(addressStr), kCFStringEncodingUTF8);
                    
                    std::string ipAddress(addressStr);
                    
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
            
            CFRelease(protocol);
        }
        CFRelease(serviceArray);
    }
    
    return violationDetected;
}

// macOS-specific mobile device detection
bool SmartDeviceDetector::DetectMacOSMobileDevices() {
    bool violationDetected = false;
    
    // USB device detection using IOKit
    CFMutableDictionaryRef matchingDict = IOServiceMatching(kIOUSBDeviceClassName);
    if (matchingDict == NULL) {
        return false;
    }
    
    io_iterator_t iter;
    kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iter);
    if (kr != KERN_SUCCESS) {
        return false;
    }
    
    io_service_t usbDevice;
    while ((usbDevice = IOIteratorNext(iter))) {
        CFMutableDictionaryRef properties;
        kr = IORegistryEntryCreateCFProperties(usbDevice, &properties, kCFAllocatorDefault, kNilOptions);
        
        if (kr == KERN_SUCCESS && properties != NULL) {
            // Get vendor ID and product ID
            CFNumberRef vendorIDRef = (CFNumberRef)CFDictionaryGetValue(properties, CFSTR(kUSBVendorID));
            CFNumberRef productIDRef = (CFNumberRef)CFDictionaryGetValue(properties, CFSTR(kUSBProductID));
            
            uint16_t vendorID = 0, productID = 0;
            if (vendorIDRef) {
                CFNumberGetValue(vendorIDRef, kCFNumberShortType, &vendorID);
            }
            if (productIDRef) {
                CFNumberGetValue(productIDRef, kCFNumberShortType, &productID);
            }
            
            // Get device name
            CFStringRef deviceNameRef = (CFStringRef)CFDictionaryGetValue(properties, CFSTR(kUSBProductString));
            std::string deviceName = "Unknown USB Device";
            if (deviceNameRef) {
                char deviceNameStr[256] = {0};
                CFStringGetCString(deviceNameRef, deviceNameStr, sizeof(deviceNameStr), kCFStringEncodingUTF8);
                deviceName = std::string(deviceNameStr);
            }
            
            // Get manufacturer
            CFStringRef manufacturerRef = (CFStringRef)CFDictionaryGetValue(properties, CFSTR(kUSBVendorString));
            std::string manufacturer = "Unknown";
            if (manufacturerRef) {
                char manufacturerStr[256] = {0};
                CFStringGetCString(manufacturerRef, manufacturerStr, sizeof(manufacturerStr), kCFStringEncodingUTF8);
                manufacturer = std::string(manufacturerStr);
            }
            
            // Convert to lowercase for pattern matching
            std::string deviceNameLower = deviceName;
            std::transform(deviceNameLower.begin(), deviceNameLower.end(), deviceNameLower.begin(), ::tolower);
            
            std::string manufacturerLower = manufacturer;
            std::transform(manufacturerLower.begin(), manufacturerLower.end(), manufacturerLower.begin(), ::tolower);
            
            bool isMobileDevice = false;
            std::string reason;
            int severity = 3; // HIGH by default
            
            // Check for Apple mobile devices (iPhone, iPad)
            if (vendorID == 0x05AC) { // Apple vendor ID
                if ((productID >= 0x1290 && productID <= 0x12AB) ||  // iPhone range
                    (productID >= 0x1460 && productID <= 0x1490) ||  // iPad range
                    deviceNameLower.find("iphone") != std::string::npos ||
                    deviceNameLower.find("ipad") != std::string::npos) {
                    isMobileDevice = true;
                    reason = "Apple mobile device (iPhone/iPad) detected";
                }
            }
            
            // Check for Android devices by vendor ID
            else if (vendorID == 0x18D1 ||  // Google
                     vendorID == 0x04E8 ||  // Samsung
                     vendorID == 0x0BB4 ||  // HTC
                     vendorID == 0x22B8 ||  // Motorola
                     vendorID == 0x1004 ||  // LG
                     vendorID == 0x2717 ||  // Xiaomi
                     vendorID == 0x2A70) {  // OnePlus
                isMobileDevice = true;
                reason = "Android mobile device detected via vendor ID";
            }
            
            // Check by device name patterns
            else if (deviceNameLower.find("android") != std::string::npos ||
                     deviceNameLower.find("samsung") != std::string::npos ||
                     deviceNameLower.find("lg mobile") != std::string::npos ||
                     deviceNameLower.find("htc") != std::string::npos ||
                     deviceNameLower.find("motorola") != std::string::npos ||
                     deviceNameLower.find("oneplus") != std::string::npos ||
                     deviceNameLower.find("pixel") != std::string::npos ||
                     deviceNameLower.find("nexus") != std::string::npos ||
                     deviceNameLower.find("galaxy") != std::string::npos) {
                isMobileDevice = true;
                reason = "Mobile device detected via device name";
            }
            
            // Check for tablet devices
            else if (deviceNameLower.find("tablet") != std::string::npos ||
                     deviceNameLower.find("surface") != std::string::npos) {
                isMobileDevice = true;
                reason = "Tablet device detected";
            }
            
            // Check for ADB (Android Debug Bridge) interfaces
            else if (deviceNameLower.find("adb") != std::string::npos ||
                     deviceNameLower.find("android debug") != std::string::npos ||
                     deviceNameLower.find("fastboot") != std::string::npos) {
                isMobileDevice = true;
                reason = "Android debugging interface detected";
                severity = 4; // CRITICAL for development tools
            }
            
            if (isMobileDevice) {
                char deviceIdStr[32];
                snprintf(deviceIdStr, sizeof(deviceIdStr), "USB_%04X_%04X", vendorID, productID);
                
                DeviceViolation violation;
                violation.deviceId = std::string(deviceIdStr);
                violation.deviceName = deviceName;
                violation.violationType = "mobile-device";
                violation.severity = severity;
                violation.reason = reason;
                violation.evidence = "Device: " + deviceName + ", Manufacturer: " + manufacturer + 
                                   ", VID: " + std::to_string(vendorID) + ", PID: " + std::to_string(productID);
                violation.persistent = true;
                
                activeViolations_.push_back(violation);
                EmitViolation(violation);
                violationDetected = true;
            }
            
            CFRelease(properties);
        }
        
        IOObjectRelease(usbDevice);
    }
    
    IOObjectRelease(iter);
    
    // Check for Bluetooth mobile devices
    CFMutableDictionaryRef bluetoothMatchingDict = IOServiceMatching("IOBluetoothDevice");
    if (bluetoothMatchingDict != NULL) {
        io_iterator_t bluetoothIter;
        kr = IOServiceGetMatchingServices(kIOMasterPortDefault, bluetoothMatchingDict, &bluetoothIter);
        
        if (kr == KERN_SUCCESS) {
            io_service_t bluetoothDevice;
            while ((bluetoothDevice = IOIteratorNext(bluetoothIter))) {
                std::string deviceName = GetIORegistryProperty(bluetoothDevice, "Name");
                std::string deviceAddress = GetIORegistryProperty(bluetoothDevice, "Address");
                
                if (!deviceName.empty()) {
                    std::string deviceNameLower = deviceName;
                    std::transform(deviceNameLower.begin(), deviceNameLower.end(), deviceNameLower.begin(), ::tolower);
                    
                    bool isMobileDevice = false;
                    std::string reason;
                    
                    // Check for mobile device patterns in Bluetooth device names
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
                        violation.deviceId = "BT_" + deviceAddress;
                        violation.deviceName = deviceName;
                        violation.violationType = "mobile-device-bluetooth";
                        violation.severity = 3; // HIGH
                        violation.reason = reason;
                        violation.evidence = "Bluetooth device: " + deviceName + ", Address: " + deviceAddress;
                        violation.persistent = true;
                        
                        activeViolations_.push_back(violation);
                        EmitViolation(violation);
                        violationDetected = true;
                    }
                }
                
                IOObjectRelease(bluetoothDevice);
            }
            
            IOObjectRelease(bluetoothIter);
        }
    }
    
    return violationDetected;
}

// macOS-specific Bluetooth device detection (ALL Bluetooth devices)

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

    @autoreleasepool {
        NSArray* pairedDevices = [IOBluetoothDevice pairedDevices];
        if (pairedDevices != nil) {
            for (IOBluetoothDevice* device in pairedDevices) {
                NSString* name = [device name];
                if (name != nil) {
                    std::string deviceName = std::string([name UTF8String]);
                    std::string deviceNameLower = deviceName;
                    std::transform(deviceNameLower.begin(), deviceNameLower.end(), deviceNameLower.begin(), ::tolower);

                    if (deviceNameLower.find("mouse") != std::string::npos) {
                        count++;
                    }
                }
            }
        }
    }

    return count;
}

int SmartDeviceDetector::CountBluetoothKeyboards() {
    int count = 0;

    @autoreleasepool {
        NSArray* pairedDevices = [IOBluetoothDevice pairedDevices];
        if (pairedDevices != nil) {
            for (IOBluetoothDevice* device in pairedDevices) {
                NSString* name = [device name];
                if (name != nil) {
                    std::string deviceName = std::string([name UTF8String]);
                    std::string deviceNameLower = deviceName;
                    std::transform(deviceNameLower.begin(), deviceNameLower.end(), deviceNameLower.begin(), ::tolower);

                    if (deviceNameLower.find("keyboard") != std::string::npos || deviceNameLower.find("magic") != std::string::npos) {
                        count++;
                    }
                }
            }
        }
    }

    return count;
}

bool SmartDeviceDetector::DetectNonInputBluetoothDevices() {
    bool violationDetected = false;

    @autoreleasepool {
        // Check if Bluetooth is enabled using IOBluetooth framework
        IOBluetoothHostController* controller = [IOBluetoothHostController defaultController];
        if (controller == nil) {
            return false; // No Bluetooth controller available
        }

        BluetoothHCIPowerState powerState = [controller powerState];
        bool bluetoothEnabled = (powerState == kBluetoothHCIPowerStateON);

        if (bluetoothEnabled) {
            // Get paired/connected devices using IOBluetooth
            NSArray* pairedDevices = [IOBluetoothDevice pairedDevices];
            if (pairedDevices != nil) {
                for (IOBluetoothDevice* device in pairedDevices) {
                    // Get device name
                    NSString* name = [device name];
                    std::string deviceName = (name != nil) ? std::string([name UTF8String]) : "Unknown Device";

                    // Get device address
                    NSString* address = [device addressString];
                    std::string deviceAddress = (address != nil) ? std::string([address UTF8String]) : "Unknown Address";

                    // Skip input devices (mouse/keyboard) as they're handled by business logic
                    std::string deviceNameLower = deviceName;
                    std::transform(deviceNameLower.begin(), deviceNameLower.end(), deviceNameLower.begin(), ::tolower);

                    if (deviceNameLower.find("mouse") != std::string::npos ||
                        deviceNameLower.find("keyboard") != std::string::npos ||
                        deviceNameLower.find("trackpad") != std::string::npos ||
                        deviceNameLower.find("magic") != std::string::npos) {
                        continue;
                    }

                    // Only process devices with valid names and addresses
                    if (!deviceName.empty() && deviceName != "Unknown Device" &&
                        !deviceAddress.empty() && deviceAddress != "Unknown Address") {

                        // Check if device is connected
                        bool isConnected = [device isConnected];

                        // Determine device type and severity
                        int severity = 2; // MEDIUM by default
                        std::string deviceType = "Unknown Bluetooth Device";
                        std::string reason = "Non-input Bluetooth device detected in strict mode";

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
                                 deviceNameLower.find("band") != std::string::npos ||
                                 deviceNameLower.find("apple watch") != std::string::npos) {
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
                                           (isConnected ? "Yes" : "No");
                        violation.persistent = true;

                        activeViolations_.push_back(violation);
                        EmitViolation(violation);
                        violationDetected = true;
                    }
                }
            }
        }
    }

    return violationDetected;
}

// macOS-specific Bluetooth device detection using IOBluetooth APIs (from BluetoothWatcher)
bool SmartDeviceDetector::DetectMacOSBluetoothDevices() {
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

    @autoreleasepool {
        // Check if Bluetooth is enabled using IOBluetooth framework
        IOBluetoothHostController* controller = [IOBluetoothHostController defaultController];
        if (controller == nil) {
            return false; // No Bluetooth controller available
        }

        BluetoothHCIPowerState powerState = [controller powerState];
        bool bluetoothEnabled = (powerState == kBluetoothHCIPowerStateON);

        if (bluetoothEnabled) {
            // Bluetooth adapter is enabled - this itself is a violation in strict mode
            DeviceViolation adapterViolation;
            adapterViolation.deviceId = "BT_ADAPTER_ENABLED";
            adapterViolation.deviceName = "Bluetooth Adapter";
            adapterViolation.violationType = "bluetooth-adapter";
            adapterViolation.severity = 2; // MEDIUM
            adapterViolation.reason = "Bluetooth adapter enabled in strict mode";
            adapterViolation.evidence = "Bluetooth controller detected and enabled";
            adapterViolation.persistent = true;

            activeViolations_.push_back(adapterViolation);
            EmitViolation(adapterViolation);
            violationDetected = true;

            // Get paired/connected devices using IOBluetooth
            NSArray* pairedDevices = [IOBluetoothDevice pairedDevices];
            if (pairedDevices != nil) {
                for (IOBluetoothDevice* device in pairedDevices) {
                    // Get device name
                    NSString* name = [device name];
                    std::string deviceName = (name != nil) ? std::string([name UTF8String]) : "Unknown Device";

                    // Get device address
                    NSString* address = [device addressString];
                    std::string deviceAddress = (address != nil) ? std::string([address UTF8String]) : "Unknown Address";

                    // Check if device is connected
                    bool isConnected = [device isConnected];

                    // Only process devices with valid names and addresses
                    if (!deviceName.empty() && deviceName != "Unknown Device" &&
                        !deviceAddress.empty() && deviceAddress != "Unknown Address") {

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
                                 deviceNameLower.find("trackpad") != std::string::npos ||
                                 deviceNameLower.find("magic") != std::string::npos) {
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
                                    bool isKeyboard = deviceNameLower.find("keyboard") != std::string::npos || deviceNameLower.find("magic") != std::string::npos;

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
                                 deviceNameLower.find("band") != std::string::npos ||
                                 deviceNameLower.find("apple watch") != std::string::npos) {
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
                                           (isConnected ? "Yes" : "No");
                        violation.persistent = true;

                        activeViolations_.push_back(violation);
                        EmitViolation(violation);
                        violationDetected = true;
                    }
                }
            }
        }
    }

    return violationDetected;
}

std::vector<StorageDeviceInfo> SmartDeviceDetector::ScanMacOSStorageDevices() {
    std::vector<StorageDeviceInfo> devices;
    @autoreleasepool {
        try {
            // Scan storage devices using IOKit
            CFMutableDictionaryRef matchDict = IOServiceMatching("IOMedia");
            if (matchDict == NULL) {
                std::cerr << "[SmartDeviceDetector] Failed to create IOMedia matching dictionary" << std::endl;
                return devices;
            }

            io_iterator_t iterator;
            kern_return_t result = IOServiceGetMatchingServices(kIOMasterPortDefault, matchDict, &iterator);

            if (result == KERN_SUCCESS) {
                io_object_t service;

                while ((service = IOIteratorNext(iterator))) {
                    try {
                        // Get device properties
                        std::string deviceName = GetIORegistryProperty(service, "Name");
                        std::string deviceType = GetIORegistryProperty(service, "Content");
                        std::string bsdName = GetIORegistryProperty(service, "BSD Name");
                        std::string size = GetIORegistryProperty(service, "Size");
                        std::string removable = GetIORegistryProperty(service, "Removable");

                        // Skip empty or invalid entries
                        if (deviceName.empty() && bsdName.empty()) {
                            IOObjectRelease(service);
                            continue;
                        }

                        // Create storage device info
                        std::string name = deviceName.empty() ? bsdName : deviceName;
                        std::string type = deviceType.empty() ? "storage" : deviceType;
                        std::string path = bsdName.empty() ? "" : "/dev/" + bsdName;

                        StorageDeviceInfo device(bsdName, type, name, path);

                        // Determine if external (removable media)
                        device.isExternal = (removable == "1" || removable == "true" ||
                                           deviceName.find("USB") != std::string::npos ||
                                           deviceName.find("External") != std::string::npos);

                        // Only add valid storage devices
                        if (!device.name.empty() && !device.id.empty()) {
                            devices.push_back(device);
                        }

                    } catch (const std::exception& e) {
                        std::cerr << "[SmartDeviceDetector] Error processing storage device: " << e.what() << std::endl;
                    }

                    IOObjectRelease(service);
                }

                IOObjectRelease(iterator);
            } else {
                std::cerr << "[SmartDeviceDetector] Failed to get IOMedia services: " << result << std::endl;
            }

        } catch (const std::exception& e) {
            std::cerr << "[SmartDeviceDetector] Exception in ScanMacOSStorageDevices: " << e.what() << std::endl;
        }
    }

    return devices;
}


std::vector<StorageDeviceInfo> SmartDeviceDetector::ScanAllStorageDevices() {
    return ScanMacOSStorageDevices();
}

bool SmartDeviceDetector::DetectNetworkInterfaces() {
    return DetectMacOSNetworkInterfaces();
}

bool SmartDeviceDetector::DetectMobileDevices() {
    return DetectMacOSMobileDevices();
}

bool SmartDeviceDetector::DetectBluetoothSpoofers() {
    return DetectMacOSBluetoothDevices();
}

bool SmartDeviceDetector::DetectVirtualDevices() {
    return DetectMacOSVirtualDevices();
}
