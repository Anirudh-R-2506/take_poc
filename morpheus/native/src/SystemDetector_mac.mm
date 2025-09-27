#include "SystemDetector.h"
#include <sstream>
#include <vector>

#ifdef __APPLE__
#import <Foundation/Foundation.h>
#import <IOKit/ps/IOPowerSources.h>
#import <IOKit/ps/IOPSKeys.h>
#endif

SystemDetector::SystemDetector() : detectionCached_(false) {
}

SystemDetector::~SystemDetector() {
}

SystemInfo SystemDetector::DetectSystemType() {
    if (detectionCached_) {
        return lastDetection_;
    }

    SystemInfo info;

#ifdef __APPLE__
    info.type = DetectMacOSSystemType();
    info.hasBattery = DetectMacOSBattery();

    // Get system model
    info.model = GetIORegistryProperty("IOPlatformExpertDevice", "model");
    info.manufacturer = "Apple Inc.";

    // Determine portability based on model and battery
    if (info.model.find("MacBook") != std::string::npos ||
        info.model.find("iMac") == std::string::npos) {
        info.isPortable = true;
        info.hasLid = true;
    }

    // Override type detection based on model for accuracy
    if (info.model.find("MacBook") != std::string::npos) {
        info.type = SystemType::LAPTOP;
        info.chassisType = "Laptop";
    } else if (info.model.find("iMac") != std::string::npos ||
               info.model.find("Mac Pro") != std::string::npos ||
               info.model.find("Mac Studio") != std::string::npos) {
        info.type = SystemType::DESKTOP;
        info.chassisType = "Desktop";
    } else if (info.model.find("Mac mini") != std::string::npos) {
        info.type = SystemType::DESKTOP;
        info.chassisType = "Mini Desktop";
    }

#elif _WIN32
    info.type = DetectWindowsSystemType();
    info.hasBattery = DetectWindowsBattery();
    info.manufacturer = QueryWMI("Win32_ComputerSystem", "Manufacturer");
    info.model = QueryWMI("Win32_ComputerSystem", "Model");
    info.chassisType = QueryWMI("Win32_SystemEnclosure", "ChassisTypes");
#endif

    lastDetection_ = info;
    detectionCached_ = true;
    return info;
}

bool SystemDetector::IsLaptop() {
    SystemInfo info = DetectSystemType();
    return info.type == SystemType::LAPTOP;
}

bool SystemDetector::IsDesktop() {
    SystemInfo info = DetectSystemType();
    return info.type == SystemType::DESKTOP;
}

bool SystemDetector::HasInternalBattery() {
    SystemInfo info = DetectSystemType();
    return info.hasBattery;
}

std::string SystemDetector::GetChassisType() {
    SystemInfo info = DetectSystemType();
    return info.chassisType;
}

#ifdef __APPLE__
std::string SystemDetector::GetIORegistryProperty(const std::string& serviceName, const std::string& property) {
    @autoreleasepool {
        io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                          IOServiceMatching(serviceName.c_str()));
        if (service == 0) {
            return "";
        }

        CFStringRef key = CFStringCreateWithCString(kCFAllocatorDefault, property.c_str(), kCFStringEncodingUTF8);
        CFTypeRef value = IORegistryEntryCreateCFProperty(service, key, kCFAllocatorDefault, 0);
        IOObjectRelease(service);
        CFRelease(key);

        if (value == nullptr) {
            return "";
        }

        std::string result;
        if (CFGetTypeID(value) == CFStringGetTypeID()) {
            CFStringRef stringValue = (CFStringRef)value;
            char buffer[256];
            if (CFStringGetCString(stringValue, buffer, sizeof(buffer), kCFStringEncodingUTF8)) {
                result = buffer;
            }
        } else if (CFGetTypeID(value) == CFDataGetTypeID()) {
            CFDataRef dataValue = (CFDataRef)value;
            const char* bytes = (const char*)CFDataGetBytePtr(dataValue);
            CFIndex length = CFDataGetLength(dataValue);
            if (bytes && length > 0) {
                result = std::string(bytes, length);
                // Remove null terminators for clean string
                size_t nullPos = result.find('\0');
                if (nullPos != std::string::npos) {
                    result = result.substr(0, nullPos);
                }
            }
        }

        CFRelease(value);
        return result;
    }
}

SystemType SystemDetector::DetectMacOSSystemType() {
    @autoreleasepool {
        // Get model identifier
        size_t size = 0;
        sysctlbyname("hw.model", nullptr, &size, nullptr, 0);

        if (size == 0) {
            return SystemType::UNKNOWN;
        }

        std::vector<char> model(size);
        sysctlbyname("hw.model", model.data(), &size, nullptr, 0);
        std::string modelStr(model.data());

        // Classify based on model identifier
        if (modelStr.find("MacBook") != std::string::npos) {
            return SystemType::LAPTOP;
        } else if (modelStr.find("iMac") != std::string::npos ||
                   modelStr.find("MacPro") != std::string::npos ||
                   modelStr.find("MacStudio") != std::string::npos ||
                   modelStr.find("Macmini") != std::string::npos) {
            return SystemType::DESKTOP;
        }

        // Fallback: check for battery presence
        if (DetectMacOSBattery()) {
            return SystemType::LAPTOP;
        }

        return SystemType::DESKTOP;
    }
}

bool SystemDetector::DetectMacOSBattery() {
    @autoreleasepool {
        CFTypeRef powerSourcesInfo = IOPSCopyPowerSourcesInfo();
        if (powerSourcesInfo == nullptr) {
            return false;
        }

        CFArrayRef powerSources = IOPSCopyPowerSourcesList(powerSourcesInfo);
        if (powerSources == nullptr) {
            CFRelease(powerSourcesInfo);
            return false;
        }

        bool hasBattery = false;
        CFIndex count = CFArrayGetCount(powerSources);

        for (CFIndex i = 0; i < count; i++) {
            CFTypeRef powerSource = CFArrayGetValueAtIndex(powerSources, i);
            CFDictionaryRef description = IOPSGetPowerSourceDescription(powerSourcesInfo, powerSource);

            if (description != nullptr) {
                CFStringRef type = (CFStringRef)CFDictionaryGetValue(description, CFSTR(kIOPSTypeKey));
                if (type != nullptr && CFStringCompare(type, CFSTR(kIOPSInternalBatteryType), 0) == kCFCompareEqualTo) {
                    hasBattery = true;
                    break;
                }
            }
        }

        CFRelease(powerSources);
        CFRelease(powerSourcesInfo);
        return hasBattery;
    }
}

#endif