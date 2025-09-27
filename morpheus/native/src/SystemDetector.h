#ifndef SYSTEM_DETECTOR_H
#define SYSTEM_DETECTOR_H

#include <napi.h>
#include <string>

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
#include <intrin.h>
#elif __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#endif

enum class SystemType {
    UNKNOWN = 0,
    DESKTOP = 1,
    LAPTOP = 2,
    TABLET = 3,
    SERVER = 4
};

struct SystemInfo {
    SystemType type;
    std::string manufacturer;
    std::string model;
    std::string serialNumber;
    bool hasBattery;
    bool hasLid;
    bool isPortable;
    std::string chassisType;

    SystemInfo() : type(SystemType::UNKNOWN), hasBattery(false), hasLid(false), isPortable(false) {}
};

class SystemDetector {
public:
    SystemDetector();
    ~SystemDetector();

    SystemInfo DetectSystemType();
    bool IsLaptop();
    bool IsDesktop();
    bool HasInternalBattery();
    std::string GetChassisType();

private:
#ifdef _WIN32
    std::string QueryWMI(const std::string& wmiClass, const std::string& property);
    SystemType DetectWindowsSystemType();
    bool DetectWindowsBattery();
    std::string GetWindowsChassisType();
#elif __APPLE__
    std::string GetIORegistryProperty(const std::string& serviceName, const std::string& property);
    SystemType DetectMacOSSystemType();
    bool DetectMacOSBattery();
#endif

    SystemInfo lastDetection_;
    bool detectionCached_;
};

#endif // SYSTEM_DETECTOR_H