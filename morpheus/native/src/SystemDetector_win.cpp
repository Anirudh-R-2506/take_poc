#include "SystemDetector.h"
#include <comdef.h>
#include <Wbemidl.h>
#include <oleauto.h>

#ifdef _WIN32
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "kernel32.lib")
#endif

SystemDetector::SystemDetector() : detectionCached_(false)
{
}

SystemDetector::~SystemDetector()
{
}

SystemInfo SystemDetector::DetectSystemType()
{
    if (detectionCached_)
    {
        return lastDetection_;
    }

    SystemInfo info;

#ifdef _WIN32
    info.type = DetectWindowsSystemType();
    info.hasBattery = DetectWindowsBattery();
    info.manufacturer = QueryWMI("Win32_ComputerSystem", "Manufacturer");
    info.model = QueryWMI("Win32_ComputerSystem", "Model");
    info.chassisType = GetWindowsChassisType();

    // Determine portability
    if (info.hasBattery || info.chassisType.find("Laptop") != std::string::npos ||
        info.chassisType.find("Notebook") != std::string::npos ||
        info.chassisType.find("Portable") != std::string::npos)
    {
        info.isPortable = true;
        info.hasLid = true;
    }

#elif __APPLE__
    info.type = DetectMacOSSystemType();
    info.hasBattery = DetectMacOSBattery();
    info.manufacturer = "Apple Inc.";

    size_t size = 0;
    sysctlbyname("hw.model", nullptr, &size, nullptr, 0);
    if (size > 0)
    {
        std::vector<char> model(size);
        sysctlbyname("hw.model", model.data(), &size, nullptr, 0);
        info.model = std::string(model.data());
    }

    if (info.model.find("MacBook") != std::string::npos)
    {
        info.type = SystemType::LAPTOP;
        info.chassisType = "Laptop";
        info.isPortable = true;
        info.hasLid = true;
    }
    else
    {
        info.type = SystemType::DESKTOP;
        info.chassisType = "Desktop";
    }
#endif

    lastDetection_ = info;
    detectionCached_ = true;
    return info;
}

bool SystemDetector::IsLaptop()
{
    SystemInfo info = DetectSystemType();
    return info.type == SystemType::LAPTOP;
}

bool SystemDetector::IsDesktop()
{
    SystemInfo info = DetectSystemType();
    return info.type == SystemType::DESKTOP;
}

bool SystemDetector::HasInternalBattery()
{
    SystemInfo info = DetectSystemType();
    return info.hasBattery;
}

std::string SystemDetector::GetChassisType()
{
    SystemInfo info = DetectSystemType();
    return info.chassisType;
}

#ifdef _WIN32
std::string SystemDetector::QueryWMI(const std::string &wmiClass, const std::string &property)
{
    std::string result;

    // Initialize COM
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr))
        return result;

    // Initialize WMI
    IWbemLocator *pLoc = nullptr;
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *)&pLoc);

    if (SUCCEEDED(hr))
    {
        IWbemServices *pSvc = nullptr;
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr, 0, NULL, 0, 0, &pSvc);

        if (SUCCEEDED(hr))
        {
            CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                              RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

            // Build WQL query
            std::wstring query = L"SELECT " + std::wstring(property.begin(), property.end()) +
                                 L" FROM " + std::wstring(wmiClass.begin(), wmiClass.end());

            IEnumWbemClassObject *pEnumerator = nullptr;
            hr = pSvc->ExecQuery(bstr_t("WQL"), bstr_t(query.c_str()),
                                 WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &pEnumerator);

            if (SUCCEEDED(hr))
            {
                IWbemClassObject *pclsObj = nullptr;
                ULONG uReturn = 0;

                hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                if (uReturn != 0)
                {
                    VARIANT vtProp;
                    VariantInit(&vtProp);

                    std::wstring propName(property.begin(), property.end());
                    hr = pclsObj->Get(propName.c_str(), 0, &vtProp, 0, 0);
                    if (SUCCEEDED(hr))
                    {
                        if (vtProp.vt == VT_BSTR && vtProp.bstrVal)
                        {
                            int len = WideCharToMultiByte(CP_UTF8, 0, vtProp.bstrVal, -1, nullptr, 0, nullptr, nullptr);
                            if (len > 0)
                            {
                                result.resize(len - 1);
                                WideCharToMultiByte(CP_UTF8, 0, vtProp.bstrVal, -1, &result[0], len, nullptr, nullptr);
                            }
                        }
                        else if (vtProp.vt == VT_I4)
                        {
                            result = std::to_string(vtProp.intVal);
                        }
                    }
                    VariantClear(&vtProp);
                    pclsObj->Release();
                }

                pEnumerator->Release();
            }

            pSvc->Release();
        }

        pLoc->Release();
    }

    CoUninitialize();
    return result;
}

SystemType SystemDetector::DetectWindowsSystemType()
{
    // Get chassis type from WMI
    std::string chassisTypes = QueryWMI("Win32_SystemEnclosure", "ChassisTypes");

    if (!chassisTypes.empty())
    {
        int chassisType = std::stoi(chassisTypes);

        // Windows chassis type values:
        // 8, 9, 10, 14 = Laptop/Portable
        // 3, 4, 5, 6, 7, 15, 16 = Desktop
        // 17, 23 = Server
        // 11, 12, 21, 30, 31, 32 = Handheld/Tablet

        switch (chassisType)
        {
        case 8:  // Portable
        case 9:  // Laptop
        case 10: // Notebook
        case 14: // Sub Notebook
            return SystemType::LAPTOP;

        case 3:  // Desktop
        case 4:  // Low Profile Desktop
        case 5:  // Pizza Box
        case 6:  // Mini Tower
        case 7:  // Tower
        case 15: // Space-saving
        case 16: // Lunch Box
            return SystemType::DESKTOP;

        case 17: // Main Server Chassis
        case 23: // Rack Mount Chassis
            return SystemType::SERVER;

        case 11: // Hand Held
        case 12: // Docking Station
        case 21: // Peripheral Chassis
        case 30: // Tablet
        case 31: // Convertible
        case 32: // Detachable
            return SystemType::TABLET;
        }
    }

    // Fallback: Check for battery presence
    if (DetectWindowsBattery())
    {
        return SystemType::LAPTOP;
    }

    return SystemType::DESKTOP;
}

bool SystemDetector::DetectWindowsBattery()
{
    // Use GetSystemPowerStatus for quick battery check
    SYSTEM_POWER_STATUS powerStatus;
    if (GetSystemPowerStatus(&powerStatus))
    {
        // If battery flag indicates no system battery (128) or unknown (255), no battery
        if (powerStatus.BatteryFlag == 128 || powerStatus.BatteryFlag == 255)
        {
            return false;
        }
        // Any other value indicates battery presence
        return true;
    }

    // Fallback: Use WMI to check for battery devices
    std::string batteryStatus = QueryWMI("Win32_Battery", "Status");
    return !batteryStatus.empty();
}

std::string SystemDetector::GetWindowsChassisType()
{
    std::string chassisTypes = QueryWMI("Win32_SystemEnclosure", "ChassisTypes");

    if (!chassisTypes.empty())
    {
        int chassisType = std::stoi(chassisTypes);

        switch (chassisType)
        {
        case 1:
            return "Other";
        case 2:
            return "Unknown";
        case 3:
            return "Desktop";
        case 4:
            return "Low Profile Desktop";
        case 5:
            return "Pizza Box";
        case 6:
            return "Mini Tower";
        case 7:
            return "Tower";
        case 8:
            return "Portable";
        case 9:
            return "Laptop";
        case 10:
            return "Notebook";
        case 11:
            return "Hand Held";
        case 12:
            return "Docking Station";
        case 13:
            return "All in One";
        case 14:
            return "Sub Notebook";
        case 15:
            return "Space-saving";
        case 16:
            return "Lunch Box";
        case 17:
            return "Main Server Chassis";
        case 18:
            return "Expansion Chassis";
        case 19:
            return "SubChassis";
        case 20:
            return "Bus Expansion Chassis";
        case 21:
            return "Peripheral Chassis";
        case 22:
            return "RAID Chassis";
        case 23:
            return "Rack Mount Chassis";
        case 24:
            return "Sealed-case PC";
        case 30:
            return "Tablet";
        case 31:
            return "Convertible";
        case 32:
            return "Detachable";
        default:
            return "Unknown (" + std::to_string(chassisType) + ")";
        }
    }

    return "Unknown";
}
