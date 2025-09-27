#include "SystemDetector.h"
#include <comdef.h>
#include <Wbemidl.h>
#include <oleauto.h>
#include <sstream>
#include <vector>

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

    // Determine portability based on chassis type and battery
    if (info.hasBattery ||
        info.chassisType.find("Laptop") != std::string::npos ||
        info.chassisType.find("Notebook") != std::string::npos ||
        info.chassisType.find("Portable") != std::string::npos ||
        info.chassisType.find("Sub Notebook") != std::string::npos)
    {
        info.isPortable = true;
        info.hasLid = true;
        info.type = SystemType::LAPTOP; // Override type if portable indicators found
    }

    // Final type validation - if we have battery but detected as desktop, override to laptop
    if (info.hasBattery && info.type == SystemType::DESKTOP) {
        info.type = SystemType::LAPTOP;
        info.chassisType = "Laptop";
        info.isPortable = true;
        info.hasLid = true;
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

std::string SystemDetector::QueryWMI(const std::string& wmiClass, const std::string& property)
{
    HRESULT hres;
    std::string result;

    // Initialize COM
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        return "";
    }

    // Set general COM security levels
    hres = CoInitializeSecurity(
        NULL,
        -1,                          // COM authentication
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_NONE,      // Default authentication
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities
        NULL                         // Reserved
    );

    if (FAILED(hres))
    {
        CoUninitialize();
        return "";
    }

    // Obtain the initial locator to WMI
    IWbemLocator *pLoc = NULL;
    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID *) &pLoc);

    if (FAILED(hres))
    {
        CoUninitialize();
        return "";
    }

    // Connect to WMI through the IWbemLocator::ConnectServer method
    IWbemServices *pSvc = NULL;
    hres = pLoc->ConnectServer(
         _bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
         NULL,                    // User name. NULL = current user
         NULL,                    // User password. NULL = current
         0,                       // Locale. NULL indicates current
         NULL,                    // Security flags.
         0,                       // Authority (e.g. Kerberos)
         0,                       // Context object
         &pSvc                    // pointer to IWbemServices proxy
         );

    if (FAILED(hres))
    {
        pLoc->Release();
        CoUninitialize();
        return "";
    }

    // Set security levels on the proxy
    hres = CoSetProxyBlanket(
       pSvc,                        // Indicates the proxy to set
       RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
       RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
       NULL,                        // Server principal name
       RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx
       RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
       NULL,                        // client identity
       EOAC_NONE                    // proxy capabilities
    );

    if (FAILED(hres))
    {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return "";
    }

    // Execute WMI query
    std::string query = "SELECT " + property + " FROM " + wmiClass;
    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(query.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres))
    {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return "";
    }

    // Get the data from the query
    IWbemClassObject *pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator)
    {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (0 == uReturn)
        {
            break;
        }

        VARIANT vtProp;
        hr = pclsObj->Get(_bstr_t(property.c_str()), 0, &vtProp, 0, 0);

        if (SUCCEEDED(hr) && vtProp.vt != VT_NULL)
        {
            if (vtProp.vt == VT_BSTR)
            {
                _bstr_t bstrVal(vtProp.bstrVal);
                result = (char*)bstrVal;
            }
            else if (vtProp.vt == VT_I4)
            {
                result = std::to_string(vtProp.lVal);
            }
            else if (vtProp.vt == (VT_ARRAY | VT_I4))
            {
                // Handle array of integers (like ChassisTypes)
                SAFEARRAY* psa = vtProp.parray;
                if (psa != NULL)
                {
                    LONG lBound, uBound;
                    SafeArrayGetLBound(psa, 1, &lBound);
                    SafeArrayGetUBound(psa, 1, &uBound);

                    if (lBound <= uBound)
                    {
                        LONG* pData;
                        SafeArrayAccessData(psa, (void**)&pData);
                        result = std::to_string(pData[0]); // Take first chassis type
                        SafeArrayUnaccessData(psa);
                    }
                }
            }
        }
        VariantClear(&vtProp);
        pclsObj->Release();
        break; // Take first result
    }

    // Cleanup
    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    CoUninitialize();

    return result;
}

SystemType SystemDetector::DetectWindowsSystemType()
{
    // First check chassis type
    std::string chassisType = GetWindowsChassisType();

    if (chassisType.find("Laptop") != std::string::npos ||
        chassisType.find("Notebook") != std::string::npos ||
        chassisType.find("Sub Notebook") != std::string::npos ||
        chassisType.find("Portable") != std::string::npos)
    {
        return SystemType::LAPTOP;
    }

    if (chassisType.find("Desktop") != std::string::npos ||
        chassisType.find("Tower") != std::string::npos ||
        chassisType.find("Mini Tower") != std::string::npos)
    {
        return SystemType::DESKTOP;
    }

    // Check battery as fallback
    if (DetectWindowsBattery())
    {
        return SystemType::LAPTOP;
    }

    // Default to desktop if uncertain
    return SystemType::DESKTOP;
}

bool SystemDetector::DetectWindowsBattery()
{
    // Method 1: Check for battery devices using WMI
    std::string batteryStatus = QueryWMI("Win32_Battery", "Status");
    if (!batteryStatus.empty())
    {
        return true;
    }

    // Method 2: Check system power status
    SYSTEM_POWER_STATUS powerStatus;
    if (GetSystemPowerStatus(&powerStatus))
    {
        // If ACLineStatus is 255, it means the battery status is unknown but there might be a battery
        // If BatteryFlag is not 255 (unknown) and not 128 (no battery), there's a battery
        if (powerStatus.BatteryFlag != 255 && powerStatus.BatteryFlag != 128)
        {
            return true;
        }
    }

    return false;
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
            return "All In One";
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

#endif