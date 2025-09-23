#include "VMDetector.h"
#include <iostream>
#include <algorithm>
#include <sstream>
#include <chrono>

VMDetector::VMDetector() : running_(false), counter_(0) {
    initializeVMSignatures();
    std::cout << "[VMDetector] Initialized for platform: " 
              << (isPlatformSupported() ? "supported" : "unsupported") << std::endl;
}

VMDetector::~VMDetector() {
    Stop();
}

bool VMDetector::isPlatformSupported() {
#if defined(_WIN32) || defined(__APPLE__)
    return true;
#else
    return false;
#endif
}

void VMDetector::initializeVMSignatures() {
    // VM vendor strings to look for - more specific patterns to avoid false positives
    vmVendorStrings = {
        "VMware", "vmware", "VMWARE", "VMware, Inc.",
        "VirtualBox", "virtualbox", "VBOX", "Oracle VM VirtualBox", "innotek GmbH",
        "Parallels", "parallels", "PRL", "Parallels Software",
        "QEMU", "qemu", "KVM", "kvm", "QEMU Virtual Machine",
        "Xen", "xen", "XEN", "Xen Project",
        "Hyper-V", "Microsoft Hyper-V", "Virtual Machine",
        "Bochs", "bochs"
    };
    
    // VM process names
    vmProcessNames = {
        "vmware.exe", "vmware-vmx.exe", "vmware-tray.exe", "vmware-unity-helper.exe",
        "vboxservice.exe", "vboxtray.exe", "virtualbox.exe",
        "prl_tools.exe", "prl_cc.exe", "parallels.exe",
        "qemu-ga.exe", "qemu-system", "qemu-img.exe",
        "xenservice.exe", "xensvc.exe",
        "VBoxService", "VBoxClient", "VMware Tools",
        "prl_tools_service", "Parallels Tools",
        "vmtoolsd", "vmware-tools"
    };
    
    // VM MAC address prefixes (OUIs)
    vmMACPrefixes = {
        "00:05:69", "00:0C:29", "00:1C:14", "00:50:56", // VMware
        "08:00:27", "0A:00:27",                         // VirtualBox
        "00:1C:42",                                     // Parallels
        "52:54:00",                                     // QEMU/KVM
        "00:16:3E"                                      // Xen
    };
}

void VMDetector::Start(Napi::Function callback, int intervalMs) {
    if (running_.load()) {
        return; // Already running
    }
    
    running_.store(true);
    intervalMs_ = intervalMs;
    callback_ = Napi::Persistent(callback);
    
    // Create thread-safe function for callbacks (following ProcessWatcher pattern)
    tsfn_ = Napi::ThreadSafeFunction::New(
        callback.Env(),
        callback,
        "VMDetector",
        0,
        1,
        [this](Napi::Env) {
            // Finalize callback
        }
    );
    
    // Start worker thread
    worker_thread_ = std::thread([this]() {
        WatcherLoop();
    });
    
    std::cout << "[VMDetector] Started monitoring (interval: " << intervalMs << "ms)" << std::endl;
}

void VMDetector::Stop() {
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
    
    std::cout << "[VMDetector] Stopped monitoring" << std::endl;
}

bool VMDetector::IsRunning() const {
    return running_.load();
}

void VMDetector::WatcherLoop() {
    while (running_.load()) {
        try {
            VMDetectionResult result = detectVirtualMachine();
            counter_++;
            
            // Only emit if result has changed or this is the first detection
            if (counter_.load() == 1 || 
                result.isInsideVM != lastResult_.isInsideVM || 
                result.detectedVM != lastResult_.detectedVM ||
                result.runningVMProcesses.size() != lastResult_.runningVMProcesses.size()) {
                
                EmitVMEvent(result);
                lastResult_ = result;
            }
            
        } catch (const std::exception& e) {
            std::cerr << "[VMDetector] Error in monitoring loop: " << e.what() << std::endl;
        }
        
        // Sleep for the specified interval
        std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs_));
    }
}

void VMDetector::EmitVMEvent(const VMDetectionResult& result) {
    if (!tsfn_) return;
    
    std::string jsonData = CreateEventJson(result);
    
    // Call JavaScript callback using thread-safe function
    auto callback = [](Napi::Env env, Napi::Function jsCallback, std::string* data) {
        if (data) {
            jsCallback.Call({Napi::String::New(env, *data)});
            delete data;
        }
    };
    
    napi_status status = tsfn_.NonBlockingCall(new std::string(jsonData), callback);
    if (status != napi_ok) {
        std::cerr << "[VMDetector] Failed to call JavaScript callback" << std::endl;
    }
}

std::string VMDetector::CreateEventJson(const VMDetectionResult& result) {
    std::ostringstream json;
    json << "{";
    json << "\"module\":\"vm-detect\",";
    json << "\"isVirtualMachine\":" << (result.isInsideVM ? "true" : "false") << ",";
    json << "\"vmSoftware\":\"" << EscapeJson(result.detectedVM) << "\",";
    json << "\"detectionMethod\":\"" << EscapeJson(result.detectionMethod) << "\",";
    
    // Running VM processes
    json << "\"runningVMProcesses\":[";
    for (size_t i = 0; i < result.runningVMProcesses.size(); i++) {
        if (i > 0) json << ",";
        json << "\"" << EscapeJson(result.runningVMProcesses[i]) << "\"";
    }
    json << "],";
    
    // VM indicators
    json << "\"vmIndicators\":[";
    for (size_t i = 0; i < result.vmIndicators.size(); i++) {
        if (i > 0) json << ",";
        json << "\"" << EscapeJson(result.vmIndicators[i]) << "\"";
    }
    json << "],";
    
    json << "\"timestamp\":" << std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() << ",";
    json << "\"source\":\"native\",";
    json << "\"count\":" << counter_.load() << ",";
    json << "\"status\":\"monitoring\"";
    json << "}";
    
    return json.str();
}

std::string VMDetector::EscapeJson(const std::string& str) {
    std::string escaped;
    escaped.reserve(str.length() + 10);
    
    for (char c : str) {
        switch (c) {
            case '\"': escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\b': escaped += "\\b"; break;
            case '\f': escaped += "\\f"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default:
                if (c >= 0 && c < 32) {
                    escaped += "\\u" + std::to_string(c);
                } else {
                    escaped += c;
                }
        }
    }
    
    return escaped;
}

VMDetectionResult VMDetector::detectVirtualMachine() {
    VMDetectionResult result = {};
    result.isInsideVM = false;
    result.detectedVM = "None";
    
    if (!isPlatformSupported()) {
        result.detectionMethod = "Unsupported platform";
        return result;
    }
    
    try {
#ifdef _WIN32
        std::cout << "[VMDetector] Running Windows VM detection" << std::endl;
        
        bool hypervisorBit = checkWindowsHypervisorBit();
        bool biosCheck = checkWindowsBIOS();
        bool macCheck = checkWindowsMAC();
        std::vector<std::string> vmProcesses = checkWindowsVMProcesses();
        
        result.runningVMProcesses = vmProcesses;
        
        // Collect indicators
        if (hypervisorBit) result.vmIndicators.push_back("Hypervisor bit set");
        if (biosCheck) result.vmIndicators.push_back("VM BIOS detected");
        if (macCheck) result.vmIndicators.push_back("VM MAC address");
        if (!vmProcesses.empty()) result.vmIndicators.push_back("VM processes running");
        
        // Determine if we're in a VM
        result.isInsideVM = hypervisorBit || biosCheck || macCheck;
        result.detectedVM = identifyWindowsVM(result.vmIndicators);
        result.detectionMethod = "Windows native detection";
        
#elif __APPLE__
        std::cout << "[VMDetector] Running macOS VM detection" << std::endl;
        
        bool systemProfiler = checkMacOSSystemProfiler();
        bool ioRegistry = checkMacOSIORegistry();
        bool hypervisorFramework = checkMacOSHypervisorFramework();
        std::vector<std::string> vmProcesses = checkMacOSVMProcesses();
        
        result.runningVMProcesses = vmProcesses;
        
        // Collect indicators
        if (systemProfiler) result.vmIndicators.push_back("VM hardware detected");
        if (ioRegistry) result.vmIndicators.push_back("VM IORegistry entries");
        if (hypervisorFramework) result.vmIndicators.push_back("Hypervisor framework");
        if (!vmProcesses.empty()) result.vmIndicators.push_back("VM processes running");
        
        // Determine if we're in a VM - require multiple strong indicators to avoid false positives
        int strongIndicators = 0;
        if (systemProfiler) strongIndicators++;
        if (ioRegistry) strongIndicators++;
        if (!vmProcesses.empty()) strongIndicators++;
        
        // Only consider VM if we have multiple indicators or very specific VM processes
        result.isInsideVM = strongIndicators >= 2 || (!vmProcesses.empty() && vmProcesses.size() >= 2);
        result.detectedVM = identifyMacOSVM(result.vmIndicators);
        result.detectionMethod = "macOS native detection";
#endif
        
    } catch (const std::exception& e) {
        std::cerr << "[VMDetector] Error during detection: " << e.what() << std::endl;
        result.detectionMethod = "Error: " + std::string(e.what());
    }
    
    std::cout << "[VMDetector] Detection complete - VM detected: " << (result.isInsideVM ? "Yes" : "No") << std::endl;
    return result;
}

#ifdef _WIN32

bool VMDetector::checkWindowsHypervisorBit() {
    try {
        int cpuInfo[4];
        __cpuid(cpuInfo, 1);
        
        // Check bit 31 of ECX (hypervisor present bit)
        bool hypervisorPresent = (cpuInfo[2] & (1 << 31)) != 0;
        
        std::cout << "[VMDetector] Hypervisor bit: " << (hypervisorPresent ? "Set" : "Not set") << std::endl;
        return hypervisorPresent;
    } catch (...) {
        std::cout << "[VMDetector] CPUID check failed" << std::endl;
        return false;
    }
}

bool VMDetector::checkWindowsBIOS() {
    try {
        // Check BIOS/System information via registry
        HKEY hKey;
        char buffer[512];
        DWORD bufferSize = sizeof(buffer);
        
        // Check BIOS vendor
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                         "HARDWARE\\DESCRIPTION\\System\\BIOS", 
                         0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            
            if (RegQueryValueExA(hKey, "SystemManufacturer", NULL, NULL, 
                               (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                std::string manufacturer(buffer);
                std::cout << "[VMDetector] System manufacturer: " << manufacturer << std::endl;
                
                for (const auto& vmString : vmVendorStrings) {
                    if (manufacturer.find(vmString) != std::string::npos) {
                        RegCloseKey(hKey);
                        return true;
                    }
                }
            }
            
            // Check BIOS version
            bufferSize = sizeof(buffer);
            if (RegQueryValueExA(hKey, "BIOSVersion", NULL, NULL, 
                               (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                std::string biosVersion(buffer);
                std::cout << "[VMDetector] BIOS version: " << biosVersion << std::endl;
                
                for (const auto& vmString : vmVendorStrings) {
                    if (biosVersion.find(vmString) != std::string::npos) {
                        RegCloseKey(hKey);
                        return true;
                    }
                }
            }
            
            RegCloseKey(hKey);
        }
        
        return false;
    } catch (...) {
        std::cout << "[VMDetector] BIOS check failed" << std::endl;
        return false;
    }
}

bool VMDetector::checkWindowsMAC() {
    try {
        DWORD dwSize = 0;
        GetAdaptersInfo(NULL, &dwSize);
        
        if (dwSize == 0) return false;
        
        PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(dwSize);
        if (!pAdapterInfo) return false;
        
        bool vmMacFound = false;
        if (GetAdaptersInfo(pAdapterInfo, &dwSize) == ERROR_SUCCESS) {
            PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
            
            while (pAdapter) {
                // Convert MAC address to string
                std::stringstream macStream;
                macStream << std::hex << std::setfill('0');
                for (int i = 0; i < 3; i++) { // First 3 bytes (OUI)
                    if (i > 0) macStream << ":";
                    macStream << std::setw(2) << (unsigned int)pAdapter->Address[i];
                }
                
                std::string macPrefix = macStream.str();
                std::transform(macPrefix.begin(), macPrefix.end(), macPrefix.begin(), ::toupper);
                
                std::cout << "[VMDetector] Found MAC prefix: " << macPrefix << std::endl;
                
                for (const auto& vmMac : vmMACPrefixes) {
                    std::string vmMacUpper = vmMac;
                    std::transform(vmMacUpper.begin(), vmMacUpper.end(), vmMacUpper.begin(), ::toupper);
                    
                    if (macPrefix == vmMacUpper) {
                        vmMacFound = true;
                        break;
                    }
                }
                
                if (vmMacFound) break;
                pAdapter = pAdapter->Next;
            }
        }
        
        free(pAdapterInfo);
        return vmMacFound;
    } catch (...) {
        std::cout << "[VMDetector] MAC address check failed" << std::endl;
        return false;
    }
}

std::vector<std::string> VMDetector::checkWindowsVMProcesses() {
    std::vector<std::string> foundProcesses;
    
    try {
        HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcessSnap == INVALID_HANDLE_VALUE) {
            return foundProcesses;
        }
        
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hProcessSnap, &pe32)) {
            do {
                std::string processName(pe32.szExeFile);
                std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);
                
                for (const auto& vmProcess : vmProcessNames) {
                    std::string vmProcessLower = vmProcess;
                    std::transform(vmProcessLower.begin(), vmProcessLower.end(), vmProcessLower.begin(), ::tolower);
                    
                    if (processName.find(vmProcessLower) != std::string::npos) {
                        foundProcesses.push_back(pe32.szExeFile);
                        std::cout << "[VMDetector] Found VM process: " << pe32.szExeFile << std::endl;
                        break;
                    }
                }
            } while (Process32Next(hProcessSnap, &pe32));
        }
        
        CloseHandle(hProcessSnap);
    } catch (...) {
        std::cout << "[VMDetector] Process enumeration failed" << std::endl;
    }
    
    return foundProcesses;
}

std::string VMDetector::identifyWindowsVM(const std::vector<std::string>& indicators) {
    if (indicators.empty()) return "None";
    
    // Simple heuristic based on common indicators
    for (const auto& indicator : indicators) {
        if (indicator.find("VMware") != std::string::npos) return "VMware";
        if (indicator.find("VirtualBox") != std::string::npos || indicator.find("VBox") != std::string::npos) return "VirtualBox";
        if (indicator.find("Parallels") != std::string::npos) return "Parallels";
        if (indicator.find("QEMU") != std::string::npos || indicator.find("KVM") != std::string::npos) return "QEMU/KVM";
        if (indicator.find("Hyper-V") != std::string::npos) return "Hyper-V";
        if (indicator.find("Xen") != std::string::npos) return "Xen";
    }
    
    // If we have indicators but can't identify specific VM
    return "Unknown VM";
}

#elif __APPLE__

bool VMDetector::checkMacOSSystemProfiler() {
    try {
        FILE* pipe = popen("system_profiler SPHardwareDataType 2>/dev/null", "r");
        if (!pipe) return false;
        
        char buffer[512];
        std::string result;
        
        while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            result += buffer;
        }
        
        pclose(pipe);
        
        std::cout << "[VMDetector] System profiler output length: " << result.length() << std::endl;
        
        // Check for VM indicators in system profiler output
        for (const auto& vmString : vmVendorStrings) {
            if (result.find(vmString) != std::string::npos) {
                std::cout << "[VMDetector] Found VM indicator in system profiler: " << vmString << std::endl;
                return true;
            }
        }
        
        return false;
    } catch (...) {
        std::cout << "[VMDetector] System profiler check failed" << std::endl;
        return false;
    }
}

bool VMDetector::checkMacOSIORegistry() {
    try {
        // Get IORegistry information
        io_registry_entry_t registry = IORegistryGetRootEntry(kIOMasterPortDefault);
        if (!registry) return false;
        
        CFMutableDictionaryRef properties;
        kern_return_t result = IORegistryEntryCreateCFProperties(registry, &properties, kCFAllocatorDefault, kNilOptions);
        
        if (result != KERN_SUCCESS) {
            IOObjectRelease(registry);
            return false;
        }
        
        // Convert to string and check for VM indicators
        CFDataRef xmlData = CFPropertyListCreateData(kCFAllocatorDefault, properties, kCFPropertyListXMLFormat_v1_0, 0, NULL);
        if (xmlData) {
            CFIndex length = CFDataGetLength(xmlData);
            const UInt8* bytes = CFDataGetBytePtr(xmlData);
            std::string xmlString((char*)bytes, length);
            
            for (const auto& vmString : vmVendorStrings) {
                if (xmlString.find(vmString) != std::string::npos) {
                    std::cout << "[VMDetector] Found VM indicator in IORegistry: " << vmString << std::endl;
                    CFRelease(xmlData);
                    CFRelease(properties);
                    IOObjectRelease(registry);
                    return true;
                }
            }
            
            CFRelease(xmlData);
        }
        
        CFRelease(properties);
        IOObjectRelease(registry);
        return false;
    } catch (...) {
        std::cout << "[VMDetector] IORegistry check failed" << std::endl;
        return false;
    }
}

bool VMDetector::checkMacOSHypervisorFramework() {
    try {
        // Check if hypervisor support is available
        int hvSupport = 0;
        size_t size = sizeof(hvSupport);
        
        if (sysctlbyname("kern.hv_support", &hvSupport, &size, NULL, 0) == 0) {
            std::cout << "[VMDetector] Hypervisor support: " << hvSupport << std::endl;
            return hvSupport != 0;
        }
        
        return false;
    } catch (...) {
        std::cout << "[VMDetector] Hypervisor framework check failed" << std::endl;
        return false;
    }
}

std::vector<std::string> VMDetector::checkMacOSVMProcesses() {
    std::vector<std::string> foundProcesses;
    
    try {
        FILE* pipe = popen("ps -axo comm 2>/dev/null", "r");
        if (!pipe) return foundProcesses;
        
        char buffer[512];
        
        while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            std::string processName(buffer);
            processName.erase(processName.find_last_not_of(" \n\r\t") + 1);
            
            for (const auto& vmProcess : vmProcessNames) {
                if (processName.find(vmProcess) != std::string::npos) {
                    foundProcesses.push_back(processName);
                    std::cout << "[VMDetector] Found VM process: " << processName << std::endl;
                    break;
                }
            }
        }
        
        pclose(pipe);
    } catch (...) {
        std::cout << "[VMDetector] Process enumeration failed" << std::endl;
    }
    
    return foundProcesses;
}

std::string VMDetector::identifyMacOSVM(const std::vector<std::string>& indicators) {
    if (indicators.empty()) return "None";
    
    // Simple heuristic based on common indicators
    for (const auto& indicator : indicators) {
        if (indicator.find("VMware") != std::string::npos) return "VMware Fusion";
        if (indicator.find("VirtualBox") != std::string::npos || indicator.find("VBox") != std::string::npos) return "VirtualBox";
        if (indicator.find("Parallels") != std::string::npos) return "Parallels Desktop";
        if (indicator.find("QEMU") != std::string::npos) return "QEMU";
    }
    
    // If we have indicators but can't identify specific VM
    return "Unknown VM";
}

#endif