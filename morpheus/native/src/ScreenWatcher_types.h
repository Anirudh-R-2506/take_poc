#ifndef SCREEN_WATCHER_TYPES_H
#define SCREEN_WATCHER_TYPES_H

#include <string>
#include <vector>

// Forward declarations and basic types for cross-platform compatibility
namespace ScreenWatcherTypes {
    // Basic types that don't depend on platform-specific headers
    struct BasicDisplayInfo {
        std::string name;
        std::string deviceId;
        bool isPrimary;
        bool isExternal;
        bool isMirrored;
        bool isBeingCaptured;
        bool hasActiveSessions;
        int width;
        int height;
        int refreshRate;
    };

    struct BasicScreenSharingSession {
        int method;  // Will map to ScreenSharingMethod enum
        std::string processName;
        int pid;
        std::string targetUrl;
        std::string description;
        double confidence;
        bool isActive;
    };
}

#endif // SCREEN_WATCHER_TYPES_H