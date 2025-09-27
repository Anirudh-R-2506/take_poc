const WorkerBase = require("./worker-base");

class DeviceWatchWorker extends WorkerBase {
  constructor() {
    super("device-watch");
    this.isUsingSmartDeviceDetector = false;
  }

  startNativeMode() {
    this.isUsingSmartDeviceDetector = true;
    this.startPollingMode();
    console.log(`[${this.moduleName}] Using SmartDeviceDetector native addon`);
  }

  startPollingMode() {
    if (
      !this.nativeAddon ||
      typeof this.nativeAddon.scanAllStorageDevices !== "function"
    ) {
      this.startFallbackMode();
      return;
    }

    this.devicePollingInterval = setInterval(() => {
      if (!this.isRunning) return;

      try {
        // Get comprehensive device information
        const storageDevices = this.nativeAddon.scanAllStorageDevices();
        const inputDevices = this.nativeAddon.scanAllInputDevices();
        const videoDevices = this.nativeAddon.scanVideoDevices();
        const violations = this.nativeAddon.getDeviceViolations();
        const securityProfile = this.nativeAddon.getSecurityProfile();

        const deviceData = {
          event: "comprehensive-scan",
          timestamp: Date.now(),
          source: "smart-device-detector",
          storageDevices: storageDevices || [],
          inputDevices: inputDevices || [],
          videoDevices: videoDevices || [],
          violations: violations || [],
          securityProfile: securityProfile || null,
          // Legacy compatibility for existing code
          devices: storageDevices || [],
        };

        this.sendToParent({
          type: "proctor-event",
          module: this.moduleName,
          payload: deviceData,
        });
      } catch (err) {
        // Fall back to JavaScript implementation
        this.startFallbackMode();
      }
    }, 2000); // 2 second interval
  }

  startFallbackMode() {
    // Use the existing fallback from worker-base with module-specific data
    super.startFallbackMode();
  }

  stop() {
    if (this.devicePollingInterval) {
      clearInterval(this.devicePollingInterval);
      this.devicePollingInterval = null;
    }

    if (this.isUsingSmartDeviceDetector && this.nativeAddon) {
      try {
        this.isUsingSmartDeviceDetector = false;
      } catch (err) {
        console.error(
          `[${this.moduleName}] Error stopping SmartDeviceDetector:`,
          err
        );
      }
    }

    super.stop();
  }

  // Minimal fallback data if SmartDeviceDetector fails completely
  getModuleSpecificData() {
    return {
      event: "fallback-scan",
      timestamp: Date.now(),
      source: "unavailable",
      status: "error",
      storageDevices: [],
      inputDevices: [],
      videoDevices: [],
      violations: [],
      securityProfile: null,
      devices: [],
    };
  }
}

const worker = new DeviceWatchWorker();
worker.start();
