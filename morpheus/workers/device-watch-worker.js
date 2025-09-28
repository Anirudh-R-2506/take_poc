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
    console.log(`[🔍 ${this.moduleName}] Starting polling mode...`);
    console.log(`[🔍 ${this.moduleName}] Native addon available:`, !!this.nativeAddon);

    if (this.nativeAddon) {
      console.log(`[🔍 ${this.moduleName}] Available methods:`, Object.keys(this.nativeAddon));
      console.log(`[🔍 ${this.moduleName}] scanAllStorageDevices available:`, typeof this.nativeAddon.scanAllStorageDevices);
      console.log(`[🔍 ${this.moduleName}] scanAllInputDevices available:`, typeof this.nativeAddon.scanAllInputDevices);
      console.log(`[🔍 ${this.moduleName}] scanVideoDevices available:`, typeof this.nativeAddon.scanVideoDevices);
      console.log(`[🔍 ${this.moduleName}] getDeviceViolations available:`, typeof this.nativeAddon.getDeviceViolations);
      console.log(`[🔍 ${this.moduleName}] getSecurityProfile available:`, typeof this.nativeAddon.getSecurityProfile);
    }

    if (
      !this.nativeAddon ||
      typeof this.nativeAddon.scanAllStorageDevices !== "function"
    ) {
      console.log(`[🔍 ${this.moduleName}] Required methods not available, falling back`);
      this.startFallbackMode();
      return;
    }

    console.log(`[🔍 ${this.moduleName}] Setting up polling interval (2s)...`);

    this.devicePollingInterval = setInterval(() => {
      if (!this.isRunning) return;

      console.log(`[🔍 ${this.moduleName}] Polling devices...`);

      try {
        // Get comprehensive device information
        console.log(`[🔍 ${this.moduleName}] Calling scanAllStorageDevices...`);
        const storageDevices = this.nativeAddon.scanAllStorageDevices();
        console.log(`[🔍 ${this.moduleName}] Storage devices:`, storageDevices?.length || 0);

        console.log(`[🔍 ${this.moduleName}] Calling scanAllInputDevices...`);
        const inputDevices = this.nativeAddon.scanAllInputDevices();
        console.log(`[🔍 ${this.moduleName}] Input devices:`, inputDevices?.length || 0);

        console.log(`[🔍 ${this.moduleName}] Calling scanVideoDevices...`);
        const videoDevices = this.nativeAddon.scanVideoDevices();
        console.log(`[🔍 ${this.moduleName}] Video devices:`, videoDevices?.length || 0);

        console.log(`[🔍 ${this.moduleName}] Calling getDeviceViolations...`);
        const violations = this.nativeAddon.getDeviceViolations();
        console.log(`[🔍 ${this.moduleName}] Violations:`, violations?.length || 0);

        console.log(`[🔍 ${this.moduleName}] Calling getSecurityProfile...`);
        const securityProfile = this.nativeAddon.getSecurityProfile();
        console.log(`[🔍 ${this.moduleName}] Security profile:`, !!securityProfile);

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

        console.log(`[🔍 ${this.moduleName}] Sending device data to parent...`);
        this.sendToParent({
          type: "proctor-event",
          module: this.moduleName,
          payload: deviceData,
        });
        console.log(`[🔍 ${this.moduleName}] Device data sent successfully`);
      } catch (err) {
        console.error(`[🔍 ${this.moduleName}] Error in polling:`, err);
        console.error(`[🔍 ${this.moduleName}] Stack trace:`, err.stack);
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
