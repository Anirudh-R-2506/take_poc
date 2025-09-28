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
    console.log(`[🔍 ${this.moduleName}] Starting comprehensive device monitoring...`);
    console.log(`[🔍 ${this.moduleName}] Native addon available:`, !!this.nativeAddon);

    if (this.nativeAddon) {
      console.log(`[🔍 ${this.moduleName}] Available methods:`, Object.keys(this.nativeAddon));
      console.log(`[🔍 ${this.moduleName}] startSmartDeviceDetector available:`, typeof this.nativeAddon.startSmartDeviceDetector);
      console.log(`[🔍 ${this.moduleName}] stopSmartDeviceDetector available:`, typeof this.nativeAddon.stopSmartDeviceDetector);
      console.log(`[🔍 ${this.moduleName}] getDeviceViolations available:`, typeof this.nativeAddon.getDeviceViolations);
      console.log(`[🔍 ${this.moduleName}] getSecurityProfile available:`, typeof this.nativeAddon.getSecurityProfile);
    }

    if (
      !this.nativeAddon ||
      typeof this.nativeAddon.startSmartDeviceDetector !== "function"
    ) {
      console.log(`[🔍 ${this.moduleName}] Required methods not available, falling back`);
      this.startFallbackMode();
      return;
    }

    // Start the SmartDeviceDetector's continuous monitoring loop
    console.log(`[🔍 ${this.moduleName}] Starting SmartDeviceDetector continuous monitoring...`);
    try {
      // Start with 1-second monitoring interval for real-time detection
      this.nativeAddon.startSmartDeviceDetector(1000);
      console.log(`[🔍 ${this.moduleName}] SmartDeviceDetector monitoring started successfully`);
    } catch (err) {
      console.error(`[🔍 ${this.moduleName}] Failed to start SmartDeviceDetector:`, err);
      this.startFallbackMode();
      return;
    }

    // Poll for violations and device data every 2 seconds
    console.log(`[🔍 ${this.moduleName}] Setting up violation polling interval (2s)...`);

    this.devicePollingInterval = setInterval(() => {
      if (!this.isRunning) return;

      console.log(`[🔍 ${this.moduleName}] Polling for device violations and status...`);

      try {
        // Get current violations from the monitoring loop
        console.log(`[🔍 ${this.moduleName}] Calling getDeviceViolations...`);
        const violations = this.nativeAddon.getDeviceViolations();
        console.log(`[🔍 ${this.moduleName}] Active violations:`, violations?.length || 0);

        // Get current security profile
        console.log(`[🔍 ${this.moduleName}] Calling getSecurityProfile...`);
        const securityProfile = this.nativeAddon.getSecurityProfile();
        console.log(`[🔍 ${this.moduleName}] Security profile:`, !!securityProfile);

        // Get comprehensive device information for display
        console.log(`[🔍 ${this.moduleName}] Calling scanAllStorageDevices...`);
        const storageDevices = this.nativeAddon.scanAllStorageDevices();
        console.log(`[🔍 ${this.moduleName}] Storage devices:`, storageDevices?.length || 0);

        console.log(`[🔍 ${this.moduleName}] Calling scanAllInputDevices...`);
        const inputDevices = this.nativeAddon.scanAllInputDevices();
        console.log(`[🔍 ${this.moduleName}] Input devices:`, inputDevices?.length || 0);

        console.log(`[🔍 ${this.moduleName}] Calling scanVideoDevices...`);
        const videoDevices = this.nativeAddon.scanVideoDevices();
        console.log(`[🔍 ${this.moduleName}] Video devices:`, videoDevices?.length || 0);

        // Enhanced payload with comprehensive device information
        const deviceData = {
          event: "device-monitoring-update",
          timestamp: Date.now(),
          source: "smart-device-detector",

          // Violation information (primary concern)
          violations: violations || [],
          violationCount: violations?.length || 0,
          hasViolations: (violations?.length || 0) > 0,

          // Security profile
          securityProfile: securityProfile || null,

          // Comprehensive device inventory
          storageDevices: storageDevices || [],
          inputDevices: inputDevices || [],
          videoDevices: videoDevices || [],

          // Device summaries
          deviceCounts: {
            storage: storageDevices?.length || 0,
            input: inputDevices?.length || 0,
            video: videoDevices?.length || 0,
            total: (storageDevices?.length || 0) + (inputDevices?.length || 0) + (videoDevices?.length || 0)
          },

          // Threat analysis
          threatLevels: this.analyzeThreatLevels(violations),

          // Legacy compatibility
          devices: storageDevices || [],
        };

        // Always send data for proper frontend status display
        console.log(`[🔍 ${this.moduleName}] Sending comprehensive device data to parent...`);
        this.sendToParent({
          type: "proctor-event",
          module: this.moduleName,
          payload: deviceData,
        });
        console.log(`[🔍 ${this.moduleName}] Device data sent successfully`);

        // Log violations for debugging
        if (violations && violations.length > 0) {
          console.log(`[${this.moduleName}] ⚠️  ${violations.length} active device violations detected:`);
          violations.forEach((violation, index) => {
            console.log(`[${this.moduleName}]   ${index + 1}. ${violation.deviceName} (${violation.violationType}): ${violation.reason}`);
          });
        } else {
          console.log(`[🔍 ${this.moduleName}] No device violations detected - system secure`);
        }

      } catch (err) {
        console.error(`[🔍 ${this.moduleName}] Error in violation polling:`, err);
        console.error(`[🔍 ${this.moduleName}] Stack trace:`, err.stack);
        // Don't fall back immediately, try to recover
      }
    }, 2000); // 2 second interval
  }

  // Analyze threat levels from violations
  analyzeThreatLevels(violations) {
    if (!violations || violations.length === 0) {
      return {
        maxThreatLevel: 'NONE',
        threatCount: { critical: 0, high: 0, medium: 0, low: 0 },
        overallRisk: 'SECURE'
      };
    }

    const threatCount = { critical: 0, high: 0, medium: 0, low: 0 };
    let maxSeverity = 0;

    violations.forEach(violation => {
      const severity = violation.severity || 0;
      maxSeverity = Math.max(maxSeverity, severity);

      if (severity >= 4) threatCount.critical++;
      else if (severity >= 3) threatCount.high++;
      else if (severity >= 2) threatCount.medium++;
      else threatCount.low++;
    });

    const threatLevels = { 0: 'NONE', 1: 'LOW', 2: 'MEDIUM', 3: 'HIGH', 4: 'CRITICAL' };
    const maxThreatLevel = threatLevels[maxSeverity] || 'UNKNOWN';

    let overallRisk = 'SECURE';
    if (maxSeverity >= 4) overallRisk = 'CRITICAL';
    else if (maxSeverity >= 3) overallRisk = 'HIGH';
    else if (maxSeverity >= 2) overallRisk = 'ELEVATED';
    else if (maxSeverity >= 1) overallRisk = 'LOW';

    return {
      maxThreatLevel,
      threatCount,
      overallRisk
    };
  }

  startFallbackMode() {
    // Use the existing fallback from worker-base with module-specific data
    super.startFallbackMode();
  }

  stop() {
    console.log(`[${this.moduleName}] Stopping device watch worker...`);

    if (this.devicePollingInterval) {
      clearInterval(this.devicePollingInterval);
      this.devicePollingInterval = null;
      console.log(`[${this.moduleName}] Device polling interval cleared`);
    }

    if (this.isUsingSmartDeviceDetector && this.nativeAddon) {
      try {
        console.log(`[${this.moduleName}] Stopping SmartDeviceDetector monitoring...`);
        this.nativeAddon.stopSmartDeviceDetector();
        this.isUsingSmartDeviceDetector = false;
        console.log(`[${this.moduleName}] SmartDeviceDetector stopped successfully`);
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
