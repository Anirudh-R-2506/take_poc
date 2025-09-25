const { spawn } = require("child_process");
const os = require("os");
const nativeAddonSingleton = require("../shared/NativeAddonSingleton");

/**
 * Centralized Permission Management System for Morpheus Proctoring
 * Handles all system permissions required for monitoring
 */
class PermissionManager {
  constructor() {
    const platform = os.platform();
    this.permissions = {
      screenRecording: {
        name: "Screen Recording",
        status: "unknown", // unknown, granted, denied, checking
        required: true,
        description:
          platform === "win32"
            ? "Required for display monitoring and overlay detection (Windows)"
            : "Required for display monitoring and overlay detection (macOS)",
        services: ["ScreenWatcher", "NotificationWatcher"],
        checkCommand:
          platform === "win32"
            ? "wmic desktopmonitor get Name"
            : "system_profiler SPDisplaysDataType",
        error: null,
      },
      accessibility: {
        name: "Accessibility",
        status: "unknown",
        required: true,
        description:
          platform === "win32"
            ? "Required for focus tracking and idle detection (Windows)"
            : "Required for focus tracking and idle detection (macOS)",
        services: ["FocusIdleWatcher", "NotificationWatcher"],
        checkCommand: null, // Uses native API
        error: null,
      },
      inputMonitoring: {
        name: "Input Monitoring",
        status: "unknown",
        required: true,
        description:
          platform === "win32"
            ? "Required for external device detection (Windows)"
            : "Required for external device detection (macOS)",
        services: ["ScreenWatcher"],
        checkCommand: null, // Uses native API
        error: null,
      },
      ...(platform === "win32" && {
        registryAccess: {
          name: "Registry Access",
          status: "unknown",
          required: true,
          description: "Required for system settings and notification control (Windows)",
          services: ["NotificationBlocker", "VMDetector"],
          checkCommand: null,
          error: null,
        },
        deviceEnumeration: {
          name: "Device Enumeration",
          status: "unknown",
          required: true,
          description: "Required for hardware device detection (Windows)",
          services: ["DeviceWatcher", "ScreenWatcher", "BluetoothWatcher"],
          checkCommand: null,
          error: null,
        },
        processAccess: {
          name: "Process Access",
          status: "unknown",
          required: true,
          description: "Required for application monitoring (Windows)",
          services: ["ProcessWatcher"],
          checkCommand: null,
          error: null,
        },
        clipboardAccess: {
          name: "Clipboard Access",
          status: "unknown",
          required: true,
          description: "Required for clipboard content monitoring (Windows)",
          services: ["ClipboardWatcher"],
          checkCommand: null,
          error: null,
        }
      }),
    };

    this.nativeAddon = null;
    this.eventCallbacks = [];
    this.isInitialized = false;
  }

  /**
   * Safe logging method that prevents EPIPE errors
   */
  safeLog(message, isError = false) {
    try {
      if (isError) {
        console.error(message);
      } else {
        console.log(message);
      }
    } catch (pipeError) {
      // Silently ignore EPIPE errors during logging
      // This prevents crashes when worker pipes are broken
    }
  }

  /**
   * Initialize the permission manager with native addon
   */
  async initialize(nativeAddon = null) {
    const platform = os.platform();
    this.safeLog(`[PermissionManager] Initializing for ${platform}...`);
    
    // Use singleton native addon if no specific instance provided
    try {
      this.nativeAddon = nativeAddon || await nativeAddonSingleton.getInstance();
      // Safely log without causing EPIPE errors
      this.safeLog("[PermissionManager] Native addon loaded via singleton");
    } catch (error) {
      this.safeLog("[PermissionManager] Failed to load native addon: " + (error?.message || error), true);
      this.nativeAddon = null;
    }
    
    this.isInitialized = true;

    // Log platform-specific information
    if (platform === "win32") {
      console.log(
        "[PermissionManager] Running on Windows - using Windows APIs for permission checks"
      );
    } else if (platform === "darwin") {
      console.log(
        "[PermissionManager] Running on macOS - using macOS APIs for permission checks"
      );
    } else {
      console.log(
        `[PermissionManager] Running on ${platform} - using generic permission checks`
      );
    }

    // Check all permissions on startup
    await this.checkAllPermissions();
    return this.getPermissionStatus();
  }

  /**
   * Register callback for permission status changes
   */
  onPermissionChange(callback) {
    this.eventCallbacks.push(callback);
  }

  /**
   * Emit permission status change to all listeners
   */
  emitPermissionChange(permissionType, status) {
    console.log(
      `[PermissionManager] Permission changed: ${permissionType} = ${status}`
    );
    this.eventCallbacks.forEach((callback) => {
      try {
        callback(permissionType, status, this.getPermissionStatus());
      } catch (err) {
        console.error("[PermissionManager] Error in permission callback:", err);
      }
    });
  }

  /**
   * Check all permissions sequentially
   */
  async checkAllPermissions() {
    console.log("[PermissionManager] Checking all permissions...");
    const platform = os.platform();

    // On Windows, also check UAC status
    if (platform === "win32") {
      await this.checkWindowsUACStatus();
    }

    // Sequential permission checking to avoid multiple system dialogs
    console.log("[PermissionManager] Checking permissions sequentially...");

    await this.checkAccessibilityPermission();
    await this.checkScreenRecordingPermission();
    await this.checkInputMonitoringPermission();

    // Windows-specific permission checks
    if (platform === "win32") {
      await this.checkRegistryAccessPermission();
      await this.checkDeviceEnumerationPermission();
      await this.checkProcessAccessPermission();
      await this.checkClipboardAccessPermission();
    }

    const status = this.getPermissionStatus();
    console.log("[PermissionManager] All permissions checked:", status);

    // Provide platform-specific recommendations if permissions are missing
    const missing = this.getMissingPermissions();
    if (missing.length > 0 && platform === "win32") {
      console.log("[PermissionManager] Windows recommendations:");
      this.getWindowsPermissionRecommendations().forEach((rec) => {
        console.log(`  - ${rec}`);
      });
    }

    return status;
  }

  /**
   * Check accessibility permission using native addon
   */
  async checkAccessibilityPermission() {
    console.log("[PermissionManager] Checking accessibility permission...");
    this.permissions.accessibility.status = "checking";
    this.emitPermissionChange("accessibility", "checking");

    try {
      const platform = os.platform();
      console.log(`[PermissionManager] Accessibility check - nativeAddon available: ${!!this.nativeAddon}`);
      console.log(`[PermissionManager] Native addon methods: ${this.nativeAddon ? Object.keys(this.nativeAddon).join(', ') : 'none'}`);
      
      if (this.nativeAddon && this.nativeAddon.checkAccessibilityPermission) {
        console.log('[PermissionManager] Using native addon for accessibility check');
        const hasPermission = this.nativeAddon.checkAccessibilityPermission();
        console.log(`[PermissionManager] Native accessibility check result: ${hasPermission}`);
        
        this.permissions.accessibility.status = hasPermission
          ? "granted"
          : "denied";
        this.permissions.accessibility.error = hasPermission
          ? null
          : platform === "win32"
            ? "Windows accessibility features not enabled"
            : "macOS accessibility permission not granted";
      } else {
        console.log('[PermissionManager] Native addon not available, using fallback for accessibility');
        // Fallback: Try to detect accessibility through system behavior
        const hasPermission = await this.testAccessibilityFallback();
        console.log(`[PermissionManager] Fallback accessibility check result: ${hasPermission}`);
        
        this.permissions.accessibility.status = hasPermission
          ? "granted"
          : "denied";
        this.permissions.accessibility.error = hasPermission
          ? null
          : platform === "win32"
            ? "Cannot verify Windows accessibility features"
            : "Cannot verify macOS accessibility permission";
      }
    } catch (error) {
      this.permissions.accessibility.status = "denied";
      this.permissions.accessibility.error = error.message;
      console.error(
        "[PermissionManager] Accessibility permission error:",
        error.message
      );
    }

    console.log(
      `[PermissionManager] Accessibility permission: ${this.permissions.accessibility.status.toUpperCase()}`
    );
    this.emitPermissionChange(
      "accessibility",
      this.permissions.accessibility.status
    );
    return this.permissions.accessibility.status;
  }

  /**
   * Check screen recording permission
   */
  async checkScreenRecordingPermission() {
    console.log("[PermissionManager] Checking screen recording permission...");
    this.permissions.screenRecording.status = "checking";
    this.emitPermissionChange("screenRecording", "checking");

    try {
      const platform = os.platform();
      if (this.nativeAddon && this.nativeAddon.checkScreenRecordingPermission) {
        const hasPermission = this.nativeAddon.checkScreenRecordingPermission();
        this.permissions.screenRecording.status = hasPermission
          ? "granted"
          : "denied";
        this.permissions.screenRecording.error = hasPermission
          ? null
          : platform === "win32"
            ? "Windows camera/screen capture permission not granted"
            : "macOS screen recording permission not granted";
      } else {
        // Fallback: Test screen recording capability
        const hasPermission = await this.testScreenRecordingFallback();
        this.permissions.screenRecording.status = hasPermission
          ? "granted"
          : "denied";
        this.permissions.screenRecording.error = hasPermission
          ? null
          : platform === "win32"
            ? "Cannot verify Windows camera/screen capture permission"
            : "Cannot verify macOS screen recording permission";
      }
    } catch (error) {
      this.permissions.screenRecording.status = "denied";
      this.permissions.screenRecording.error = error.message;
      console.error(
        "[PermissionManager] Screen recording permission error:",
        error.message
      );
    }

    console.log(
      `[PermissionManager] Screen recording permission: ${this.permissions.screenRecording.status.toUpperCase()}`
    );
    this.emitPermissionChange(
      "screenRecording",
      this.permissions.screenRecording.status
    );
    return this.permissions.screenRecording.status;
  }

  /**
   * Check input monitoring permission
   */
  async checkInputMonitoringPermission() {
    console.log("[PermissionManager] Checking input monitoring permission...");
    this.permissions.inputMonitoring.status = "checking";
    this.emitPermissionChange("inputMonitoring", "checking");

    try {
      const platform = os.platform();
      console.log(`[PermissionManager] Input monitoring check - nativeAddon available: ${!!this.nativeAddon}`);
      
      if (this.nativeAddon && this.nativeAddon.checkInputMonitoringPermission) {
        console.log('[PermissionManager] Using native addon for input monitoring check');
        const hasPermission = this.nativeAddon.checkInputMonitoringPermission();
        console.log(`[PermissionManager] Native input monitoring check result: ${hasPermission}`);
        
        this.permissions.inputMonitoring.status = hasPermission
          ? "granted"
          : "denied";
        this.permissions.inputMonitoring.error = hasPermission
          ? null
          : platform === "win32"
            ? "Windows input monitoring permission not granted"
            : "macOS input monitoring permission not granted";
      } else {
        console.log('[PermissionManager] Native addon not available, using fallback for input monitoring');
        // Fallback: Test input monitoring capability
        const hasPermission = await this.testInputMonitoringFallback();
        console.log(`[PermissionManager] Fallback input monitoring check result: ${hasPermission}`);
        
        this.permissions.inputMonitoring.status = hasPermission
          ? "granted"
          : "denied";
        this.permissions.inputMonitoring.error = hasPermission
          ? null
          : platform === "win32"
            ? "Cannot verify Windows input monitoring permission"
            : "Cannot verify macOS input monitoring permission";
      }
    } catch (error) {
      this.permissions.inputMonitoring.status = "denied";
      this.permissions.inputMonitoring.error = error.message;
      console.error(
        "[PermissionManager] Input monitoring permission error:",
        error.message
      );
    }

    console.log(
      `[PermissionManager] Input monitoring permission: ${this.permissions.inputMonitoring.status.toUpperCase()}`
    );
    this.emitPermissionChange(
      "inputMonitoring",
      this.permissions.inputMonitoring.status
    );
    return this.permissions.inputMonitoring.status;
  }

  /**
   * Check registry access permission (Windows only)
   */
  async checkRegistryAccessPermission() {
    console.log("[PermissionManager] Checking registry access permission...");
    this.permissions.registryAccess.status = "checking";
    this.emitPermissionChange("registryAccess", "checking");

    try {
      if (this.nativeAddon && this.nativeAddon.checkRegistryPermission) {
        console.log('[PermissionManager] Using native addon for registry access check');
        const hasPermission = this.nativeAddon.checkRegistryPermission();
        console.log(`[PermissionManager] Native registry access check result: ${hasPermission}`);

        this.permissions.registryAccess.status = hasPermission ? "granted" : "denied";
        this.permissions.registryAccess.error = hasPermission ? null : "Cannot access Windows registry";
      } else {
        this.permissions.registryAccess.status = "denied";
        this.permissions.registryAccess.error = "Native addon not available";
      }
    } catch (error) {
      this.permissions.registryAccess.status = "denied";
      this.permissions.registryAccess.error = error.message;
      console.error("[PermissionManager] Registry access permission error:", error.message);
    }

    console.log(`[PermissionManager] Registry access permission: ${this.permissions.registryAccess.status.toUpperCase()}`);
    this.emitPermissionChange("registryAccess", this.permissions.registryAccess.status);
    return this.permissions.registryAccess.status;
  }

  /**
   * Check device enumeration permission (Windows only)
   */
  async checkDeviceEnumerationPermission() {
    console.log("[PermissionManager] Checking device enumeration permission...");
    this.permissions.deviceEnumeration.status = "checking";
    this.emitPermissionChange("deviceEnumeration", "checking");

    try {
      if (this.nativeAddon && this.nativeAddon.checkDeviceEnumerationPermission) {
        console.log('[PermissionManager] Using native addon for device enumeration check');
        const hasPermission = this.nativeAddon.checkDeviceEnumerationPermission();
        console.log(`[PermissionManager] Native device enumeration check result: ${hasPermission}`);

        this.permissions.deviceEnumeration.status = hasPermission ? "granted" : "denied";
        this.permissions.deviceEnumeration.error = hasPermission ? null : "Cannot enumerate hardware devices";
      } else {
        this.permissions.deviceEnumeration.status = "denied";
        this.permissions.deviceEnumeration.error = "Native addon not available";
      }
    } catch (error) {
      this.permissions.deviceEnumeration.status = "denied";
      this.permissions.deviceEnumeration.error = error.message;
      console.error("[PermissionManager] Device enumeration permission error:", error.message);
    }

    console.log(`[PermissionManager] Device enumeration permission: ${this.permissions.deviceEnumeration.status.toUpperCase()}`);
    this.emitPermissionChange("deviceEnumeration", this.permissions.deviceEnumeration.status);
    return this.permissions.deviceEnumeration.status;
  }

  /**
   * Check process access permission (Windows only)
   */
  async checkProcessAccessPermission() {
    console.log("[PermissionManager] Checking process access permission...");
    this.permissions.processAccess.status = "checking";
    this.emitPermissionChange("processAccess", "checking");

    try {
      if (this.nativeAddon && this.nativeAddon.checkProcessAccessPermission) {
        console.log('[PermissionManager] Using native addon for process access check');
        const hasPermission = this.nativeAddon.checkProcessAccessPermission();
        console.log(`[PermissionManager] Native process access check result: ${hasPermission}`);

        this.permissions.processAccess.status = hasPermission ? "granted" : "denied";
        this.permissions.processAccess.error = hasPermission ? null : "Cannot access process information";
      } else {
        this.permissions.processAccess.status = "denied";
        this.permissions.processAccess.error = "Native addon not available";
      }
    } catch (error) {
      this.permissions.processAccess.status = "denied";
      this.permissions.processAccess.error = error.message;
      console.error("[PermissionManager] Process access permission error:", error.message);
    }

    console.log(`[PermissionManager] Process access permission: ${this.permissions.processAccess.status.toUpperCase()}`);
    this.emitPermissionChange("processAccess", this.permissions.processAccess.status);
    return this.permissions.processAccess.status;
  }

  /**
   * Check clipboard access permission (Windows only)
   */
  async checkClipboardAccessPermission() {
    console.log("[PermissionManager] Checking clipboard access permission...");
    this.permissions.clipboardAccess.status = "checking";
    this.emitPermissionChange("clipboardAccess", "checking");

    try {
      if (this.nativeAddon && this.nativeAddon.checkClipboardPermission) {
        console.log('[PermissionManager] Using native addon for clipboard access check');
        const hasPermission = this.nativeAddon.checkClipboardPermission();
        console.log(`[PermissionManager] Native clipboard access check result: ${hasPermission}`);

        this.permissions.clipboardAccess.status = hasPermission ? "granted" : "denied";
        this.permissions.clipboardAccess.error = hasPermission ? null : "Cannot access clipboard";
      } else {
        this.permissions.clipboardAccess.status = "denied";
        this.permissions.clipboardAccess.error = "Native addon not available";
      }
    } catch (error) {
      this.permissions.clipboardAccess.status = "denied";
      this.permissions.clipboardAccess.error = error.message;
      console.error("[PermissionManager] Clipboard access permission error:", error.message);
    }

    console.log(`[PermissionManager] Clipboard access permission: ${this.permissions.clipboardAccess.status.toUpperCase()}`);
    this.emitPermissionChange("clipboardAccess", this.permissions.clipboardAccess.status);
    return this.permissions.clipboardAccess.status;
  }

  /**
   * Request specific permission
   */
  async requestPermission(permissionType) {
    console.log(`[PermissionManager] Requesting permission: ${permissionType}`);

    switch (permissionType) {
      case "accessibility":
        return await this.requestAccessibilityPermission();
      case "screenRecording":
        return await this.requestScreenRecordingPermission();
      case "inputMonitoring":
        return await this.requestInputMonitoringPermission();
      default:
        console.error(
          `[PermissionManager] Unknown permission type: ${permissionType}`
        );
        return false;
    }
  }

  /**
   * Request accessibility permission with cross-platform support
   */
  async requestAccessibilityPermission() {
    console.log("[PermissionManager] Requesting accessibility permission...");
    const platform = os.platform();

    if (this.nativeAddon && this.nativeAddon.requestAccessibilityPermission) {
      console.log('[PermissionManager] Using native addon to request accessibility permission');
      try {
        const granted = this.nativeAddon.requestAccessibilityPermission();
        console.log(`[PermissionManager] Native accessibility request result: ${granted}`);
        
        if (granted) {
          this.permissions.accessibility.status = "granted";
          this.permissions.accessibility.error = null;
          this.emitPermissionChange("accessibility", "granted");
          return true;
        } else {
          // Permission was requested but not granted, or system preferences opened
          console.log('[PermissionManager] Accessibility permission requested, may need user action in System Preferences');
        }
      } catch (error) {
        console.error(
          "[PermissionManager] Error requesting accessibility permission:",
          error
        );
      }
    } else {
      console.log('[PermissionManager] Native addon not available, opening system settings');
    }

    // Fallback: Open system settings
    if (platform === "win32") {
      await this.openSystemPreferences("Security", "Privacy_Accessibility");
      console.log(
        "[PermissionManager] Please enable accessibility features in Windows Settings"
      );
    } else {
      await this.openSystemPreferences("Security", "Privacy_Accessibility");
      console.log(
        "[PermissionManager] Please enable accessibility permission in System Preferences > Security & Privacy > Privacy > Accessibility"
      );
    }
    return false;
  }

  /**
   * Request screen recording permission with cross-platform support
   */
  async requestScreenRecordingPermission() {
    console.log(
      "[PermissionManager] Requesting screen recording permission..."
    );
    const platform = os.platform();

    if (this.nativeAddon && this.nativeAddon.requestScreenRecordingPermission) {
      try {
        const granted = this.nativeAddon.requestScreenRecordingPermission();
        if (granted) {
          this.permissions.screenRecording.status = "granted";
          this.permissions.screenRecording.error = null;
          this.emitPermissionChange("screenRecording", "granted");
          return true;
        }
      } catch (error) {
        console.error(
          "[PermissionManager] Error requesting screen recording permission:",
          error
        );
      }
    }

    // Fallback: Open system settings
    if (platform === "win32") {
      await this.openSystemPreferences("Security", "Privacy_ScreenCapture");
      console.log(
        "[PermissionManager] Please enable camera/screen capture permissions in Windows Settings"
      );
    } else {
      await this.openSystemPreferences("Security", "Privacy_ScreenCapture");
    }
    return false;
  }

  /**
   * Request input monitoring permission with cross-platform support
   */
  async requestInputMonitoringPermission() {
    console.log(
      "[PermissionManager] Requesting input monitoring permission..."
    );
    const platform = os.platform();

    if (this.nativeAddon && this.nativeAddon.requestInputMonitoringPermission) {
      console.log('[PermissionManager] Using native addon to request input monitoring permission');
      try {
        const granted = this.nativeAddon.requestInputMonitoringPermission();
        console.log(`[PermissionManager] Native input monitoring request result: ${granted}`);
        
        if (granted) {
          this.permissions.inputMonitoring.status = "granted";
          this.permissions.inputMonitoring.error = null;
          this.emitPermissionChange("inputMonitoring", "granted");
          return true;
        } else {
          console.log('[PermissionManager] Input monitoring permission requested, may need user action in System Preferences');
        }
      } catch (error) {
        console.error(
          "[PermissionManager] Error requesting input monitoring permission:",
          error
        );
      }
    } else {
      console.log('[PermissionManager] Native addon not available, opening system settings');
    }

    // Fallback: Open system settings
    if (platform === "win32") {
      await this.openSystemPreferences("Security", "Privacy_ListenEvent");
      console.log(
        "[PermissionManager] Please enable microphone/input monitoring permissions in Windows Settings"
      );
    } else {
      await this.openSystemPreferences("Security", "Privacy_ListenEvent");
      console.log(
        "[PermissionManager] Please enable input monitoring permission in System Preferences > Security & Privacy > Privacy > Input Monitoring"
      );
    }
    return false;
  }

  /**
   * Request registry access permission (Windows-specific)
   */
  async requestRegistryPermission() {
    if (os.platform() !== 'win32') {
      console.log('[PermissionManager] Registry permission not needed on this platform');
      return true;
    }

    console.log('[PermissionManager] Requesting registry access permission...');

    if (this.nativeAddon && this.nativeAddon.requestRegistryPermission) {
      try {
        const granted = this.nativeAddon.requestRegistryPermission();
        if (granted) {
          this.permissions.registryAccess.status = 'granted';
          this.permissions.registryAccess.error = null;
          this.emitPermissionChange('registryAccess', 'granted');
          return true;
        }
      } catch (error) {
        console.error('[PermissionManager] Error requesting registry permission:', error);
        this.permissions.registryAccess.error = error.message;
      }
    }

    await this.openSystemPreferences('Security', 'Privacy_Registry');
    console.log('[PermissionManager] Please run as administrator or grant registry access');
    return false;
  }

  /**
   * Request device enumeration permission (Windows-specific)
   */
  async requestDeviceEnumerationPermission() {
    if (os.platform() !== 'win32') {
      console.log('[PermissionManager] Device enumeration permission not needed on this platform');
      return true;
    }

    console.log('[PermissionManager] Requesting device enumeration permission...');

    if (this.nativeAddon && this.nativeAddon.requestDeviceEnumerationPermission) {
      try {
        const granted = this.nativeAddon.requestDeviceEnumerationPermission();
        if (granted) {
          this.permissions.deviceEnumeration.status = 'granted';
          this.permissions.deviceEnumeration.error = null;
          this.emitPermissionChange('deviceEnumeration', 'granted');
          return true;
        }
      } catch (error) {
        console.error('[PermissionManager] Error requesting device enumeration permission:', error);
        this.permissions.deviceEnumeration.error = error.message;
      }
    }

    await this.openSystemPreferences('Security', 'Privacy_Devices');
    console.log('[PermissionManager] Please grant device access permissions in Windows Settings');
    return false;
  }

  /**
   * Request process access permission (Windows-specific)
   */
  async requestProcessAccessPermission() {
    if (os.platform() !== 'win32') {
      console.log('[PermissionManager] Process access permission not needed on this platform');
      return true;
    }

    console.log('[PermissionManager] Requesting process access permission...');

    if (this.nativeAddon && this.nativeAddon.requestProcessAccessPermission) {
      try {
        const granted = this.nativeAddon.requestProcessAccessPermission();
        if (granted) {
          this.permissions.processAccess.status = 'granted';
          this.permissions.processAccess.error = null;
          this.emitPermissionChange('processAccess', 'granted');
          return true;
        }
      } catch (error) {
        console.error('[PermissionManager] Error requesting process access permission:', error);
        this.permissions.processAccess.error = error.message;
      }
    }

    await this.openSystemPreferences('Security', 'Privacy_Process');
    console.log('[PermissionManager] Please run as administrator or grant process access');
    return false;
  }

  /**
   * Request clipboard access permission (Windows-specific)
   */
  async requestClipboardPermission() {
    if (os.platform() !== 'win32') {
      console.log('[PermissionManager] Clipboard access permission not needed on this platform');
      return true;
    }

    console.log('[PermissionManager] Requesting clipboard access permission...');

    if (this.nativeAddon && this.nativeAddon.requestClipboardPermission) {
      try {
        const granted = this.nativeAddon.requestClipboardPermission();
        if (granted) {
          this.permissions.clipboardAccess.status = 'granted';
          this.permissions.clipboardAccess.error = null;
          this.emitPermissionChange('clipboardAccess', 'granted');
          return true;
        }
      } catch (error) {
        console.error('[PermissionManager] Error requesting clipboard access permission:', error);
        this.permissions.clipboardAccess.error = error.message;
      }
    }

    await this.openSystemPreferences('Security', 'Privacy_Clipboard');
    console.log('[PermissionManager] Please grant clipboard access in Windows Settings');
    return false;
  }

  /**
   * Execute sudo command with cross-platform support
   * @deprecated Use sudoManager.executeSudoCommand instead
   */
  async executeSudoCommand(command) {
    // Wrapper for backwards compatibility - delegate to sudoManager
    console.log("[PermissionManager] executeSudoCommand delegating to sudoManager");
    try {
      return await sudoManager.executeSudoCommand(command.split(' '));
    } catch (error) {
      throw new Error(`Command execution failed: ${error.message}`);
    }
  }

  /**
   * Check if running with Windows administrator privileges
   * @deprecated Use sudoManager.checkCurrentPrivileges instead
   */
  async checkWindowsAdminPrivileges() {
    console.log("[PermissionManager] checkWindowsAdminPrivileges delegating to sudoManager");
    return await sudoManager.checkCurrentPrivileges();
  }

  /**
   * Check Windows UAC status and permissions
   */
  async checkWindowsUACStatus() {
    if (os.platform() !== "win32") return null;

    try {
      const result = await this.executeCommand(
        'powershell "Get-ItemProperty -Path \"HKLM:SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" -Name EnableLUA | Select-Object -ExpandProperty EnableLUA"'
      );
      const uacEnabled = result.trim() === "1";
      console.log(
        `[PermissionManager] Windows UAC status: ${uacEnabled ? "ENABLED" : "DISABLED"}`
      );
      return uacEnabled;
    } catch (error) {
      console.error(
        "[PermissionManager] Could not check UAC status:",
        error.message
      );
      return null;
    }
  }

  /**
   * Get Windows permission recommendations
   */
  getWindowsPermissionRecommendations() {
    if (os.platform() !== "win32") return [];

    return [
      "Run the application as Administrator for full system access",
      "Enable Windows Defender exclusions for the application directory",
      "Check Windows Privacy Settings for camera and microphone permissions",
      "Ensure Windows Security is not blocking the application",
      "Consider temporarily disabling antivirus during first run",
    ];
  }

  /**
   * Fallback methods for permission testing
   */
  async testAccessibilityFallback() {
    const platform = os.platform();

    try {
      if (platform === "win32") {
        // On Windows, try to get active window information
        const result = await this.executeCommand(
          'powershell "Get-Process | Where-Object {$_.MainWindowTitle -ne \"\"} | Select-Object -First 1 ProcessName"'
        );
        return result && result.includes("ProcessName");
      } else {
        // On macOS, try to get idle time - requires accessibility permission
        const result = await this.executeCommand(
          'system_profiler SPHardwareDataType | grep "Idle Time"'
        );
        return result && result.length > 0;
      }
    } catch {
      return false;
    }
  }

  async testScreenRecordingFallback() {
    const platform = os.platform();

    try {
      if (platform === "win32") {
        // On Windows, try to get display information
        const result = await this.executeCommand(
          "wmic desktopmonitor get Name /format:list"
        );
        return (
          result && (result.includes("Name=") || result.includes("Display"))
        );
      } else {
        // On macOS, try to get display information - requires screen recording permission
        const result = await this.executeCommand(
          "system_profiler SPDisplaysDataType | head -5"
        );
        return result && result.includes("Display");
      }
    } catch {
      return false;
    }
  }

  async testInputMonitoringFallback() {
    const platform = os.platform();

    try {
      if (platform === "win32") {
        // On Windows, try to enumerate input devices
        const result = await this.executeCommand(
          'powershell "Get-WmiObject Win32_Keyboard | Select-Object -First 1 Name"'
        );
        return result && result.includes("Name");
      } else {
        // On macOS, try to enumerate HID devices - may require input monitoring
        const result = await this.executeCommand(
          "system_profiler SPUSBDataType | grep -i keyboard"
        );
        return result && result.length > 0;
      }
    } catch {
      return false;
    }
  }

  /**
   * Execute regular command with cross-platform support
   */
  async executeCommand(command) {
    return new Promise((resolve, reject) => {
      const platform = os.platform();
      let child;

      if (platform === "win32") {
        // On Windows, use cmd for PowerShell commands or direct command execution
        if (command.startsWith("powershell ")) {
          child = spawn("cmd", ["/c", command], { shell: true });
        } else {
          child = spawn("cmd", ["/c", command], { shell: true });
        }
      } else {
        // On macOS/Linux, use bash
        child = spawn("bash", ["-c", command]);
      }

      let stdout = "";
      let stderr = "";

      child.stdout.on("data", (data) => {
        stdout += data.toString();
      });

      child.stderr.on("data", (data) => {
        stderr += data.toString();
      });

      child.on("close", (code) => {
        if (code === 0) {
          resolve(stdout.trim());
        } else {
          reject(new Error(stderr || `Command failed with code ${code}`));
        }
      });
    });
  }

  /**
   * Open system settings/preferences with cross-platform support
   */
  async openSystemPreferences(pane, subpane = null) {
    const platform = os.platform();

    try {
      if (platform === "win32") {
        // On Windows, open appropriate settings
        let command;
        if (pane === "Security" && subpane === "Privacy_Accessibility") {
          command = "ms-settings:easeofaccess";
        } else if (pane === "Security" && subpane === "Privacy_ScreenCapture") {
          command = "ms-settings:privacy-webcam";
        } else if (pane === "Security" && subpane === "Privacy_ListenEvent") {
          command = "ms-settings:privacy-microphone";
        } else {
          command = "ms-settings:privacy";
        }

        await this.executeCommand(`start ${command}`);
        console.log(`[PermissionManager] Opened Windows Settings: ${command}`);
      } else {
        // On macOS, use System Preferences
        const command = subpane
          ? `open "x-apple.systempreferences:com.apple.preference.${pane}?${subpane}"`
          : `open "x-apple.systempreferences:com.apple.preference.${pane}"`;

        await this.executeCommand(command);
        console.log(
          `[PermissionManager] Opened System Preferences: ${pane}${subpane ? "/" + subpane : ""}`
        );
      }
    } catch (error) {
      console.error(
        "[PermissionManager] Failed to open system settings:",
        error
      );
    }
  }

  /**
   * Get current permission status
   */
  getPermissionStatus() {
    const status = {
      allGranted: true,
      readyToStart: true,
      permissions: {},
    };

    for (const [key, permission] of Object.entries(this.permissions)) {
      status.permissions[key] = {
        name: permission.name,
        status: permission.status,
        required: permission.required,
        description: permission.description,
        services: permission.services,
        error: permission.error,
      };

      if (permission.required && permission.status !== "granted") {
        status.allGranted = false;
        if (permission.status !== "checking") {
          status.readyToStart = false;
        }
      }
    }

    return status;
  }

  /**
   * Check if all required permissions are granted
   */
  areAllPermissionsGranted() {
    return Object.values(this.permissions)
      .filter((p) => p.required)
      .every((p) => p.status === "granted");
  }

  /**
   * Get list of missing permissions
   */
  getMissingPermissions() {
    return Object.entries(this.permissions)
      .filter(
        ([_, permission]) =>
          permission.required && permission.status !== "granted"
      )
      .map(([key, permission]) => ({
        key,
        name: permission.name,
        status: permission.status,
        error: permission.error,
      }));
  }

  /**
   * Reset all permissions (useful for testing)
   */
  resetPermissions() {
    console.log("[PermissionManager] Resetting all permissions...");
    Object.keys(this.permissions).forEach((key) => {
      this.permissions[key].status = "unknown";
      this.permissions[key].error = null;
    });
    this.emitPermissionChange("all", "reset");
  }
}

module.exports = PermissionManager;
