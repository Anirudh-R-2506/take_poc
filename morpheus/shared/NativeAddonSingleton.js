const path = require('path');

class NativeAddonSingleton {
    constructor() {
        this.instance = null;
        this.isLoaded = false;
        this.loadPromise = null;
    }

    async getInstance() {
        if (this.isLoaded && this.instance) {
            return this.instance;
        }

        if (this.loadPromise) {
            return this.loadPromise;
        }

        this.loadPromise = this.loadNativeAddon();
        return this.loadPromise;
    }

    async loadNativeAddon() {
        if (this.isLoaded && this.instance) {
            return this.instance;
        }

        try {
            console.log("[NativeAddonSingleton] Loading native addon...");
            
            const addonPath = path.join(__dirname, '../native/build/Release/proctor_native');
            this.instance = require(addonPath);
            this.isLoaded = true;

            console.log("[NativeAddonSingleton] Native addon loaded successfully");
            
            // Validate that the addon has the expected methods
            const requiredMethods = [
                'checkAccessibilityPermission',
                'checkScreenRecordingPermission', 
                'checkInputMonitoringPermission',
                'getCurrentRunningProcesses',
                'getCurrentFocusIdleStatus',
                'detectRecordingAndOverlays'
            ];

            for (const method of requiredMethods) {
                if (typeof this.instance[method] !== 'function') {
                    console.warn(`[NativeAddonSingleton] Missing method: ${method}`);
                }
            }

            return this.instance;
        } catch (error) {
            console.error("[NativeAddonSingleton] Failed to load native addon:", error);
            this.isLoaded = false;
            this.instance = null;
            this.loadPromise = null;
            throw error;
        }
    }

    reset() {
        this.instance = null;
        this.isLoaded = false;
        this.loadPromise = null;
        console.log("[NativeAddonSingleton] Reset singleton");
    }

    isAvailable() {
        return this.isLoaded && this.instance !== null;
    }
}

// Export singleton instance
const nativeAddonSingleton = new NativeAddonSingleton();
module.exports = nativeAddonSingleton;