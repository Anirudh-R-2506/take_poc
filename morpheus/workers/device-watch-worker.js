const WorkerBase = require('./worker-base');

class DeviceWatchWorker extends WorkerBase {
    constructor() {
        super('device-watch');
        this.isUsingDeviceWatcher = false;
    }
    
    startNativeMode() {
        console.log(`[${this.moduleName}] Native callback-based device watcher disabled due to threading issues - using polling mode`);
        
        // Skip native callback-based startDeviceWatcher to avoid segfaults
        this.isUsingDeviceWatcher = false;
        this.startPollingMode();
    }
    
    startPollingMode() {
        console.log(`[${this.moduleName}] Using native API polling mode`);
        
        // Check if the native method exists
        if (!this.nativeAddon || typeof this.nativeAddon.getConnectedDevices !== 'function') {
            console.error(`[${this.moduleName}] getConnectedDevices method not available, falling back`);
            this.startFallbackMode();
            return;
        }
        
        console.log(`[${this.moduleName}] Starting device polling with 2s interval`);
        
        // Poll connected devices every 2 seconds using direct API calls
        this.devicePollingInterval = setInterval(() => {
            if (!this.isRunning) return;
            
            try {
                console.log(`[${this.moduleName}] Attempting to get connected devices...`);
                const devices = this.nativeAddon.getConnectedDevices();
                console.log(`[${this.moduleName}] Device result:`, devices ? 'received data' : 'no data');
                
                if (devices) {
                    this.sendToParent({
                        type: 'proctor-event',
                        module: this.moduleName,
                        payload: devices
                    });
                    console.log(`[${this.moduleName}] Sent device data to parent`);
                } else {
                    console.log(`[${this.moduleName}] No device data returned`);
                }
            } catch (err) {
                console.error(`[${this.moduleName}] Error getting connected devices:`, err);
                // Fall back to JavaScript implementation
                this.startFallbackMode();
            }
        }, 2000); // 2 second interval
    }
    
    startFallbackMode() {
        console.log(`[${this.moduleName}] Using JavaScript device watcher fallback`);
        
        // Use the existing fallback from worker-base with module-specific data
        super.startFallbackMode();
    }
    
    stop() {
        if (this.devicePollingInterval) {
            clearInterval(this.devicePollingInterval);
            this.devicePollingInterval = null;
        }
        
        if (this.isUsingDeviceWatcher && this.nativeAddon) {
            try {
                this.nativeAddon.stopDeviceWatcher();
                this.isUsingDeviceWatcher = false;
            } catch (err) {
                console.error(`[${this.moduleName}] Error stopping device watcher:`, err);
            }
        }
        
        super.stop();
    }
    
    // Minimal fallback data if device watcher fails completely
    getModuleSpecificData() {
        console.error(`[${this.moduleName}] Device watcher completely failed - no native support available`);
        
        return {
            event: 'heartbeat',
            devices: [],
            source: 'unavailable',
            status: 'error'
        };
    }
    
    // Uses the main native addon (same as ProcessWatch)
    // No need to override loadNativeAddon
}

const worker = new DeviceWatchWorker();
worker.start();