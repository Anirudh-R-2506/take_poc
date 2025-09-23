const WorkerBase = require('./worker-base');

class BluetoothWatchWorker extends WorkerBase {
    constructor() {
        super('bt-watch');
        this.isUsingBluetoothWatcher = false;
    }
    
    startNativeMode() {
        console.log(`[${this.moduleName}] Using native Bluetooth implementation with polling`);
        
        // Use native implementation with polling to avoid threading issues
        this.startPollingMode();
    }
    
    startPollingMode() {
        console.log(`[${this.moduleName}] Starting native Bluetooth polling with 3s interval`);
        
        // Check if the native method exists
        if (!this.nativeAddon || typeof this.nativeAddon.getBluetoothStatus !== 'function') {
            console.error(`[${this.moduleName}] getBluetoothStatus method not available, falling back`);
            this.startFallbackMode();
            return;
        }
        
        // Poll Bluetooth status every 3 seconds using native implementation
        this.bluetoothPollingInterval = setInterval(() => {
            if (!this.isRunning) return;
            
            try {
                console.log(`[${this.moduleName}] Attempting to get Bluetooth status...`);
                const bluetoothResult = this.nativeAddon.getBluetoothStatus();
                console.log(`[${this.moduleName}] Bluetooth result:`, bluetoothResult ? 'received data' : 'no data');
                
                if (bluetoothResult) {
                    const bluetoothData = JSON.parse(bluetoothResult);
                    
                    this.sendToParent({
                        type: 'proctor-event',
                        module: this.moduleName,
                        payload: {
                            enabled: bluetoothData.enabled,
                            devices: bluetoothData.devices ? bluetoothData.devices.map(d => d.name).filter(Boolean) : [],
                            connectedDevices: bluetoothData.devices ? bluetoothData.devices.filter(d => d.connected).map(d => d.name) : [],
                            timestamp: Date.now(),
                            count: this.counter++,
                            source: 'native',
                            platform: process.platform,
                            error: bluetoothData.error || null
                        }
                    });
                    console.log(`[${this.moduleName}] Sent Bluetooth status to parent`);
                } else {
                    console.log(`[${this.moduleName}] No Bluetooth data returned`);
                }
            } catch (err) {
                console.error(`[${this.moduleName}] Error getting Bluetooth status:`, err);
                // Fall back to JavaScript implementation
                this.startFallbackMode();
            }
        }, 3000); // 3 second interval
    }
    
    startFallbackMode() {
        console.log(`[${this.moduleName}] Using JavaScript Bluetooth fallback`);
        
        // Use the existing fallback from worker-base with module-specific data
        super.startFallbackMode();
    }
    
    stop() {
        if (this.bluetoothPollingInterval) {
            clearInterval(this.bluetoothPollingInterval);
            this.bluetoothPollingInterval = null;
        }
        
        if (this.isUsingBluetoothWatcher && this.nativeAddon) {
            try {
                this.nativeAddon.stopBluetoothWatcher();
                this.isUsingBluetoothWatcher = false;
            } catch (err) {
                console.error(`[${this.moduleName}] Error stopping Bluetooth watcher:`, err);
            }
        }
        
        super.stop();
    }
    
    // Minimal fallback data if Bluetooth watcher fails completely
    getModuleSpecificData() {
        console.error(`[${this.moduleName}] Bluetooth watcher completely failed - no native support available`);
        
        return {
            enabled: false,
            devices: [],
            source: 'unavailable',
            platform: process.platform,
            count: 0,
            status: 'error'
        };
    }
}

const worker = new BluetoothWatchWorker();
worker.start();