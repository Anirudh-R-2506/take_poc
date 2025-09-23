const WorkerBase = require('./worker-base');

class FocusIdleWatchWorker extends WorkerBase {
    constructor() {
        super('focus-idle-watch');
        this.isUsingFocusIdleWatcher = false;
    }
    
    startNativeMode() {
        console.log(`[${this.moduleName}] Native callback-based focus/idle watcher disabled due to threading issues - using polling mode`);
        
        // Skip native callback-based startFocusIdleWatcher to avoid segfaults
        this.isUsingFocusIdleWatcher = false;
        this.startPollingMode();
    }
    
    startPollingMode() {
        console.log(`[${this.moduleName}] Using native API polling mode`);
        
        // Check if the native method exists
        if (!this.nativeAddon || typeof this.nativeAddon.getCurrentFocusIdleStatus !== 'function') {
            console.error(`[${this.moduleName}] getCurrentFocusIdleStatus method not available, falling back`);
            this.startFallbackMode();
            return;
        }
        
        console.log(`[${this.moduleName}] Starting focus/idle polling with 1s interval`);
        
        // Poll focus/idle status every 1 second using direct API calls
        this.focusIdlePollingInterval = setInterval(() => {
            if (!this.isRunning) return;
            
            try {
                console.log(`[${this.moduleName}] Attempting to get focus/idle status...`);
                const focusIdleStatus = this.nativeAddon.getCurrentFocusIdleStatus();
                console.log(`[${this.moduleName}] Focus/idle result:`, focusIdleStatus ? `event: ${focusIdleStatus.eventType}` : 'no data');
                
                if (focusIdleStatus) {
                    // Always send data to keep UI updated with current status
                    this.sendToParent({
                        type: 'proctor-event',
                        module: this.moduleName,
                        payload: focusIdleStatus
                    });
                    console.log(`[${this.moduleName}] Sent focus/idle data to parent: ${focusIdleStatus.eventType}`);
                } else {
                    console.log(`[${this.moduleName}] No focus/idle data returned`);
                }
            } catch (err) {
                console.error(`[${this.moduleName}] Error getting focus/idle status:`, err);
                // Fall back to JavaScript implementation
                this.startFallbackMode();
            }
        }, 1000); // 1 second interval
    }
    
    startFallbackMode() {
        console.log(`[${this.moduleName}] Using JavaScript focus/idle watcher fallback`);
        
        // Use the existing fallback from worker-base with module-specific data
        super.startFallbackMode();
    }
    
    stop() {
        if (this.focusIdlePollingInterval) {
            clearInterval(this.focusIdlePollingInterval);
            this.focusIdlePollingInterval = null;
        }
        
        if (this.isUsingFocusIdleWatcher && this.nativeAddon) {
            try {
                this.nativeAddon.stopFocusIdleWatcher();
                this.isUsingFocusIdleWatcher = false;
            } catch (err) {
                console.error(`[${this.moduleName}] Error stopping focus/idle watcher:`, err);
            }
        }
        
        super.stop();
    }
    
    // Minimal fallback data if focus/idle watcher fails completely
    getModuleSpecificData() {
        console.error(`[${this.moduleName}] Focus/idle watcher completely failed - no native support available`);
        
        return {
            eventType: 'heartbeat',
            details: {},
            source: 'unavailable',
            status: 'error'
        };
    }
}

const worker = new FocusIdleWatchWorker();
worker.start();