const WorkerBase = require('./worker-base');

class ScreenWatchWorker extends WorkerBase {
    constructor() {
        super('screen-watch');
        this.isUsingScreenWatcher = false;
    }
    
    startNativeMode() {
        console.log(`[${this.moduleName}] Native screen watcher temporarily disabled due to threading issues - using fallback mode`);
        
        // Skip native startScreenWatcher call entirely to avoid SIGSEGV
        // The threading callback mechanism is unsafe and causes segfaults
        this.isUsingScreenWatcher = false;
        this.startFallbackMode();
        
        // Add recording detection using direct API calls instead of callback-based approach
        this.startRecordingDetection();
    }
    
    startRecordingDetection() {
        // Check for recording/overlays every 5 seconds
        this.recordingCheckInterval = setInterval(() => {
            if (!this.isRunning) return;
            
            try {
                const recordingResult = this.nativeAddon.detectRecordingAndOverlays();
                
                // Only send events if something interesting happened
                if (recordingResult.eventType !== 'heartbeat') {
                    this.sendToParent({
                        type: 'proctor-event',
                        module: 'recorder-overlay-watch',
                        payload: recordingResult
                    });
                }
            } catch (err) {
                console.error(`[${this.moduleName}] Error detecting recording/overlays:`, err);
            }
        }, 5000); // 5 second interval
    }
    
    startFallbackMode() {
        console.log(`[${this.moduleName}] Using JavaScript screen fallback with native API polling`);
        
        // Add screen status detection using direct API calls (safe without callbacks)
        this.screenStatusInterval = setInterval(() => {
            if (!this.isRunning) return;
            
            try {
                const screenStatus = this.nativeAddon.getCurrentScreenStatus();
                
                if (screenStatus) {
                    this.sendToParent({
                        type: 'proctor-event',
                        module: this.moduleName,
                        payload: screenStatus
                    });
                }
            } catch (err) {
                console.error(`[${this.moduleName}] Error getting screen status:`, err);
                // Fall back to basic JS monitoring
                super.startFallbackMode();
            }
        }, 3000); // 3 second interval
    }
    
    stop() {
        if (this.recordingCheckInterval) {
            clearInterval(this.recordingCheckInterval);
            this.recordingCheckInterval = null;
        }
        
        if (this.screenStatusInterval) {
            clearInterval(this.screenStatusInterval);
            this.screenStatusInterval = null;
        }
        
        if (this.isUsingScreenWatcher && this.nativeAddon) {
            try {
                this.nativeAddon.stopScreenWatcher();
                this.isUsingScreenWatcher = false;
            } catch (err) {
                console.error(`[${this.moduleName}] Error stopping screen watcher:`, err);
            }
        }
        
        super.stop();
    }
    
    // Minimal fallback data if screen watcher fails completely
    getModuleSpecificData() {
        console.error(`[${this.moduleName}] Screen watcher completely failed - no native support available`);
        
        return {
            mirroring: false,
            splitScreen: false,
            displays: ['Built-in Display'],
            externalDisplays: [],
            externalKeyboards: [],
            externalDevices: [],
            source: 'unavailable',
            platform: process.platform,
            count: 0,
            status: 'error'
        };
    }
}

const worker = new ScreenWatchWorker();
worker.start();