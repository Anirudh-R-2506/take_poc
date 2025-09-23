const WorkerBase = require('./worker-base');

class VMDetectWorker extends WorkerBase {
    constructor() {
        super('vm-detect');
        this.isUsingVMDetector = false;
    }
    
    startNativeMode() {
        console.log(`[${this.moduleName}] Native callback-based VM detector disabled due to threading issues - using polling mode`);
        
        // Skip native callback-based startVMDetector to avoid segfaults
        this.isUsingVMDetector = false;
        this.startPollingMode();
    }
    
    startPollingMode() {
        console.log(`[${this.moduleName}] Using native API polling mode`);
        
        // Check if the native method exists
        if (!this.nativeAddon || typeof this.nativeAddon.detectVirtualMachine !== 'function') {
            console.error(`[${this.moduleName}] detectVirtualMachine method not available, falling back`);
            this.startFallbackMode();
            return;
        }
        
        console.log(`[${this.moduleName}] Starting VM detection polling with 10s interval`);
        
        // Poll VM detection every 10 seconds using direct API calls
        this.vmPollingInterval = setInterval(() => {
            if (!this.isRunning) return;
            
            try {
                console.log(`[${this.moduleName}] Attempting to detect virtual machine...`);
                const vmResult = this.nativeAddon.detectVirtualMachine();
                console.log(`[${this.moduleName}] VM detection result:`, vmResult ? 'received data' : 'no data');
                
                if (vmResult) {
                    this.sendToParent({
                        type: 'proctor-event',
                        module: this.moduleName,
                        payload: vmResult
                    });
                    console.log(`[${this.moduleName}] Sent VM detection to parent`);
                } else {
                    console.log(`[${this.moduleName}] No VM data returned`);
                }
            } catch (err) {
                console.error(`[${this.moduleName}] Error detecting virtual machine:`, err);
                // Fall back to JavaScript implementation
                this.startFallbackMode();
            }
        }, 10000); // 10 second interval
    }
    
    startFallbackMode() {
        console.log(`[${this.moduleName}] Using JavaScript VM detector fallback`);
        
        // Use the existing fallback from worker-base with module-specific data
        super.startFallbackMode();
    }
    
    stop() {
        if (this.vmPollingInterval) {
            clearInterval(this.vmPollingInterval);
            this.vmPollingInterval = null;
        }
        
        if (this.isUsingVMDetector && this.nativeAddon) {
            try {
                this.nativeAddon.stopVMDetector();
                this.isUsingVMDetector = false;
            } catch (err) {
                console.error(`[${this.moduleName}] Error stopping VM detector:`, err);
            }
        }
        
        super.stop();
    }
    
    // Minimal fallback data if VM detector fails completely
    getModuleSpecificData() {
        console.error(`[${this.moduleName}] VM detector completely failed - no native support available`);
        
        return {
            isInsideVM: false,
            detectedVM: 'Unknown',
            detectionMethod: 'unavailable',
            runningVMProcesses: [],
            vmIndicators: [],
            source: 'unavailable',
            status: 'error'
        };
    }
}

const worker = new VMDetectWorker();
worker.start();