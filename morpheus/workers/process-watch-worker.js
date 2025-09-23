const WorkerBase = require('./worker-base');

class ProcessWatchWorker extends WorkerBase {
    constructor() {
        super('process-watch');
        this.isUsingProcessWatcher = false;
    }
    
    startNativeMode() {
        console.log(`[${this.moduleName}] Native callback-based process watcher disabled due to threading issues - using polling mode`);
        
        // Skip native callback-based startProcessWatcher to avoid segfaults
        // Use direct API polling instead
        this.isUsingProcessWatcher = false;
        this.startPollingMode();
    }
    
    startPollingMode() {
        console.log(`[${this.moduleName}] Using native API polling mode`);
        
        // Check if the native method exists
        if (!this.nativeAddon || typeof this.nativeAddon.getProcessSnapshot !== 'function') {
            console.error(`[${this.moduleName}] getProcessSnapshot method not available, falling back`);
            this.startFallbackMode();
            return;
        }
        
        console.log(`[${this.moduleName}] Starting process polling with 1.5s interval`);
        
        // Poll process snapshot every 1.5 seconds using direct API calls
        this.processPollingInterval = setInterval(() => {
            if (!this.isRunning) return;
            
            try {
                console.log(`[${this.moduleName}] Attempting to get process snapshot...`);
                const snapshot = this.nativeAddon.getProcessSnapshot();
                console.log(`[${this.moduleName}] Process snapshot result:`, snapshot ? 'received data' : 'no data');
                
                if (snapshot) {
                    // Process the snapshot to extract blacklisted processes
                    const processedData = this.processSnapshot(snapshot);
                    
                    this.sendToParent({
                        type: 'proctor-event',
                        module: this.moduleName,
                        payload: processedData
                    });
                    console.log(`[${this.moduleName}] Sent process data to parent: ${processedData.blacklisted_found ? 'blacklisted found' : 'no blacklisted'}`);
                } else {
                    console.log(`[${this.moduleName}] No process data returned`);
                }
            } catch (err) {
                console.error(`[${this.moduleName}] Error getting process snapshot:`, err);
                // Fall back to JavaScript implementation
                this.startFallbackMode();
            }
        }, 1500); // 1.5 second interval
    }
    
    startFallbackMode() {
        console.log(`[${this.moduleName}] Using JavaScript process watcher fallback`);
        
        // Use the existing fallback from worker-base with module-specific data
        super.startFallbackMode();
    }
    
    processSnapshot(snapshot) {
        // Define blacklisted process patterns (more comprehensive)
        const blacklist = [
            'chrome', 'Chrome', 'Google Chrome',
            'firefox', 'Firefox', 'Mozilla Firefox',
            'safari', 'Safari',
            'opera', 'Opera',
            'edge', 'Edge', 'Microsoft Edge',
            'brave', 'Brave',
            'tor', 'Tor'
        ];
        
        const matches = [];
        
        // Check each process against blacklist patterns
        if (snapshot && Array.isArray(snapshot)) {
            for (const process of snapshot) {
                const processName = process.name || '';
                const processPath = process.path || '';
                
                // Check if process name or path contains blacklisted terms
                for (const blacklistTerm of blacklist) {
                    if (processName.toLowerCase().includes(blacklistTerm.toLowerCase()) ||
                        processPath.toLowerCase().includes(blacklistTerm.toLowerCase())) {
                        matches.push({
                            pid: process.pid,
                            name: processName,
                            path: processPath
                        });
                        break; // Don't add same process multiple times
                    }
                }
            }
        }
        
        return {
            blacklisted_found: matches.length > 0,
            matches: matches,
            total_processes: snapshot ? snapshot.length : 0,
            timestamp: Date.now(),
            source: 'native'
        };
    }
    
    stop() {
        if (this.processPollingInterval) {
            clearInterval(this.processPollingInterval);
            this.processPollingInterval = null;
        }
        
        if (this.isUsingProcessWatcher && this.nativeAddon) {
            try {
                this.nativeAddon.stopProcessWatcher();
                this.isUsingProcessWatcher = false;
            } catch (err) {
                console.error(`[${this.moduleName}] Error stopping process watcher:`, err);
            }
        }
        
        super.stop();
    }
    
    // Minimal fallback data if process watcher fails completely
    getModuleSpecificData() {
        console.error(`[${this.moduleName}] Process watcher completely failed - no native support available`);
        
        return {
            blacklisted_found: false,
            matches: [],
            source: 'unavailable',
            status: 'error'
        };
    }
}

const worker = new ProcessWatchWorker();
worker.start();