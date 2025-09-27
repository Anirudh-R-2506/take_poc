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
        console.log(`[${this.moduleName}] Using enhanced detection mode`);

        // Check if enhanced methods are available
        const hasEnhanced = this.nativeAddon &&
                           typeof this.nativeAddon.getProcessSnapshot === 'function' &&
                           typeof this.nativeAddon.detectSuspiciousBehavior === 'function';

        if (!hasEnhanced && (!this.nativeAddon || typeof this.nativeAddon.getProcessSnapshot !== 'function')) {
            console.error(`[${this.moduleName}] Process detection methods not available, falling back`);
            this.startFallbackMode();
            return;
        }

        console.log(`[${this.moduleName}] Starting enhanced process detection with 1.5s interval`);

        this.processPollingInterval = setInterval(() => {
            if (!this.isRunning) return;

            try {
                let processedData;

                if (hasEnhanced) {
                    // Use enhanced detection with threat scoring
                    const suspiciousBehavior = this.nativeAddon.detectSuspiciousBehavior();
                    const enhancedSnapshot = this.nativeAddon.getProcessSnapshot();

                    processedData = this.processEnhancedSnapshot(suspiciousBehavior, enhancedSnapshot);
                    console.log(`[${this.moduleName}] Enhanced detection: ${suspiciousBehavior.length} suspicious processes found`);
                } else {
                    // Fallback to basic detection
                    const snapshot = this.nativeAddon.getProcessSnapshot();
                    processedData = this.processSnapshot(snapshot);
                    console.log(`[${this.moduleName}] Basic detection: ${processedData.blacklisted_found ? 'blacklisted found' : 'no blacklisted'}`);
                }

                this.sendToParent({
                    type: 'proctor-event',
                    module: this.moduleName,
                    payload: processedData
                });

            } catch (err) {
                console.error(`[${this.moduleName}] Error in process detection:`, err);
                this.startFallbackMode();
            }
        }, 1500);
    }
    
    startFallbackMode() {
        console.log(`[${this.moduleName}] Using JavaScript process watcher fallback`);
        
        // Use the existing fallback from worker-base with module-specific data
        super.startFallbackMode();
    }
    
    processEnhancedSnapshot(suspiciousBehavior, enhancedSnapshot) {
        const threatLevels = {
            0: 'NONE',
            1: 'LOW',
            2: 'MEDIUM',
            3: 'HIGH',
            4: 'CRITICAL'
        };

        const categories = {
            0: 'SAFE',
            1: 'AI_TOOL',
            2: 'BROWSER',
            3: 'SCREEN_SHARING',
            4: 'REMOTE_ACCESS',
            5: 'VPN_TOOL',
            6: 'DEVELOPMENT',
            7: 'VIRTUAL_MACHINE',
            8: 'RECORDING',
            9: 'COMMUNICATION',
            10: 'OVERLAY_TOOL'
        };

        const violations = [];
        let maxThreatLevel = 0;

        // Process suspicious behavior (highest priority threats)
        if (suspiciousBehavior && Array.isArray(suspiciousBehavior)) {
            for (const process of suspiciousBehavior) {
                violations.push({
                    pid: process.pid,
                    name: process.name,
                    path: process.path,
                    threatLevel: threatLevels[process.threatLevel] || 'UNKNOWN',
                    category: categories[process.category] || 'UNKNOWN',
                    confidence: process.confidence,
                    riskReason: process.riskReason,
                    violation_type: 'SUSPICIOUS_BEHAVIOR'
                });
                maxThreatLevel = Math.max(maxThreatLevel, process.threatLevel);
            }
        }

        return {
            blacklisted_found: violations.length > 0,
            violations: violations,
            matches: violations, // Backwards compatibility
            total_processes: enhancedSnapshot ? enhancedSnapshot.length : 0,
            max_threat_level: threatLevels[maxThreatLevel],
            threat_count: {
                critical: violations.filter(v => v.threatLevel === 'CRITICAL').length,
                high: violations.filter(v => v.threatLevel === 'HIGH').length,
                medium: violations.filter(v => v.threatLevel === 'MEDIUM').length,
                low: violations.filter(v => v.threatLevel === 'LOW').length
            },
            timestamp: Date.now(),
            source: 'enhanced_native'
        };
    }

    processSnapshot(snapshot) {
        // Legacy basic detection for fallback
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

        if (snapshot && Array.isArray(snapshot)) {
            for (const process of snapshot) {
                const processName = process.name || '';
                const processPath = process.path || '';

                for (const blacklistTerm of blacklist) {
                    if (processName.toLowerCase().includes(blacklistTerm.toLowerCase()) ||
                        processPath.toLowerCase().includes(blacklistTerm.toLowerCase())) {
                        matches.push({
                            pid: process.pid,
                            name: processName,
                            path: processPath,
                            violation_type: 'BASIC_BLACKLIST'
                        });
                        break;
                    }
                }
            }
        }

        return {
            blacklisted_found: matches.length > 0,
            matches: matches,
            violations: matches,
            total_processes: snapshot ? snapshot.length : 0,
            timestamp: Date.now(),
            source: 'basic_native'
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