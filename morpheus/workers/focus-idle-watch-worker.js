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
        console.log(`[${this.moduleName}] Using enhanced dual-detection mode (native + real-time)`);

        // Check if native methods exist
        const hasBasicFocus = this.nativeAddon && typeof this.nativeAddon.getCurrentFocusIdleStatus === 'function';
        const hasRealtimeFocus = this.nativeAddon && typeof this.nativeAddon.getRealtimeFocusStatus === 'function';
        const hasRealtimeMonitor = this.nativeAddon && typeof this.nativeAddon.startRealtimeWindowMonitor === 'function';

        if (!hasBasicFocus) {
            console.error(`[${this.moduleName}] getCurrentFocusIdleStatus method not available, falling back`);
            this.startFallbackMode();
            return;
        }

        console.log(`[${this.moduleName}] Dual detection capabilities - Basic: ${hasBasicFocus}, Realtime: ${hasRealtimeFocus}, Monitor: ${hasRealtimeMonitor}`);

        // Start real-time window monitoring if available
        if (hasRealtimeMonitor) {
            try {
                console.log(`[${this.moduleName}] Starting real-time window monitoring...`);
                this.nativeAddon.startRealtimeWindowMonitor();
                console.log(`[${this.moduleName}] ✓ Real-time window monitoring started`);
            } catch (err) {
                console.error(`[${this.moduleName}] Failed to start real-time monitoring:`, err);
            }
        }

        console.log(`[${this.moduleName}] Starting enhanced focus/idle polling with 500ms interval`);

        // Enhanced polling with dual detection
        this.focusIdlePollingInterval = setInterval(() => {
            if (!this.isRunning) return;

            try {
                // Primary detection: Standard focus/idle status
                const basicStatus = this.nativeAddon.getCurrentFocusIdleStatus();

                // Secondary detection: Real-time focus status if available
                let realtimeStatus = null;
                if (hasRealtimeFocus) {
                    try {
                        realtimeStatus = this.nativeAddon.getRealtimeFocusStatus();
                    } catch (err) {
                        console.log(`[${this.moduleName}] Real-time focus detection unavailable:`, err.message);
                    }
                }

                // Process and combine detection results
                const combinedStatus = this.processDualDetection(basicStatus, realtimeStatus);

                if (combinedStatus) {
                    this.sendToParent({
                        type: 'proctor-event',
                        module: this.moduleName,
                        payload: combinedStatus
                    });

                    // Log violations for debugging
                    if (combinedStatus.eventType === 'focus-lost' ||
                        combinedStatus.eventType === 'window-switch-violation' ||
                        combinedStatus.eventType === 'rapid-window-switching') {
                        console.log(`[${this.moduleName}] 🚨 VIOLATION DETECTED: ${combinedStatus.eventType} - App: ${combinedStatus.details?.activeApp || 'Unknown'}`);
                    }
                }

            } catch (err) {
                console.error(`[${this.moduleName}] Error in enhanced focus detection:`, err);
                this.startFallbackMode();
            }
        }, 500); // Faster polling for better detection
    }

    processDualDetection(basicStatus, realtimeStatus) {
        // Prioritize real-time violations over basic status
        if (realtimeStatus && (
            realtimeStatus.eventType === 'realtime-focus-lost' ||
            realtimeStatus.eventType === 'window-switch-violation' ||
            realtimeStatus.eventType === 'rapid-window-switching'
        )) {
            console.log(`[${this.moduleName}] Real-time violation detected: ${realtimeStatus.eventType}`);
            return {
                ...realtimeStatus,
                detection_mode: 'dual',
                primary_source: 'realtime-native',
                backup_source: 'native'
            };
        }

        // Use basic status as primary source
        if (basicStatus) {
            const enhanced = {
                ...basicStatus,
                detection_mode: 'dual',
                primary_source: 'native'
            };

            // Add real-time context if available
            if (realtimeStatus && realtimeStatus.details) {
                enhanced.realtime_context = {
                    activeApp: realtimeStatus.details.activeApp,
                    windowTitle: realtimeStatus.details.windowTitle,
                    reason: realtimeStatus.details.reason
                };
                enhanced.backup_source = 'realtime-native';
            }

            return enhanced;
        }

        return null;
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

        // Stop real-time window monitoring if available
        if (this.nativeAddon && typeof this.nativeAddon.stopRealtimeWindowMonitor === 'function') {
            try {
                console.log(`[${this.moduleName}] Stopping real-time window monitoring...`);
                this.nativeAddon.stopRealtimeWindowMonitor();
                console.log(`[${this.moduleName}] ✓ Real-time window monitoring stopped`);
            } catch (err) {
                console.error(`[${this.moduleName}] Error stopping real-time monitoring:`, err);
            }
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