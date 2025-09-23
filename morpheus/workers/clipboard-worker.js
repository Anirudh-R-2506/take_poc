const WorkerBase = require('./worker-base');

class ClipboardWorker extends WorkerBase {
    constructor() {
        super('clipboard-worker');
        this.isUsingClipboardWatcher = false;
        this.privacyMode = 2; // 0 = METADATA_ONLY, 1 = REDACTED, 2 = FULL
        this.lastClipboardHash = null; // Track clipboard changes
        this.lastFormats = null; // Track format changes
    }
    
    startNativeMode() {
        console.log(`[${this.moduleName}] Native callback-based clipboard watcher disabled due to threading issues - using polling mode`);
        
        // Use polling mode instead of callbacks to avoid threading issues
        this.startPollingMode();
    }
    
    startPollingMode() {
        console.log(`[${this.moduleName}] Using native API polling mode`);
        
        // Check if the native method exists
        if (!this.nativeAddon || typeof this.nativeAddon.getClipboardSnapshot !== 'function') {
            console.error(`[${this.moduleName}] getClipboardSnapshot method not available, falling back`);
            this.startFallbackMode();
            return;
        }
        
        console.log(`[${this.moduleName}] Starting clipboard polling with 2s interval`);

        // Set privacy mode to FULL to capture clipboard content
        if (typeof this.nativeAddon.setClipboardPrivacyMode === 'function') {
            this.nativeAddon.setClipboardPrivacyMode(this.privacyMode);
            console.log(`[${this.moduleName}] Set privacy mode to ${this.privacyMode} (FULL)`);
        }

        // Poll clipboard status every 2 seconds using direct API calls
        this.clipboardPollingInterval = setInterval(() => {
            if (!this.isRunning) return;
            
            try {
                console.log(`[${this.moduleName}] Attempting to get clipboard snapshot...`);
                const clipboardSnapshot = this.nativeAddon.getClipboardSnapshot();
                console.log(`[${this.moduleName}] Clipboard result:`, clipboardSnapshot ? 'received data' : 'no data');
                
                if (clipboardSnapshot) {
                    // Detect clipboard changes by comparing formats or timestamp
                    const currentFormats = JSON.stringify(clipboardSnapshot.clipFormats || []);
                    const currentHash = clipboardSnapshot.contentHash;
                    const currentTimestamp = clipboardSnapshot.timestamp;

                    let eventType = 'heartbeat';
                    let hasChanged = false;

                    // Check for actual changes
                    if (this.lastFormats !== currentFormats) {
                        console.log(`[${this.moduleName}] Clipboard formats changed`);
                        hasChanged = true;
                    }

                    if (currentHash && this.lastClipboardHash !== currentHash) {
                        console.log(`[${this.moduleName}] Clipboard content hash changed`);
                        hasChanged = true;
                    }

                    // Even in METADATA_ONLY mode, if content preview exists, it means something was copied
                    if (clipboardSnapshot.contentPreview && clipboardSnapshot.contentPreview.length > 0) {
                        console.log(`[${this.moduleName}] Clipboard has content preview`);
                        hasChanged = true;
                    }

                    if (hasChanged) {
                        eventType = 'clipboard-changed';
                        this.lastFormats = currentFormats;
                        this.lastClipboardHash = currentHash;
                        console.log(`[${this.moduleName}] Clipboard change detected!`);
                    }

                    this.sendToParent({
                        type: 'proctor-event',
                        module: this.moduleName,
                        payload: {
                            ...clipboardSnapshot,
                            eventType: eventType,
                            module: this.moduleName,
                            timestamp: Date.now(),
                            count: this.counter++,
                            source: 'native',
                            privacyMode: this.privacyMode,
                            hasChanged: hasChanged
                        }
                    });
                    console.log(`[${this.moduleName}] Sent clipboard data to parent: ${eventType}`);
                } else {
                    console.log(`[${this.moduleName}] No clipboard data returned`);
                }
            } catch (err) {
                console.error(`[${this.moduleName}] Error getting clipboard snapshot:`, err);
                // Fall back to JavaScript implementation
                this.startFallbackMode();
            }
        }, 2000); // 2 second interval
    }
    
    startFallbackMode() {
        console.log(`[${this.moduleName}] Using JavaScript clipboard watcher fallback`);
        
        // Use the existing fallback from worker-base with module-specific data
        super.startFallbackMode();
    }
    
    stop() {
        if (this.clipboardPollingInterval) {
            clearInterval(this.clipboardPollingInterval);
            this.clipboardPollingInterval = null;
        }
        
        if (this.isUsingClipboardWatcher && this.nativeAddon) {
            try {
                this.nativeAddon.stopClipboardWatcher();
                this.isUsingClipboardWatcher = false;
            } catch (err) {
                console.error(`[${this.moduleName}] Error stopping clipboard watcher:`, err);
            }
        }
        
        super.stop();
    }
    
    // Handle control messages from supervisor
    handleControlMessage(message) {
        super.handleControlMessage(message);
        
        switch (message.cmd) {
            case 'setPrivacyMode':
                this.setPrivacyMode(message.mode);
                break;
            case 'snapshot':
                this.getSnapshot();
                break;
            default:
                console.warn(`[${this.moduleName}] Unknown control command:`, message.cmd);
        }
    }
    
    setPrivacyMode(mode) {
        // Privacy modes: 'METADATA_ONLY', 'REDACTED', 'FULL'
        const modeMap = {
            'METADATA_ONLY': 0,
            'REDACTED': 1,
            'FULL': 2
        };
        
        const numericMode = typeof mode === 'string' ? modeMap[mode] : mode;
        
        if (numericMode !== undefined && numericMode !== this.privacyMode) {
            this.privacyMode = numericMode;
            console.log(`[${this.moduleName}] Privacy mode changed to:`, mode, `(${numericMode})`);
            
            if (this.nativeAddon && this.nativeAddon.setClipboardPrivacyMode) {
                this.nativeAddon.setClipboardPrivacyMode(numericMode);
            }
        }
    }
    
    getSnapshot() {
        if (this.nativeAddon && this.nativeAddon.getClipboardSnapshot) {
            try {
                const snapshot = this.nativeAddon.getClipboardSnapshot();
                
                this.sendToParent({
                    type: 'proctor-event',
                    module: this.moduleName,
                    payload: {
                        ...snapshot,
                        eventType: 'snapshot',
                        module: 'clipboard-watch',
                        ts: Date.now(),
                        count: this.counter,
                        source: 'native'
                    }
                });
            } catch (err) {
                console.error(`[${this.moduleName}] Error getting clipboard snapshot:`, err);
            }
        } else {
            console.warn(`[${this.moduleName}] Clipboard snapshot not available`);
        }
    }
    
    // Minimal fallback data if clipboard watcher fails completely
    getModuleSpecificData() {
        console.error(`[${this.moduleName}] Clipboard watcher completely failed - no native support available`);
        
        return {
            eventType: 'heartbeat',
            sourceApp: null,
            pid: null,
            clipFormats: [],
            contentPreview: null,
            contentHash: null,
            isSensitive: false,
            privacyMode: this.privacyMode,
            source: 'unavailable',
            status: 'error'
        };
    }
}

const worker = new ClipboardWorker();
worker.start();