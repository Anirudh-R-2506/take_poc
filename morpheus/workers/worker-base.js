const path = require('path');
const nativeAddonSingleton = require('../shared/NativeAddonSingleton');

class WorkerBase {
    constructor(moduleName) {
        this.moduleName = moduleName;
        this.isRunning = false;
        this.nativeAddon = null;
        this.fallbackInterval = null;
        this.heartbeatInterval = null;
        this.counter = 0;
        this.addonLoadPromise = null;
        
        this.loadNativeAddon();
        this.setupIPC();
        this.startHeartbeat();
    }
    
    async loadNativeAddon() {
        if (this.addonLoadPromise) {
            return this.addonLoadPromise;
        }

        this.addonLoadPromise = this._loadAddonInternal();
        return this.addonLoadPromise;
    }

    async _loadAddonInternal() {
        try {
            console.log(`[${this.moduleName}] Loading native addon via singleton...`);
            this.nativeAddon = await nativeAddonSingleton.getInstance();
            console.log(`[${this.moduleName}] Native addon loaded via singleton`);
            return this.nativeAddon;
        } catch (err) {
            console.warn(`[${this.moduleName}] Native addon not available, using JS fallback:`, err.message);
            this.nativeAddon = null;
            return null;
        }
    }
    
    setupIPC() {
        process.on('message', (message) => {
            if (message && message.cmd === 'stop') {
                this.stop();
                process.exit(0);
            }
        });
        
        process.on('SIGTERM', () => {
            this.stop();
            process.exit(0);
        });
        
        process.on('SIGINT', () => {
            this.stop();
            process.exit(0);
        });
    }
    
    startHeartbeat() {
        this.heartbeatInterval = setInterval(() => {
            this.sendToParent({
                type: 'heartbeat',
                module: this.moduleName,
                timestamp: Date.now(),
                pid: process.pid
            });
        }, 5000); // Every 5 seconds
    }
    
    async start() {
        if (this.isRunning) {
            console.warn(`[${this.moduleName}] Already running`);
            return;
        }
        
        console.log(`[${this.moduleName}] Starting worker`);
        
        // Wait for native addon to be loaded
        await this.loadNativeAddon();
        
        this.isRunning = true;
        
        if (this.nativeAddon) {
            await this.startNativeMode();
        } else {
            this.startFallbackMode();
        }
    }
    
    async startNativeMode() {
        console.log(`[${this.moduleName}] Using native addon mode`);
        this.nativeAddon.start((jsonData) => {
            if (!this.isRunning) return;
            
            try {
                const payload = JSON.parse(jsonData);
                payload.module = this.moduleName;
                payload.source = 'native';
                
                this.sendToParent({
                    type: 'proctor-event',
                    module: this.moduleName,
                    payload: payload
                });
            } catch (err) {
                console.error(`[${this.moduleName}] Error parsing native data:`, err);
            }
        });
    }
    
    startFallbackMode() {
        console.error(`[${this.moduleName}] Native addon unavailable - worker functionality limited`);
        this.fallbackInterval = setInterval(() => {
            if (!this.isRunning) return;
            
            this.counter++;
            const payload = {
                module: this.moduleName,
                ts: Math.floor(Date.now() / 1000),
                count: this.counter,
                source: 'fallback',
                status: 'limited',
                // Add module-specific minimal data
                ...this.getModuleSpecificData()
            };
            
            this.sendToParent({
                type: 'proctor-event',
                module: this.moduleName,
                payload: payload
            });
        }, 10000); // Every 10 seconds (less frequent for error states)
    }
    
    stop() {
        if (!this.isRunning) return;
        
        console.log(`[${this.moduleName}] Stopping worker`);
        this.isRunning = false;
        
        if (this.nativeAddon) {
            try {
                this.nativeAddon.stop();
            } catch (err) {
                console.error(`[${this.moduleName}] Error stopping native addon:`, err);
            }
        }
        
        if (this.fallbackInterval) {
            clearInterval(this.fallbackInterval);
            this.fallbackInterval = null;
        }
        
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
            this.heartbeatInterval = null;
        }
    }
    
    sendToParent(message) {
        if (process.send) {
            process.send(message);
        }
    }
    
    // Override this method in specific workers to provide module-specific minimal error data
    getModuleSpecificData() {
        return {
            status: 'error',
            message: 'Native addon unavailable'
        };
    }
}

module.exports = WorkerBase;