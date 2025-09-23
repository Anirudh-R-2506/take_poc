const { execSync, spawn } = require('child_process');

let nativeAddon = null;

try {
    nativeAddon = require('./build/Release/proctor_native');
    console.log('[ProctorNative] Native addon loaded successfully');
} catch (err) {
    console.warn('[ProctorNative] Failed to load native addon, will use JS fallback:', err.message);
}

class JSProcessWatcher {
    constructor() {
        this.running = false;
        this.counter = 0;
        this.callback = null;
        this.interval = null;
        this.blacklist = ['chrome', 'chrome.exe', 'Google Chrome'];
        this.intervalMs = 1500;
        this.lastDetectionState = false;
    }
    
    start(callback, options = {}) {
        if (this.running) {
            return false;
        }
        
        this.running = true;
        this.callback = callback;
        this.intervalMs = options.intervalMs || 1500;
        this.blacklist = options.blacklist || this.blacklist;
        
        this.interval = setInterval(() => {
            if (!this.running) return;
            
            this.checkProcesses();
        }, this.intervalMs);
        
        return true;
    }
    
    stop() {
        this.running = false;
        if (this.interval) {
            clearInterval(this.interval);
            this.interval = null;
        }
        this.callback = null;
    }
    
    async checkProcesses() {
        try {
            const processes = await this.getRunningProcesses();
            const blacklisted = this.filterBlacklistedProcesses(processes);
            const currentState = blacklisted.length > 0;
            
            // Only emit if state changed
            if (currentState !== this.lastDetectionState) {
                this.emitDetectionEvent(currentState, blacklisted);
                this.lastDetectionState = currentState;
            }
            
            this.counter++;
        } catch (err) {
            console.error('[JSProcessWatcher] Error checking processes:', err.message);
        }
    }
    
    async getRunningProcesses() {
        const processes = [];
        
        try {
            if (process.platform === 'darwin') {
                // macOS: use ps command
                const output = execSync('ps -axo pid,comm', { encoding: 'utf8' });
                const lines = output.split('\n').slice(1); // Skip header
                
                for (const line of lines) {
                    const trimmed = line.trim();
                    if (!trimmed) continue;
                    
                    const parts = trimmed.split(/\s+/);
                    if (parts.length >= 2) {
                        const pid = parseInt(parts[0]);
                        const name = parts.slice(1).join(' ');
                        
                        if (!isNaN(pid) && name) {
                            processes.push({ pid, name, path: name });
                        }
                    }
                }
            } else if (process.platform === 'win32') {
                // Windows: use tasklist command
                const output = execSync('tasklist /fo csv /nh', { encoding: 'utf8' });
                const lines = output.split('\n');
                
                for (const line of lines) {
                    if (!line.trim()) continue;
                    
                    const parts = line.split(',').map(part => part.replace(/"/g, ''));
                    if (parts.length >= 2) {
                        const name = parts[0];
                        const pid = parseInt(parts[1]);
                        
                        if (!isNaN(pid) && name) {
                            processes.push({ pid, name, path: name });
                        }
                    }
                }
            }
        } catch (err) {
            console.error('[JSProcessWatcher] Error getting processes:', err.message);
        }
        
        return processes;
    }
    
    filterBlacklistedProcesses(processes) {
        return processes.filter(proc => {
            return this.blacklist.some(blacklistItem => 
                proc.name.toLowerCase().includes(blacklistItem.toLowerCase()) ||
                proc.path.toLowerCase().includes(blacklistItem.toLowerCase())
            );
        });
    }
    
    emitDetectionEvent(detected, blacklistedProcesses) {
        const eventData = {
            module: 'process-watch',
            blacklisted_found: detected,
            matches: blacklistedProcesses.map(proc => ({
                pid: proc.pid,
                name: proc.name,
                path: proc.path
            })),
            ts: Date.now(),
            count: this.counter,
            source: 'fallback'
        };
        
        if (this.callback) {
            this.callback(JSON.stringify(eventData));
        }
    }
}

const fallbackWatcher = new JSProcessWatcher();

// Device watcher fallback removed - redundant

// Native Bluetooth implementation now available directly through addon

module.exports = {
    // Process watcher specific functions
    startProcessWatcher: (callback, options) => {
        if (nativeAddon && nativeAddon.startProcessWatcher) {
            return nativeAddon.startProcessWatcher(callback, options);
        } else {
            return fallbackWatcher.start(callback, options);
        }
    },
    
    stopProcessWatcher: () => {
        if (nativeAddon && nativeAddon.stopProcessWatcher) {
            return nativeAddon.stopProcessWatcher();
        } else {
            return fallbackWatcher.stop();
        }
    },
    
    getProcessSnapshot: () => {
        if (nativeAddon && nativeAddon.getProcessSnapshot) {
            return nativeAddon.getProcessSnapshot();
        } else {
            return null;
        }
    },
    
    // Device watcher specific functions
    startDeviceWatcher: (callback, options) => {
        if (nativeAddon && nativeAddon.startDeviceWatcher) {
            return nativeAddon.startDeviceWatcher(callback, options);
        } else {
            console.warn('[ProctorNative] Device watcher not available, no fallback implemented');
            return false;
        }
    },
    
    stopDeviceWatcher: () => {
        if (nativeAddon && nativeAddon.stopDeviceWatcher) {
            return nativeAddon.stopDeviceWatcher();
        } else {
            return null;
        }
    },
    
    getConnectedDevices: () => {
        if (nativeAddon && nativeAddon.getConnectedDevices) {
            return nativeAddon.getConnectedDevices();
        } else {
            return [];
        }
    },
    
    // Screen watcher specific functions
    startScreenWatcher: (callback, options) => {
        if (nativeAddon && nativeAddon.startScreenWatcher) {
            return nativeAddon.startScreenWatcher(callback, options);
        } else {
            console.warn('[ProctorNative] Screen watcher not available, no fallback implemented');
            return false;
        }
    },
    
    stopScreenWatcher: () => {
        if (nativeAddon && nativeAddon.stopScreenWatcher) {
            return nativeAddon.stopScreenWatcher();
        } else {
            return null;
        }
    },
    
    getCurrentScreenStatus: () => {
        if (nativeAddon && nativeAddon.getCurrentScreenStatus) {
            return nativeAddon.getCurrentScreenStatus();
        } else {
            // Return safe defaults
            return {
                mirroring: false,
                splitScreen: false,
                displays: [],
                externalDisplays: [],
                externalKeyboards: [],
                externalDevices: []
            };
        }
    },
    
    // Recording and overlay detection functions (moved to ScreenWatcher)
    detectRecordingAndOverlays: () => {
        if (nativeAddon && nativeAddon.detectRecordingAndOverlays) {
            return nativeAddon.detectRecordingAndOverlays();
        } else {
            console.warn('[ProctorNative] Recording/overlay detection not available');
            return {
                eventType: 'heartbeat',
                isRecording: false,
                recordingSources: [],
                virtualCameras: [],
                overlayWindows: [],
                recordingConfidence: 0.0,
                overlayConfidence: 0.0
            };
        }
    },
    
    // VM detector specific functions
    startVMDetector: (callback, options) => {
        if (nativeAddon && nativeAddon.startVMDetector) {
            return nativeAddon.startVMDetector(callback, options);
        } else {
            console.warn('[ProctorNative] VM detector not available, no fallback implemented');
            return false;
        }
    },
    
    stopVMDetector: () => {
        if (nativeAddon && nativeAddon.stopVMDetector) {
            return nativeAddon.stopVMDetector();
        } else {
            return null;
        }
    },
    
    detectVirtualMachine: () => {
        if (nativeAddon && nativeAddon.detectVirtualMachine) {
            return nativeAddon.detectVirtualMachine();
        } else {
            // Return safe defaults
            return {
                isInsideVM: false,
                detectedVM: "None",
                runningVMProcesses: [],
                vmIndicators: [],
                detectionMethod: "Native addon not available"
            };
        }
    },
    
    // Notification watcher specific functions
    startNotificationWatcher: (callback, options) => {
        if (nativeAddon && nativeAddon.startNotificationWatcher) {
            return nativeAddon.startNotificationWatcher(callback, options);
        } else {
            console.warn('[ProctorNative] Notification watcher not available, no fallback implemented');
            return false;
        }
    },
    
    stopNotificationWatcher: () => {
        if (nativeAddon && nativeAddon.stopNotificationWatcher) {
            return nativeAddon.stopNotificationWatcher();
        } else {
            return null;
        }
    },
    
    getCurrentNotifications: () => {
        if (nativeAddon && nativeAddon.getCurrentNotifications) {
            return nativeAddon.getCurrentNotifications();
        } else {
            return [];
        }
    },
    
    // Focus Idle watcher specific functions
    startFocusIdleWatcher: (callback, options) => {
        if (nativeAddon && nativeAddon.startFocusIdleWatcher) {
            return nativeAddon.startFocusIdleWatcher(callback, options);
        } else {
            console.warn('[ProctorNative] Focus Idle watcher not available, no fallback implemented');
            return false;
        }
    },
    
    stopFocusIdleWatcher: () => {
        if (nativeAddon && nativeAddon.stopFocusIdleWatcher) {
            return nativeAddon.stopFocusIdleWatcher();
        } else {
            return null;
        }
    },
    
    getCurrentFocusIdleStatus: () => {
        if (nativeAddon && nativeAddon.getCurrentFocusIdleStatus) {
            return nativeAddon.getCurrentFocusIdleStatus();
        } else {
            return {
                eventType: "heartbeat",
                timestamp: Date.now(),
                details: {}
            };
        }
    },
    
    // Bluetooth watcher functions (native-based)
    startBluetoothWatcher: (callback, options) => {
        if (nativeAddon && nativeAddon.startBluetoothWatcher) {
            return nativeAddon.startBluetoothWatcher(callback, options);
        } else {
            console.warn('[ProctorNative] Bluetooth watcher not available, no fallback implemented');
            return false;
        }
    },
    
    stopBluetoothWatcher: () => {
        if (nativeAddon && nativeAddon.stopBluetoothWatcher) {
            return nativeAddon.stopBluetoothWatcher();
        } else {
            return null;
        }
    },
    
    getBluetoothStatus: () => {
        if (nativeAddon && nativeAddon.getBluetoothStatus) {
            return nativeAddon.getBluetoothStatus();
        } else {
            return JSON.stringify({
                enabled: false,
                devices: [],
                error: "Native addon not available"
            });
        }
    },
    
    // Clipboard watcher specific functions
    startClipboardWatcher: (callback, options) => {
        if (nativeAddon && nativeAddon.startClipboardWatcher) {
            return nativeAddon.startClipboardWatcher(callback, options);
        } else {
            console.warn('[ProctorNative] Clipboard watcher not available, no fallback implemented');
            return false;
        }
    },
    
    stopClipboardWatcher: () => {
        if (nativeAddon && nativeAddon.stopClipboardWatcher) {
            return nativeAddon.stopClipboardWatcher();
        } else {
            return null;
        }
    },
    
    setClipboardPrivacyMode: (mode) => {
        if (nativeAddon && nativeAddon.setClipboardPrivacyMode) {
            return nativeAddon.setClipboardPrivacyMode(mode);
        } else {
            console.warn('[ProctorNative] Clipboard privacy mode setting not available');
            return false;
        }
    },
    
    getClipboardSnapshot: () => {
        if (nativeAddon && nativeAddon.getClipboardSnapshot) {
            return nativeAddon.getClipboardSnapshot();
        } else {
            return {
                eventType: "snapshot",
                sourceApp: null,
                pid: null,
                clipFormats: [],
                contentPreview: null,
                contentHash: null,
                isSensitive: false,
                timestamp: Date.now()
            };
        }
    },
    
    // Legacy compatibility functions
    start: (callback) => {
        if (nativeAddon) {
            return nativeAddon.start(callback);
        } else {
            // Use process watcher as default
            return fallbackWatcher.start(callback);
        }
    },
    
    stop: () => {
        if (nativeAddon) {
            return nativeAddon.stop();
        } else {
            return fallbackWatcher.stop();
        }
    },
    
    hasNativeAddon: () => !!nativeAddon
};