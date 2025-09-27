const WorkerBase = require('./worker-base');

class ScreenWatchWorker extends WorkerBase {
    constructor() {
        super('screen-watch');
        this.isUsingScreenWatcher = false;
    }
    
    startNativeMode() {
        console.log(`[${this.moduleName}] Using enhanced screen sharing detection mode`);

        this.isUsingScreenWatcher = false;
        this.startEnhancedDetection();
    }

    startEnhancedDetection() {
        const hasEnhanced = this.nativeAddon &&
                           typeof this.nativeAddon.detectScreenSharingSessions === 'function' &&
                           typeof this.nativeAddon.isScreenBeingCaptured === 'function' &&
                           typeof this.nativeAddon.calculateScreenSharingThreatLevel === 'function';

        if (!hasEnhanced) {
            console.error(`[${this.moduleName}] Enhanced screen detection methods not available, falling back`);
            this.startFallbackMode();
            return;
        }

        console.log(`[${this.moduleName}] Starting enhanced screen detection with 2s interval`);

        this.enhancedDetectionInterval = setInterval(() => {
            if (!this.isRunning) return;

            try {
                const screenSessions = this.nativeAddon.detectScreenSharingSessions();
                const isScreenCaptured = this.nativeAddon.isScreenBeingCaptured();
                const threatLevel = this.nativeAddon.calculateScreenSharingThreatLevel();

                const processedData = this.processEnhancedScreenData(screenSessions, isScreenCaptured, threatLevel);

                if (processedData.violations.length > 0 || processedData.isScreenCaptured) {
                    console.log(`[${this.moduleName}] Screen sharing detected: ${processedData.violations.length} violations, capture: ${processedData.isScreenCaptured}`);

                    this.sendToParent({
                        type: 'proctor-event',
                        module: this.moduleName,
                        payload: processedData
                    });
                }

            } catch (err) {
                console.error(`[${this.moduleName}] Error in enhanced screen detection:`, err);
                this.startFallbackMode();
            }
        }, 2000);

        this.startRecordingDetection();
    }

    processEnhancedScreenData(screenSessions, isScreenCaptured, threatLevel) {
        const methods = {
            0: 'NONE',
            1: 'BROWSER_WEBRTC',
            2: 'DESKTOP_DUPLICATION',
            3: 'SCREENCAPTUREKIT',
            4: 'APPLICATION_SHARING',
            5: 'VIRTUAL_CAMERA',
            6: 'DISPLAY_MIRRORING',
            7: 'REMOTE_DESKTOP'
        };

        const threatLevels = {
            0: 'NONE',
            1: 'LOW',
            2: 'MEDIUM',
            3: 'HIGH',
            4: 'CRITICAL'
        };

        const violations = [];
        let maxThreatLevel = 0;

        if (screenSessions && Array.isArray(screenSessions)) {
            for (const session of screenSessions) {
                violations.push({
                    sessionId: session.sessionId,
                    method: methods[session.method] || 'UNKNOWN',
                    appName: session.appName,
                    pid: session.pid,
                    threatLevel: threatLevels[session.threatLevel] || 'UNKNOWN',
                    confidence: session.confidence,
                    details: session.details,
                    violation_type: 'SCREEN_SHARING_SESSION'
                });
                maxThreatLevel = Math.max(maxThreatLevel, session.threatLevel);
            }
        }

        return {
            isScreenCaptured: isScreenCaptured || false,
            violations: violations,
            sessions: violations,
            total_sessions: screenSessions ? screenSessions.length : 0,
            max_threat_level: threatLevels[Math.max(maxThreatLevel, threatLevel || 0)],
            overall_threat_level: threatLevel || 0,
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
        if (this.enhancedDetectionInterval) {
            clearInterval(this.enhancedDetectionInterval);
            this.enhancedDetectionInterval = null;
        }

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
            isScreenCaptured: false,
            violations: [],
            sessions: [],
            total_sessions: 0,
            max_threat_level: 'NONE',
            overall_threat_level: 0,
            threat_count: {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0
            },
            timestamp: Date.now(),
            source: 'unavailable',
            status: 'error'
        };
    }
}

const worker = new ScreenWatchWorker();
worker.start();