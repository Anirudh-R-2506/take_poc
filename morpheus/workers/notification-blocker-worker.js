const WorkerBase = require('./worker-base');

class NotificationBlockerWorker extends WorkerBase {
    constructor() {
        super('notification-blocker');
        this.isExamActive = false;
        this.originalDNDState = null;
        this.doNotDisturb = null;
        this.lastViolationCheck = 0;
        this.violationCheckInterval = 2000; // Check for violations every 2 seconds

        // Initialize macOS do-not-disturb module if on macOS
        if (process.platform === 'darwin') {
            try {
                const dndModule = require('@sindresorhus/do-not-disturb');
                this.doNotDisturb = dndModule.default || dndModule;
                console.log(`[${this.moduleName}] macOS do-not-disturb module loaded`);
            } catch (error) {
                console.error(`[${this.moduleName}] Failed to load do-not-disturb module:`, error.message);
            }
        }
    }

    startNativeMode() {
        console.log(`[${this.moduleName}] Starting notification blocker in polling mode`);
        this.startPollingMode();
    }

    startPollingMode() {
        console.log(`[${this.moduleName}] Using notification blocker polling mode`);

        // Start exam mode - enable notification blocking
        this.startExamMode();

        // Poll notification status every 2 seconds
        this.notificationPollingInterval = setInterval(() => {
            if (!this.isRunning) return;

            try {
                this.checkNotificationStatus();
            } catch (err) {
                console.error(`[${this.moduleName}] Error checking notification status:`, err);
                this.sendToParent({
                    type: 'proctor-event',
                    module: this.moduleName,
                    payload: {
                        eventType: 'error',
                        reason: 'polling-error',
                        message: err.message,
                        timestamp: Date.now(),
                        count: this.counter++,
                        source: 'native'
                    }
                });
            }
        }, this.violationCheckInterval);
    }

    async startExamMode() {
        console.log(`[${this.moduleName}] Starting exam mode - enabling notification blocking`);
        this.isExamActive = true;

        try {
            if (process.platform === 'darwin') {
                // macOS: Use do-not-disturb module
                await this.enableMacOSNotificationBlocking();
            } else if (process.platform === 'win32') {
                // Windows: Use native addon
                await this.enableWindowsNotificationBlocking();
            }

            this.sendToParent({
                type: 'proctor-event',
                module: this.moduleName,
                payload: {
                    eventType: 'notification-blocking-enabled',
                    reason: 'exam-started',
                    isBlocked: true,
                    examActive: true,
                    timestamp: Date.now(),
                    count: this.counter++,
                    source: process.platform === 'darwin' ? 'dnd-module' : 'native'
                }
            });

        } catch (error) {
            console.error(`[${this.moduleName}] Failed to enable notification blocking:`, error.message);
            this.sendToParent({
                type: 'proctor-event',
                module: this.moduleName,
                payload: {
                    eventType: 'error',
                    reason: 'blocking-enable-failed',
                    message: error.message,
                    timestamp: Date.now(),
                    count: this.counter++,
                    source: 'worker'
                }
            });
        }
    }

    async stopExamMode() {
        console.log(`[${this.moduleName}] Stopping exam mode - disabling notification blocking`);
        this.isExamActive = false;

        try {
            if (process.platform === 'darwin') {
                // macOS: Restore original do-not-disturb state
                await this.disableMacOSNotificationBlocking();
            } else if (process.platform === 'win32') {
                // Windows: Use native addon to restore
                await this.disableWindowsNotificationBlocking();
            }

            this.sendToParent({
                type: 'proctor-event',
                module: this.moduleName,
                payload: {
                    eventType: 'notification-blocking-disabled',
                    reason: 'exam-ended',
                    isBlocked: false,
                    examActive: false,
                    timestamp: Date.now(),
                    count: this.counter++,
                    source: process.platform === 'darwin' ? 'dnd-module' : 'native'
                }
            });

        } catch (error) {
            console.error(`[${this.moduleName}] Failed to disable notification blocking:`, error.message);
        }
    }

    async enableMacOSNotificationBlocking() {
        if (!this.doNotDisturb) {
            throw new Error('do-not-disturb module not available');
        }

        try {
            // Backup current state
            this.originalDNDState = await this.doNotDisturb.isEnabled();
            console.log(`[${this.moduleName}] Backed up original DND state: ${this.originalDNDState}`);

            // Enable do-not-disturb if not already enabled
            if (!this.originalDNDState) {
                await this.doNotDisturb.enable();
                console.log(`[${this.moduleName}] macOS Do Not Disturb enabled`);
            } else {
                console.log(`[${this.moduleName}] macOS Do Not Disturb already enabled`);
            }

        } catch (error) {
            console.error(`[${this.moduleName}] Error enabling macOS DND:`, error.message);
            throw error;
        }
    }

    async disableMacOSNotificationBlocking() {
        if (!this.doNotDisturb) {
            console.warn(`[${this.moduleName}] do-not-disturb module not available for restore`);
            return;
        }

        try {
            // Only disable if we originally enabled it
            if (this.originalDNDState === false) {
                await this.doNotDisturb.disable();
                console.log(`[${this.moduleName}] macOS Do Not Disturb restored to original state (disabled)`);
            } else {
                console.log(`[${this.moduleName}] macOS Do Not Disturb left enabled (was originally enabled)`);
            }

        } catch (error) {
            console.error(`[${this.moduleName}] Error restoring macOS DND:`, error.message);
        }
    }

    async enableWindowsNotificationBlocking() {
        if (!this.nativeAddon || typeof this.nativeAddon.enableNotificationBlocking !== 'function') {
            throw new Error('Windows notification blocking not available in native addon');
        }

        const success = this.nativeAddon.enableNotificationBlocking();
        if (!success) {
            throw new Error('Failed to enable Windows Focus Assist');
        }

        console.log(`[${this.moduleName}] Windows Focus Assist enabled successfully`);
    }

    async disableWindowsNotificationBlocking() {
        if (!this.nativeAddon || typeof this.nativeAddon.disableNotificationBlocking !== 'function') {
            console.warn(`[${this.moduleName}] Windows notification blocking not available for restore`);
            return;
        }

        const success = this.nativeAddon.disableNotificationBlocking();
        if (!success) {
            console.error(`[${this.moduleName}] Failed to restore Windows Focus Assist`);
        } else {
            console.log(`[${this.moduleName}] Windows Focus Assist restored successfully`);
        }
    }

    checkNotificationStatus() {
        if (!this.isExamActive) return;

        if (process.platform === 'win32') {
            this.checkWindowsNotificationStatus();
        } else if (process.platform === 'darwin') {
            this.checkMacOSNotificationStatus();
        }
    }

    checkWindowsNotificationStatus() {
        if (!this.nativeAddon || typeof this.nativeAddon.getNotificationBlockerStatus !== 'function') {
            return;
        }

        try {
            const status = this.nativeAddon.getNotificationBlockerStatus();

            // Check for violations (user manually changed Focus Assist)
            if (status.userModified) {
                console.warn(`[${this.moduleName}] Violation detected: User modified Focus Assist during exam`);
                this.sendToParent({
                    type: 'proctor-event',
                    module: this.moduleName,
                    payload: {
                        ...status,
                        eventType: 'violation',
                        reason: 'user-modified-focus-assist',
                        violationType: 'notification-settings-changed',
                        severity: 'high',
                        count: this.counter++
                    }
                });
            } else {
                // Send regular status update
                this.sendToParent({
                    type: 'proctor-event',
                    module: this.moduleName,
                    payload: {
                        ...status,
                        count: this.counter++
                    }
                });
            }

        } catch (error) {
            console.error(`[${this.moduleName}] Error checking Windows notification status:`, error.message);
        }
    }

    async checkMacOSNotificationStatus() {
        if (!this.doNotDisturb) return;

        try {
            const currentState = await this.doNotDisturb.isEnabled();

            // Check if user manually disabled DND during exam
            if (!currentState && this.isExamActive) {
                console.warn(`[${this.moduleName}] Violation detected: User disabled Do Not Disturb during exam`);
                this.sendToParent({
                    type: 'proctor-event',
                    module: this.moduleName,
                    payload: {
                        eventType: 'violation',
                        reason: 'user-disabled-dnd',
                        violationType: 'notification-settings-changed',
                        severity: 'high',
                        isBlocked: false,
                        userModified: true,
                        timestamp: Date.now(),
                        count: this.counter++,
                        source: 'dnd-module'
                    }
                });

                // Try to re-enable DND
                try {
                    await this.doNotDisturb.enable();
                    console.log(`[${this.moduleName}] Re-enabled Do Not Disturb after violation`);
                } catch (reEnableError) {
                    console.error(`[${this.moduleName}] Failed to re-enable DND:`, reEnableError.message);
                }
            } else {
                // Send regular status update
                this.sendToParent({
                    type: 'proctor-event',
                    module: this.moduleName,
                    payload: {
                        eventType: currentState ? 'notification-blocked' : 'notification-enabled',
                        reason: currentState ? 'dnd-active' : 'dnd-inactive',
                        isBlocked: currentState,
                        userModified: false,
                        examActive: this.isExamActive,
                        timestamp: Date.now(),
                        count: this.counter++,
                        source: 'dnd-module'
                    }
                });
            }

        } catch (error) {
            console.error(`[${this.moduleName}] Error checking macOS notification status:`, error.message);
        }
    }

    stop() {
        console.log(`[${this.moduleName}] Stopping notification blocker...`);

        // Clear polling interval
        if (this.notificationPollingInterval) {
            clearInterval(this.notificationPollingInterval);
            this.notificationPollingInterval = null;
        }

        // Stop exam mode and restore notifications
        if (this.isExamActive) {
            this.stopExamMode();
        }

        super.stop();
    }

    // Handle control messages from supervisor
    handleControlMessage(message) {
        super.handleControlMessage(message);

        switch (message.cmd) {
            case 'startExam':
                this.startExamMode();
                break;
            case 'stopExam':
                this.stopExamMode();
                break;
            case 'checkViolations':
                this.checkNotificationStatus();
                break;
            default:
                console.warn(`[${this.moduleName}] Unknown control message: ${message.cmd}`);
        }
    }

    startFallbackMode() {
        console.log(`[${this.moduleName}] Using fallback mode - limited notification blocking`);

        // Minimal fallback - just report that blocking is not available
        this.sendToParent({
            type: 'proctor-event',
            module: this.moduleName,
            payload: {
                eventType: 'error',
                reason: 'notification-blocking-unavailable',
                message: 'Platform does not support notification blocking',
                timestamp: Date.now(),
                count: this.counter++,
                source: 'fallback'
            }
        });

        super.startFallbackMode();
    }

    getModuleSpecificData() {
        return {
            eventType: 'heartbeat',
            reason: 'notification-blocker-active',
            isBlocked: this.isExamActive,
            examActive: this.isExamActive,
            platform: process.platform,
            source: 'worker',
            status: 'running'
        };
    }
}

const worker = new NotificationBlockerWorker();
worker.start();