const WorkerBase = require('./worker-base');

class NotificationWatchWorker extends WorkerBase {
    constructor() {
        super('notification-watch');
        this.isUsingNotificationWatcher = false;
    }
    
    startNativeMode() {
        console.log(`[${this.moduleName}] Native callback-based notification watcher disabled due to threading issues - using polling mode`);
        
        // Skip native callback-based startNotificationWatcher to avoid segfaults
        this.isUsingNotificationWatcher = false;
        this.startPollingMode();
    }
    
    startPollingMode() {
        console.log(`[${this.moduleName}] Using native API polling mode`);
        
        // Check if the native method exists
        if (!this.nativeAddon || typeof this.nativeAddon.getCurrentNotifications !== 'function') {
            console.error(`[${this.moduleName}] getCurrentNotifications method not available, falling back`);
            this.startFallbackMode();
            return;
        }
        
        console.log(`[${this.moduleName}] Starting notification polling with 1s interval`);
        
        // Poll current notifications every 1 second using direct API calls
        this.notificationPollingInterval = setInterval(() => {
            if (!this.isRunning) return;
            
            try {
                console.log(`[${this.moduleName}] Attempting to get current notifications...`);
                const notifications = this.nativeAddon.getCurrentNotifications();
                console.log(`[${this.moduleName}] Notification result:`, notifications ? `${notifications.length} notifications` : 'no data');
                
                // Always send data to keep UI updated, even if no notifications
                const payload = {
                    eventType: (notifications && notifications.length > 0) ? 'notifications-found' : 'heartbeat',
                    notifications: notifications || [],
                    count: notifications ? notifications.length : 0,
                    timestamp: Date.now(),
                    source: 'native'
                };
                
                this.sendToParent({
                    type: 'proctor-event',
                    module: this.moduleName,
                    payload: payload
                });
                
                if (notifications && notifications.length > 0) {
                    console.log(`[${this.moduleName}] Sent ${notifications.length} notifications to parent`);
                } else {
                    console.log(`[${this.moduleName}] Sent heartbeat (no notifications)`);
                }
            } catch (err) {
                console.error(`[${this.moduleName}] Error getting current notifications:`, err);
                // Fall back to JavaScript implementation
                this.startFallbackMode();
            }
        }, 1000); // 1 second interval
    }
    
    startFallbackMode() {
        console.log(`[${this.moduleName}] Using JavaScript notification watcher fallback`);
        
        // Use the existing fallback from worker-base with module-specific data
        super.startFallbackMode();
    }
    
    stop() {
        if (this.notificationPollingInterval) {
            clearInterval(this.notificationPollingInterval);
            this.notificationPollingInterval = null;
        }
        
        if (this.isUsingNotificationWatcher && this.nativeAddon) {
            try {
                this.nativeAddon.stopNotificationWatcher();
                this.isUsingNotificationWatcher = false;
            } catch (err) {
                console.error(`[${this.moduleName}] Error stopping notification watcher:`, err);
            }
        }
        
        super.stop();
    }
    
    // Minimal fallback data if notification watcher fails completely
    getModuleSpecificData() {
        console.error(`[${this.moduleName}] Notification watcher completely failed - no native support available`);
        
        return {
            eventType: 'heartbeat',
            sourceApp: null,
            pid: 0,
            title: null,
            body: null,
            notificationId: null,
            timestamp: Date.now(),
            confidence: 0,
            source: 'unavailable',
            status: 'error'
        };
    }
}

const worker = new NotificationWatchWorker();
worker.start();