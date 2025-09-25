const EventEmitter = require('events');
const PermissionManager = require('../permissions/PermissionManager');

class PermissionService extends EventEmitter {
    constructor() {
        super();
        this.permissionManager = new PermissionManager();
        this.isInitialized = false;
        this.isInitializing = false;
        this.initPromise = null;
        this.permissionStatus = null;
        this.permissionCheckInProgress = false;
    }

    /**
     * Initialize permissions once and cache the result
     */
    async initialize() {
        if (this.isInitialized) {
            return this.permissionStatus;
        }

        if (this.isInitializing && this.initPromise) {
            return this.initPromise;
        }

        this.isInitializing = true;
        this.initPromise = this._performInitialization();
        return this.initPromise;
    }

    async _performInitialization() {
        try {
            console.log('[PermissionService] Starting centralized permission initialization...');
            
            // Initialize PermissionManager 
            await this.permissionManager.initialize();
            
            // Check all permissions sequentially
            this.permissionStatus = await this.permissionManager.checkAllPermissions();
            
            this.isInitialized = true;
            this.isInitializing = false;
            
            console.log('[PermissionService] Permission initialization completed:', this.permissionStatus);
            
            // Emit permission ready event
            this.emit('permissions-ready', this.permissionStatus);
            
            return this.permissionStatus;
        } catch (error) {
            this.isInitializing = false;
            this.initPromise = null;
            console.error('[PermissionService] Failed to initialize permissions:', error);
            throw error;
        }
    }

    /**
     * Get current permission status without triggering new checks
     */
    getPermissionStatus() {
        if (!this.isInitialized) {
            return {
                allGranted: false,
                error: 'Permissions not initialized'
            };
        }
        return this.permissionStatus;
    }

    /**
     * Check if all required permissions are granted
     */
    hasAllRequiredPermissions() {
        return this.isInitialized && this.permissionStatus && this.permissionStatus.allGranted;
    }

    /**
     * Wait for permissions to be ready
     */
    async waitForPermissions(timeoutMs = 30000) {
        if (this.isInitialized) {
            return this.permissionStatus;
        }

        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                reject(new Error('Permission initialization timeout'));
            }, timeoutMs);

            this.once('permissions-ready', (status) => {
                clearTimeout(timeout);
                resolve(status);
            });

            // Start initialization if not already started
            if (!this.isInitializing) {
                this.initialize().catch(reject);
            }
        });
    }

    /**
     * Request specific permission (delegate to PermissionManager)
     */
    async requestPermission(permissionType) {
        if (!this.isInitialized) {
            await this.initialize();
        }

        let granted = false;

        try {
            switch (permissionType) {
                case 'accessibility':
                    granted = await this.permissionManager.requestAccessibilityPermission();
                    break;
                case 'screenRecording':
                    granted = await this.permissionManager.requestScreenRecordingPermission();
                    break;
                case 'inputMonitoring':
                    granted = await this.permissionManager.requestInputMonitoringPermission();
                    break;
                case 'registryAccess':
                    granted = await this.permissionManager.requestRegistryPermission();
                    break;
                case 'deviceEnumeration':
                    granted = await this.permissionManager.requestDeviceEnumerationPermission();
                    break;
                case 'processAccess':
                    granted = await this.permissionManager.requestProcessAccessPermission();
                    break;
                case 'clipboardAccess':
                    granted = await this.permissionManager.requestClipboardPermission();
                    break;
                default:
                    throw new Error(`Unknown permission type: ${permissionType}`);
            }

            // Refresh permission status after request
            console.log(`[PermissionService] Permission ${permissionType} request result: ${granted}, refreshing status...`);
            await this.refreshPermissions();

            return granted;
        } catch (error) {
            console.error(`[PermissionService] Error requesting permission ${permissionType}:`, error);
            return false;
        }
    }

    /**
     * Refresh permissions (for UI refresh scenarios)
     */
    async refreshPermissions() {
        if (this.permissionCheckInProgress) {
            console.log('[PermissionService] Permission check already in progress, skipping...');
            return this.permissionStatus;
        }

        console.log('[PermissionService] Refreshing permissions...');
        this.permissionCheckInProgress = true;

        try {
            this.permissionStatus = await this.permissionManager.checkAllPermissions();
            this.emit('permissions-updated', this.permissionStatus);
            return this.permissionStatus;
        } finally {
            this.permissionCheckInProgress = false;
        }
    }

    /**
     * Reset the service (for testing or reinitialization)
     */
    reset() {
        this.isInitialized = false;
        this.isInitializing = false;
        this.initPromise = null;
        this.permissionStatus = null;
        this.permissionCheckInProgress = false;
        this.removeAllListeners();
        console.log('[PermissionService] Service reset');
    }
}

// Export singleton instance
const permissionService = new PermissionService();
module.exports = permissionService;